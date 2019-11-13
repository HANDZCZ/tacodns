extern crate byteorder;

use std::io::{self, Cursor, Read, Seek, Write};
use std::io::SeekFrom::Start;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub mod record_type {
	pub const A: u16 = 1;
	pub const NS: u16 = 2;
	pub const CNAME: u16 = 5;
	pub const SOA: u16 = 6;
	pub const MX: u16 = 15;
	pub const TXT: u16 = 16;
	pub const AAAA: u16 = 28;
	pub const SRV: u16 = 33;
}

#[derive(Debug, Default)]
pub struct Header {
	// https://tools.ietf.org/html/rfc1035#page-26
	pub id: u16,
	pub qr: bool,
	// 4 bits
	pub opcode: u8,
	pub aa: bool,
	pub tc: bool,
	pub rd: bool,
	pub ra: bool,
	// 3 bits
	pub z: u8,
	// 4 bits
	pub rcode: u8,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Question {
	pub qname: Vec<String>,
	pub qtype: u16,
	pub qclass: u16,
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct Resource {
	pub rname: Vec<String>,
	pub rtype: u16,
	pub rclass: u16,
	pub ttl: u32,
	pub rdata: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct EdnsOption {
	code: u16,
	data: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Edns {
	udp_payload_size: u16,
	extended_rcode_and_flags: u32,
	options: Vec<EdnsOption>,
}

#[derive(Debug, Default)]
pub struct Message {
	pub header: Header,
	pub question: Vec<Question>,
	pub answer: Vec<Resource>,
	pub authority: Vec<Resource>,
	pub additional: Vec<Resource>,
	pub edns: Option<Edns>,
}

pub fn parse(buf: &[u8]) -> Message {
	let mut message: Message = Default::default();
	let mut cursor = Cursor::new(buf.to_vec());
	
	let mut header = &mut message.header;
	header.id = cursor.read_u16::<BigEndian>().unwrap();
	let flags = cursor.read_u16::<BigEndian>().unwrap();
	header.qr = flags >> 15 == 1;
	header.opcode = (flags >> 11 & 0b1111) as u8;
	header.aa = (flags >> 10 & 1) == 1;
	header.tc = (flags >> 9 & 1) == 1;
	header.rd = (flags >> 8 & 1) == 1;
	header.ra = (flags >> 7 & 1) == 1;
	header.z = (flags >> 4 & 0b111) as u8;
	header.rcode = (flags & 0b1111) as u8;
	
	let question_count = cursor.read_u16::<BigEndian>().unwrap();
	//println!("question_count: {:.unwrap()}", question_count);
	let answer_count = cursor.read_u16::<BigEndian>().unwrap();
	//println!("answer_count: {:.unwrap()}", answer_count);
	let authority_count = cursor.read_u16::<BigEndian>().unwrap();
	//println!("authority_count: {:.unwrap()}", authority_count);
	let additional_count = cursor.read_u16::<BigEndian>().unwrap();
	//println!("additional_count: {:.unwrap()}", additional_count);
	
	fn parse_name(cursor: &mut Cursor<Vec<u8>>) -> Vec<String> {
		let mut result = vec![];
		
		let mut label_cursor: &mut Cursor<Vec<u8>> = cursor;
		let mut _label_cursor = Cursor::new(vec![]);
		loop {
			let label_size = label_cursor.read_u8().unwrap();
			if label_size == 0 { break; }
			
			if label_size >> 6 == 3 {
				// message compression: https://tools.ietf.org/html/rfc1035#section-4.1.4
				let second_octet = label_cursor.read_u8().unwrap();
				let offset = ((label_size as u16 & 0b00111111) << 8) | second_octet as u16;
				_label_cursor = cursor.clone();
				label_cursor = &mut _label_cursor;
				label_cursor.seek(Start(offset as u64)).unwrap();
				continue;
			}
			
			let mut label_buf = vec![0u8; label_size as usize];
			label_cursor.read_exact(label_buf.as_mut()).unwrap();
			let label = String::from_utf8(label_buf)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)).unwrap();
			result.push(label);
		}
		
		return result;
	}
	
	// question
	message.question = Vec::with_capacity(question_count as usize);
	for _ in 0..question_count {
		let mut question: Question = Default::default();
		
		question.qname = parse_name(&mut cursor);
		question.qtype = cursor.read_u16::<BigEndian>().unwrap();
		question.qclass = cursor.read_u16::<BigEndian>().unwrap();
		
		message.question.push(question);
	}
	
	// answer, authority, additional
	fn read_resources(cursor: &mut Cursor<Vec<u8>>, count: u16) -> io::Result<Vec<Resource>> {
		let mut resources = Vec::with_capacity(count as usize);
		for _ in 0..count {
			let mut resource: Resource = Default::default();
			
			resource.rname = parse_name(cursor);
			resource.rtype = cursor.read_u16::<BigEndian>().unwrap();
			resource.rclass = cursor.read_u16::<BigEndian>().unwrap();
			resource.ttl = cursor.read_u32::<BigEndian>().unwrap();
			
			let rdata_len = cursor.read_u16::<BigEndian>().unwrap();
			let rdata_buf = match resource.rtype {
				record_type::CNAME | record_type::NS => {
					serialize_name(parse_name(cursor).iter().map(|label| label.as_str()))
				}
				record_type::MX => {
					let mut rdata_buf = vec![];
					rdata_buf.push(cursor.read_u8().unwrap());
					rdata_buf.push(cursor.read_u8().unwrap());
					rdata_buf.append(&mut serialize_name(parse_name(cursor).iter().map(|label| label.as_str())));
					rdata_buf
				}
				_ => {
					let mut rdata_buf = vec![0; rdata_len as usize];
					cursor.read_exact(rdata_buf.as_mut()).unwrap();
					rdata_buf
				}
			};
			resource.rdata = rdata_buf;
			
			resources.push(resource);
		}
		return Ok(resources);
	}
	message.answer = read_resources(&mut cursor, answer_count).unwrap();
	message.authority = read_resources(&mut cursor, authority_count).unwrap();
	message.additional = read_resources(&mut cursor, additional_count).unwrap().into_iter().filter(|x| if x.rtype == 41 {
		let mut options = vec![];
		let len = x.rdata.len() as u64;
		let mut cursor = Cursor::new(x.rdata.clone());
		
		while cursor.position() < len {
			let code = cursor.read_u16::<BigEndian>().unwrap();
			let length = cursor.read_u16::<BigEndian>().unwrap();
			let mut data = vec![0; length as usize];
			cursor.read_exact(&mut data).unwrap();
			options.push(EdnsOption {
				code,
				data,
			});
		}
		
		message.edns = Some(Edns {
			udp_payload_size: x.rclass,
			extended_rcode_and_flags: x.ttl,
			options,
		});
		return false;
	} else {
		return true;
	}).collect();
	
	return message;
}

/// Takes a list of labels (e.g. `["google", "com"]`) and converts it into a binary format useful for rdata
pub fn serialize_name<'a, I: IntoIterator<Item=&'a str>>(name: I) -> Vec<u8> {
	let mut bytes = vec![];
	for label in name {
		bytes.push(label.len() as u8);
		bytes.append(&mut label.as_bytes().to_vec());
	}
	bytes.push(0);
	return bytes;
}

pub fn serialize(message: &Message, tcp: bool) -> Vec<u8> {
	fn name_len(name: &Vec<String>) -> usize {
		return name.iter().map(|name| 1 + name.len()).sum::<usize>() + 1;
	}
	fn compute_truncation<'a>(available_size: usize, question: &'a [Question], answer: &'a [Resource], authority: &'a [Resource], additional: &'a [Resource]) ->
	(usize, bool, &'a [Question], &'a [Resource], &'a [Resource], &'a [Resource]) {
		let mut size = 12;
		
		for (index, q) in question.iter().enumerate() {
			let increase = name_len(&q.qname) + 4;
			if size + increase > available_size {
				return (size, true, &question[0..index], &answer[0..0], &authority[0..0], &additional[0..0]);
			}
			size += increase;
		}
		
		for (index, a) in answer.iter().enumerate() {
			let increase = name_len(&a.rname) + 10 + a.rdata.len();
			if size + increase > available_size {
				return (size, true, question, &answer[0..index], &authority[0..0], &additional[0..0]);
			}
			size += increase;
		}
		
		for (index, a) in authority.iter().enumerate() {
			let increase = name_len(&a.rname) + 10 + a.rdata.len();
			if size + increase > available_size {
				return (size, true, question, answer, &authority[0..index], &additional[0..0]);
			}
			size += increase;
		}
		
		for (index, a) in additional.iter().enumerate() {
			let increase = name_len(&a.rname) + 10 + a.rdata.len();
			if size + increase > available_size {
				return (size, true, question, answer, authority, &additional[0..index]);
			}
			size += increase;
		}
		
		return (size, false, question, answer, authority, additional);
	}
	let available_size: u16 = if tcp { u16::max_value() } else { message.edns.as_ref().map(|edns| edns.udp_payload_size).unwrap_or(512) };
	let mut additional;
	let (buff_len, truncated, question, answer, authority, additional) =
		compute_truncation(available_size as usize, &message.question, &message.answer, &message.authority, if message.edns.is_none() { &message.additional } else {
			additional = Vec::with_capacity(message.additional.len() + 1);
			additional.extend_from_slice(&message.additional);
			additional.push(Resource {
				rname: vec![],
				rtype: 41,
				rclass: u16::max_value(),
				ttl: 0,
				rdata: vec![]
			});
			&additional
		});
	assert!(buff_len <= u16::max_value() as usize);
	let mut cursor = Cursor::new(Vec::with_capacity(buff_len));
	
	let header = &message.header;
	cursor.write_u16::<BigEndian>(header.id).unwrap();
	let mut flags = 0u16;
	flags |= header.rcode as u16;
	flags |= (header.z << 4) as u16;
	flags |= if header.ra { 1 } else { 0 } << 7;
	flags |= if header.rd { 1 } else { 0 } << 8;
	flags |= if truncated { 1 } else { 0 } << 9;
	flags |= if header.aa { 1 } else { 0 } << 10;
	flags |= (header.opcode as u16) << 11;
	flags |= if header.qr { 1 } else { 0 } << 15;
	cursor.write_u16::<BigEndian>(flags).unwrap();
	
	cursor.write_u16::<BigEndian>(question.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(answer.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(authority.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(additional.len() as u16).unwrap();
	
	for question in question {
		cursor.write_all(serialize_name(question.qname.iter().map(|label| label.as_str())).as_slice()).unwrap();
		cursor.write_u16::<BigEndian>(question.qtype).unwrap();
		cursor.write_u16::<BigEndian>(question.qclass).unwrap();
	}
	
	fn write_resources(cursor: &mut Cursor<Vec<u8>>, resources: &[Resource]) {
		for resource in resources {
			cursor.write_all(serialize_name(resource.rname.iter().map(|label| label.as_str())).as_slice()).unwrap();
			cursor.write_u16::<BigEndian>(resource.rtype).unwrap();
			cursor.write_u16::<BigEndian>(resource.rclass).unwrap();
			cursor.write_u32::<BigEndian>(resource.ttl).unwrap();
			cursor.write_u16::<BigEndian>(resource.rdata.len() as u16).unwrap();
			cursor.write_all(resource.rdata.as_ref()).unwrap();
		}
	}
	write_resources(&mut cursor, answer);
	write_resources(&mut cursor, authority);
	write_resources(&mut cursor, additional);
	
	let buffer = cursor.into_inner();
	assert_eq!(buffer.len(), buff_len);
	return buffer;
}

pub fn make_message_from_question(question: Vec<Question>) -> Message {
	let mut message = Message::default();
	message.header.rd = true;
	message.question = question;
	return message;
}
