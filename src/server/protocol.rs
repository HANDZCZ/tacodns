extern crate byteorder;

use std::io::{self, Cursor, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

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

#[derive(Debug, Default)]
pub struct Question {
	pub qname: Vec<String>,
	pub qtype: u16,
	pub qclass: u16,
}

#[derive(Debug, Default, PartialEq)]
pub struct Resource {
	pub rname: Vec<String>,
	pub rtype: u16,
	pub rclass: u16,
	pub ttl: u32,
	pub rdata: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Message {
	pub header: Header,
	pub question: Vec<Question>,
	pub answer: Vec<Resource>,
	pub authority: Vec<Resource>,
	pub additional: Vec<Resource>,
}

pub fn parse(buf: &[u8]) -> io::Result<Message> {
	let mut message: Message = Default::default();
	let mut cursor = Cursor::new(buf.to_vec());
	
	let mut header = &mut message.header;
	header.id = cursor.read_u16::<BigEndian>()?;
	let flags = cursor.read_u16::<BigEndian>()?;
	header.qr = flags >> 15 == 1;
	header.opcode = (flags >> 11 & 0b1111) as u8;
	header.aa = (flags >> 10 & 1) == 1;
	header.tc = (flags >> 9 & 1) == 1;
	header.rd = (flags >> 8 & 1) == 1;
	header.ra = (flags >> 7 & 1) == 1;
	header.z = (flags >> 4 & 0b111) as u8;
	header.rcode = (flags & 0b1111) as u8;
	
	let question_count = cursor.read_u16::<BigEndian>()?;
	//println!("question_count: {:?}", question_count);
	let answer_count = cursor.read_u16::<BigEndian>()?;
	//println!("answer_count: {:?}", answer_count);
	let authority_count = cursor.read_u16::<BigEndian>()?;
	//println!("authority_count: {:?}", authority_count);
	let additional_count = cursor.read_u16::<BigEndian>()?;
	//println!("additional_count: {:?}", additional_count);
	
	// question
	message.question = Vec::with_capacity(question_count as usize);
	for _ in 0..question_count {
		let mut question: Question = Default::default();
		
		loop {
			let label_size = cursor.read_u8()?;
			if label_size == 0 { break; }
			
			let mut label_buf = vec![0u8; label_size as usize];
			cursor.read_exact(label_buf.as_mut())?;
			let label = String::from_utf8(label_buf)
				.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
			question.qname.push(label);
		}
		question.qtype = cursor.read_u16::<BigEndian>()?;
		question.qclass = cursor.read_u16::<BigEndian>()?;
		
		message.question.push(question);
	}
	
	// answer, authority, additional
	fn read_resources(cursor: &mut Cursor<Vec<u8>>, count: u16) -> io::Result<Vec<Resource>> {
		let mut resources = Vec::with_capacity(count as usize);
		for _ in 0..count {
			let mut resource: Resource = Default::default();
			
			loop {
				let label_size = cursor.read_u8()?;
				if label_size == 0 { break; }
				
				let mut label_buf = vec![0u8; label_size as usize];
				cursor.read_exact(label_buf.as_mut())?;
				let label = String::from_utf8(label_buf)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
				resource.rname.push(label);
			}
			
			resource.rtype = cursor.read_u16::<BigEndian>()?;
			resource.rclass = cursor.read_u16::<BigEndian>()?;
			resource.ttl = cursor.read_u32::<BigEndian>()?;
			
			let rdata_len = cursor.read_u16::<BigEndian>()?;
			let mut rdata_buf = vec![0; rdata_len as usize];
			cursor.read_exact(rdata_buf.as_mut())?;
			resource.rdata = rdata_buf;
			
			resources.push(resource);
		}
		return Ok(resources);
	}
	message.answer = read_resources(&mut cursor, answer_count)?;
	message.authority = read_resources(&mut cursor, authority_count)?;
	message.additional = read_resources(&mut cursor, additional_count)?;
	
	return Ok(message);
}

pub fn serialize(message: &Message) -> Vec<u8> {
	let mut cursor = Cursor::new(Vec::new());
	
	let header = &message.header;
	cursor.write_u16::<BigEndian>(header.id).unwrap();
	let mut flags = 0u16;
	flags |= header.rcode as u16;
	flags |= (header.z << 4) as u16;
	flags |= if header.ra { 1 } else { 0 } << 7;
	flags |= if header.rd { 1 } else { 0 } << 8;
	flags |= if header.tc { 1 } else { 0 } << 9;
	flags |= if header.aa { 1 } else { 0 } << 10;
	flags |= (header.opcode as u16) << 11;
	flags |= if header.qr { 1 } else { 0 } << 15;
	cursor.write_u16::<BigEndian>(flags).unwrap();
	
	cursor.write_u16::<BigEndian>(message.question.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(message.answer.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(message.authority.len() as u16).unwrap();
	cursor.write_u16::<BigEndian>(message.additional.len() as u16).unwrap();
	
	for question in &message.question {
		for label in &question.qname {
			cursor.write_u8(label.len() as u8).unwrap();
			cursor.write_all(label.as_bytes()).unwrap();
		}
		cursor.write_u8(0).unwrap();
		cursor.write_u16::<BigEndian>(question.qtype).unwrap();
		cursor.write_u16::<BigEndian>(question.qclass).unwrap();
	}
	
	fn write_resources(cursor: &mut Cursor<Vec<u8>>, resources: &Vec<Resource>) {
		for resource in resources {
			for label in &resource.rname {
				cursor.write_u8(label.len() as u8).unwrap();
				cursor.write_all(label.as_bytes()).unwrap();
			}
			cursor.write_u8(0).unwrap();
			
			cursor.write_u16::<BigEndian>(resource.rtype).unwrap();
			cursor.write_u16::<BigEndian>(resource.rclass).unwrap();
			cursor.write_u32::<BigEndian>(resource.ttl).unwrap();
			cursor.write_u16::<BigEndian>(resource.rdata.len() as u16).unwrap();
			cursor.write_all(resource.rdata.as_ref()).unwrap();
		}
	}
	write_resources(&mut cursor, &message.answer);
	write_resources(&mut cursor, &message.authority);
	write_resources(&mut cursor, &message.additional);
	
	return cursor.into_inner();
}
