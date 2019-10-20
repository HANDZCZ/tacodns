use std::net::UdpSocket;
use std::time::Duration;

use protocol::Resource;

use crate::config::{AaaaRecord, ARecord, Config, NsRecord, Records, Zone, ZoneMatcher};
use crate::options::Options;
use crate::server::protocol::Question;

mod protocol;

mod record_type {
	pub const A: u16 = 1;
	pub const NS: u16 = 2;
	pub const CNAME: u16 = 5;
	pub const SOA: u16 = 6;
	pub const MX: u16 = 15;
	pub const TXT: u16 = 16;
	pub const AAAA: u16 = 28;
	pub const SRV: u16 = 33;
}

pub fn serve(opts: &Options, config: &Config) {
	let socket = UdpSocket::bind((opts.listen_address, opts.listen_port)).unwrap();
	
	loop {
		let mut buf = [0; 512];
		let (_size, src) = socket.recv_from(&mut buf).unwrap();
		
		let mut message = match protocol::parse(&buf) {
			Ok(message) => message,
			Err(error) => {
				eprintln!("Error while parsing DNS request: {:?}", error);
				continue;
			}
		};
		if opts.verbose { println!("request: {:?}", message); }
		
		/*request.answer = Vec::with_capacity(request.question.len());
		for question in &request.question {
			// respond to all A requests with 127.0.0.1
			if question.qtype == 1 {
				request.answer.push(Resource {
					rname: question.qname.clone(),
					rtype: 1,
					rclass: 1,
					ttl: 1800,
					rdata: vec![127, 0, 0, 1],
				});
			}
		}
		request.authority = Vec::new();
		request.additional = Vec::new();*/
		
		let response = handle_dns(&message.question, &config);
		
		message.header.qr = true;
		message.header.aa = true;
		message.header.ra = false;
		
		match response {
			Response::Ok(answer, authority, additional) => {
				message.header.rcode = 0;
				message.answer = answer;
				message.authority = authority;
				message.additional = additional;
			}
			Response::FormatError => message.header.rcode = 1,
			Response::ServerFailure => message.header.rcode = 2,
			Response::NameError => message.header.rcode = 3,
			Response::NotImplemented => message.header.rcode = 4,
			Response::Refused => message.header.rcode = 5,
		}
		
		if opts.verbose { println!("response: {:?}", message); }
		socket.send_to(protocol::serialize(&message).as_slice(), src).unwrap();
	}
}

#[derive(Debug, PartialEq)]
enum Response {
	Ok(Vec<Resource>, Vec<Resource>, Vec<Resource>),
	FormatError,
	ServerFailure,
	NameError,
	NotImplemented,
	Refused,
}

fn handle_dns(question: &Vec<Question>, config: &Config) -> Response {
	let mut answer: Vec<Resource> = Vec::new();
	let mut authority: Vec<Resource> = Vec::new();
	let mut additional: Vec<Resource> = Vec::new();
	
	for question in question {
		if question.qclass != 1 { return Response::NotImplemented; }
		let qname: String = question.qname.join(".");
		
		for zone in &config.zones {
			let matches = match &zone.matcher {
				ZoneMatcher::Basic(basic) => basic.as_str() == qname.as_str(),
				ZoneMatcher::Regex(regex) => regex.is_match(&qname),
				ZoneMatcher::List(_) => unimplemented!(),
				ZoneMatcher::Wildcard(_, _) => unimplemented!(),
			};
			if matches {
				match question.qtype {
					record_type::A => {
						for a in &zone.records.a {
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: question.qtype,
								rclass: question.qclass,
								ttl: a.ttl.as_secs() as u32,
								rdata: a.ip4addr.octets().to_vec(),
							});
						}
					}
					record_type::AAAA => {
						for aaaa in &zone.records.aaaa {
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: question.qtype,
								rclass: question.qclass,
								ttl: aaaa.ttl.as_secs() as u32,
								rdata: aaaa.ip6addr.octets().to_vec(),
							});
						}
					}
					record_type::NS => {
						let mut ns_records = vec![];
						let ns_records: &Vec<NsRecord> = if zone.records.ns.len() == 0 {
							// fallback to the zone authority
							for authority in &config.authority {
								ns_records.push(NsRecord {
									ttl: config.ttl,
									name: authority.clone(),
								});
							}
							&ns_records
						} else {
							&zone.records.ns
						};
						for ns in ns_records {
							let mut name: Vec<u8> = vec![];
							let labels: Vec<&str> = ns.name.split(".").collect();
							for label in &labels {
								name.push(label.len() as u8);
								name.append(&mut label.as_bytes().to_vec());
							}
							name.push(0);
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: question.qtype,
								rclass: question.qclass,
								ttl: ns.ttl.as_secs() as u32,
								rdata: name,
							});
							
							// lookup A and AAAA records for this to go in the additional section
							let mut string_labels = vec![];
							for label in &labels {
								string_labels.push(label.to_string());
							}
							
							// lookup A
							if let Response::Ok(mut answer, _, _) = handle_dns(&vec![Question {
								qname: string_labels.clone(),
								qtype: record_type::A,
								qclass: 1,
							}], config) {
								additional.append(&mut answer);
							}
							
							// lookup AAAA
							if let Response::Ok(mut answer, _, _) = handle_dns(&vec![Question {
								qname: string_labels,
								qtype: record_type::AAAA,
								qclass: 1,
							}], config) {
								additional.append(&mut answer);
							}
						}
					}
					record_type::SOA => {
						return Response::NotImplemented;
					}
					record_type::MX => {
						return Response::NotImplemented;
					}
					record_type::TXT => {
						return Response::NotImplemented;
					}
					record_type::SRV => {
						return Response::NotImplemented;
					}
					_ => return Response::NotImplemented
				}
				break;
			}
		}
	}
	
	if answer.len() == 0 {
		return Response::NameError;
	}
	
	return Response::Ok(answer, authority, additional);
}

#[test]
fn test_a() {
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["example".to_string(), "com".to_string()],
		qtype: record_type::A,
		qclass: 1,
	}], &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![ARecord {
					ttl: Duration::from_secs(100),
					ip4addr: "10.10.10.10".parse().unwrap(),
				}],
				aaaa: vec![],
				ns: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::A,
		rclass: 1,
		ttl: 100,
		rdata: vec![10, 10, 10, 10],
	}], vec![], vec![]));
	
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["example".to_string(), "com".to_string()],
		qtype: record_type::A,
		qclass: 1,
	}], &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![ARecord {
					ttl: Duration::from_secs(100),
					ip4addr: "10.10.10.10".parse().unwrap(),
				}, ARecord {
					ttl: Duration::from_secs(100),
					ip4addr: "11.11.11.11".parse().unwrap(),
				}],
				aaaa: vec![],
				ns: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::A,
		rclass: 1,
		ttl: 100,
		rdata: vec![10, 10, 10, 10],
	}, Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::A,
		rclass: 1,
		ttl: 100,
		rdata: vec![11, 11, 11, 11],
	}], vec![], vec![]));
}

#[test]
fn test_aaaa() {
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["example".to_string(), "com".to_string()],
		qtype: record_type::AAAA,
		qclass: 1,
	}], &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![AaaaRecord {
					ttl: Duration::from_secs(100),
					ip6addr: "::1".parse().unwrap(),
				}],
				ns: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::AAAA,
		rclass: 1,
		ttl: 100,
		rdata: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
	}], vec![], vec![]));
	
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["example".to_string(), "com".to_string()],
		qtype: record_type::AAAA,
		qclass: 1,
	}], &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![AaaaRecord {
					ttl: Duration::from_secs(100),
					ip6addr: "::2".parse().unwrap(),
				}, AaaaRecord {
					ttl: Duration::from_secs(100),
					ip6addr: "::3".parse().unwrap(),
				}],
				ns: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::AAAA,
		rclass: 1,
		ttl: 100,
		rdata: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
	}, Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::AAAA,
		rclass: 1,
		ttl: 100,
		rdata: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3],
	}], vec![], vec![]));
}
