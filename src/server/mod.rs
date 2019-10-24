use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use threadpool::ThreadPool;

use protocol::Resource;

use crate::config::{AaaaRecord, ARecord, CnameRecord, Config, NsRecord, Records, Zone, ZoneMatcher};
use crate::options::Options;
use crate::server::protocol::{Message, Question, record_type};

mod protocol;

pub fn serve(options: Options, config: Config) {
	let socket = UdpSocket::bind((options.listen_address, options.listen_port)).unwrap();
	
	assert!(options.threads >= 2, "Thread count must be >=2");
	let pool = ThreadPool::new(options.threads);
	
	loop {
		let mut buf = [0; 512];
		let (_size, src) = socket.recv_from(&mut buf).unwrap();
		
		let options = options.clone();
		let config = config.clone();
		let socket = socket.try_clone().unwrap();
		let instant = Instant::now();
		pool.execute(move || {
			let mut message = protocol::parse(&buf);
			if options.verbose { println!("request: {:?}", message); }
			
			let response = handle_dns(&message.question, &options, &config);
			
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
			
			if options.verbose { println!("response: {:?}", message); }
			socket.send_to(protocol::serialize(&message).as_slice(), src).unwrap();
			if options.verbose { println!("response took: {:?}", instant.elapsed()); }
		});
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

fn rewrite_xname(xname_destination: &str, qname: &str) -> String {
	// TODO perhaps this isn't the best way to operate here
	// rather than using the regular "if it ends with a dot, make it absolute" scheme, perhaps we make our own syntax?
	// example.com:
	//   MX: mail.example.com
	//   MX: .mail 
	// www.example.com:
	//   CNAME: example.com
	//   CNAME: ..
	// www2.example.com:
	//   CNAME: www.example.com
	//   CNAME: ..www
	// mail.example.com:
	
	// generate the full name this maps to, with the trailing dot removed
	if xname_destination.ends_with(".") {
		// CNAME is absolute
		xname_destination.split_at(xname_destination.len() - 1).0.to_string()
	} else {
		// CNAME is relative; make it absolute
		let mut parent_name = qname;
		if let Some(index) = parent_name.find(".") {
			parent_name = parent_name.split_at(index + 1).1;
		}
		xname_destination.to_string() + "." + parent_name
	}
}

/// Performs a DNS query against a third-party recursive resolver.
fn resolver_lookup(question: Vec<Question>, server: SocketAddr) -> Response {
	// TODO cache
	match TcpStream::connect(server) {
		Err(_) => return Response::ServerFailure,
		Ok(mut stream) => {
			let request = protocol::serialize(&protocol::make_message_from_question(question));
			stream.write_u16::<BigEndian>(request.len() as u16).unwrap();
			stream.write(request.as_slice()).unwrap();
			
			let message_size = stream.read_u16::<BigEndian>().unwrap();
			let mut buffer: Vec<u8> = vec![0; message_size as usize];
			stream.read(buffer.as_mut_slice()).unwrap();
			
			let mut message = protocol::parse(buffer.as_slice());
			return Response::Ok(message.answer, message.authority, message.additional);
		}
	}
}

fn handle_dns(question: &Vec<Question>, options: &Options, config: &Config) -> Response {
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
					// CNAME
					_ if zone.records.cname.len() > 0 => {
						for cname in &zone.records.cname {
							let new_name = rewrite_xname(cname.name.as_str(), qname.as_str());
							
							// add the CNAME to our result
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: record_type::CNAME,
								rclass: question.qclass,
								ttl: cname.ttl.as_secs() as u32,
								rdata: protocol::serialize_name(new_name.split('.')),
							});
							
							// follow the CNAME and lookup records there
							// (Note that this might trigger a stack overflow. We aren't handling this
							// right now and shouldn't be considered a security issue. It's the fault of
							// the configurer for not configuring it right.)
							let question = vec![Question {
								qname: new_name.split(".").map(|label| label.to_string()).collect(),
								qtype: question.qtype,
								qclass: 1,
							}];
							match handle_dns(&question, options, config) {
								Response::Ok(mut cname_answer, _, _) => answer.append(&mut cname_answer),
								Response::NameError => {
									if let Response::Ok(mut cname_answer, _, _) = resolver_lookup(question, options.resolver) {
										answer.append(&mut cname_answer);
									}
								}
								_ => {
									// no-op
								}
							}
						}
					}
					
					// ANAME
					record_type::A | record_type::AAAA if zone.records.aname.len() > 0 => {
						for aname in &zone.records.aname {
							let new_name = rewrite_xname(aname.name.as_str(), qname.as_str());
							
							// follow the ANAME and lookup records there
							// (Note that this might trigger a stack overflow. We aren't handling this
							// right now and shouldn't be considered a security issue. It's the fault of
							// the configurer for not configuring it right.)
							let question = vec![Question {
								qname: new_name.split(".").map(|label| label.to_string()).collect(),
								qtype: question.qtype,
								qclass: 1,
							}];
							match handle_dns(&question, options, config) {
								Response::Ok(mut cname_answer, _, _) => answer.append(&mut cname_answer),
								Response::NameError => {
									if let Response::Ok(mut aname_answer, _, _) = resolver_lookup(question, options.resolver) {
										let qname_split: Vec<String> = qname.split(".").map(|label| label.to_string()).collect();
										for mut resource in aname_answer {
											resource.rname = qname_split.clone();
											answer.push(resource);
										}
									}
								}
								_ => {
									// no-op
								}
							}
						}
					}
					
					// A
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
					
					// AAAA
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
					
					// NS
					record_type::NS => {
						let mut ns_records = vec![]; // this needs to be out here to fix a ownership issue
						
						// if this zone doesn't have any NS records, inherit from the top-level zone authority
						let ns_records: &Vec<NsRecord> = if zone.records.ns.len() == 0 {
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
							// add the NS to the response
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: question.qtype,
								rclass: question.qclass,
								ttl: ns.ttl.as_secs() as u32,
								rdata: protocol::serialize_name(ns.name.split('.')),
							});
							
							// lookup A and AAAA records for this to go in the additional section
							let string_labels: Vec<String> = ns.name.split('.').map(|label| label.to_string()).collect();
							
							// lookup A
							if let Response::Ok(mut answer, _, _) = handle_dns(&vec![Question {
								qname: string_labels.clone(),
								qtype: record_type::A,
								qclass: 1,
							}], options, config) {
								additional.append(&mut answer);
							}
							
							// lookup AAAA
							if let Response::Ok(mut answer, _, _) = handle_dns(&vec![Question {
								qname: string_labels,
								qtype: record_type::AAAA,
								qclass: 1,
							}], options, config) {
								additional.append(&mut answer);
							}
						}
					}
					
					// SOA
					record_type::SOA => {
						return Response::NotImplemented;
					}
					
					// MX
					record_type::MX => {
						for mx in &zone.records.mx {
							let mut rdata: Vec<u8> = vec![];
							rdata.push((mx.priority >> 8) as u8);
							rdata.push(mx.priority as u8);
							rdata.append(&mut protocol::serialize_name(mx.host.split(".")));
							answer.push(Resource {
								rname: question.qname.clone(),
								rtype: question.qtype,
								rclass: question.qclass,
								ttl: mx.ttl.as_secs() as u32,
								rdata,
							});
						}
					}
					
					// TXT
					record_type::TXT => {
						return Response::NotImplemented;
					}
					
					// SRV
					record_type::SRV => {
						return Response::NotImplemented;
					}
					
					_ => return Response::NotImplemented
				}
				
				// we matched something; break the search
				break;
			}
		}
	}
	
	if answer.len() == 0 {
		return Response::NameError;
	}
	
	return Response::Ok(answer, authority, additional);
}

#[cfg(test)]
fn test_options() -> Options {
	Options {
		listen_address: "127.0.0.1".parse().unwrap(),
		listen_port: 0,
		verbose: false,
		config: "".to_string(),
		config_env: None,
		threads: 0,
		resolver: "127.0.0.53:53".parse().unwrap(),
	}
}

#[test]
fn test_a() {
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["example".to_string(), "com".to_string()],
		qtype: record_type::A,
		qclass: 1,
	}], &test_options(), &Config {
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
				cname: vec![],
				aname: vec![],
				mx: vec![],
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
	}], &test_options(), &Config {
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
				cname: vec![],
				aname: vec![],
				mx: vec![],
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
	}], &test_options(), &Config {
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
				cname: vec![],
				aname: vec![],
				mx: vec![],
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
	}], &test_options(), &Config {
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
				cname: vec![],
				aname: vec![],
				mx: vec![],
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

#[test]
fn test_rewrite_xname() {
	// Q: www2.example.com
	// www2.example.com CNAME www.example.com.
	assert_eq!(rewrite_xname("www.example.com.", "www2.example.com"), "www.example.com");
	
	// Q: www2.example.com
	// www2.example.com CNAME www
	assert_eq!(rewrite_xname("www", "www2.example.com"), "www.example.com");
}

#[test]
fn test_cname() {
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["www".to_string(), "example".to_string(), "com".to_string()],
		qtype: record_type::A,
		qclass: 1,
	}], &test_options(), &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![ARecord {
					ttl: Duration::from_secs(100),
					ip4addr: "127.0.0.1".parse().unwrap(),
				}],
				aaaa: vec![],
				ns: vec![],
				cname: vec![],
				aname: vec![],
				mx: vec![],
			},
		}, Zone {
			matcher: ZoneMatcher::Basic("www.example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![],
				ns: vec![],
				cname: vec![CnameRecord {
					ttl: Duration::from_secs(100),
					name: "example.com.".to_string(),
				}],
				aname: vec![],
				mx: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["www".to_string(), "example".to_string(), "com".to_string()],
		rtype: record_type::CNAME,
		rclass: 1,
		ttl: 100,
		rdata: vec![7, 'e' as u8, 'x' as u8, 'a' as u8, 'm' as u8, 'p' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8, 'o' as u8, 'm' as u8, 0],
	}, Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::A,
		rclass: 1,
		ttl: 100,
		rdata: vec![127, 0, 0, 1],
	}], vec![], vec![]));
	
	assert_eq!(handle_dns(&vec![Question {
		qname: vec!["www2".to_string(), "example".to_string(), "com".to_string()],
		qtype: record_type::A,
		qclass: 1,
	}], &test_options(), &Config {
		ttl: Duration::from_secs(1800),
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![ARecord {
					ttl: Duration::from_secs(100),
					ip4addr: "127.0.0.1".parse().unwrap(),
				}],
				aaaa: vec![],
				ns: vec![],
				cname: vec![],
				aname: vec![],
				mx: vec![],
			},
		}, Zone {
			matcher: ZoneMatcher::Basic("www.example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![],
				ns: vec![],
				cname: vec![CnameRecord {
					ttl: Duration::from_secs(100),
					name: "example.com.".to_string(),
				}],
				aname: vec![],
				mx: vec![],
			},
		}, Zone {
			matcher: ZoneMatcher::Basic("www2.example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![],
				ns: vec![],
				cname: vec![CnameRecord {
					ttl: Duration::from_secs(100),
					name: "www".to_string(),
				}],
				aname: vec![],
				mx: vec![],
			},
		}],
	}), Response::Ok(vec![Resource {
		rname: vec!["www2".to_string(), "example".to_string(), "com".to_string()],
		rtype: record_type::CNAME,
		rclass: 1,
		ttl: 100,
		rdata: vec![3, 'w' as u8, 'w' as u8, 'w' as u8, 7, 'e' as u8, 'x' as u8, 'a' as u8, 'm' as u8, 'p' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8, 'o' as u8, 'm' as u8, 0],
	}, Resource {
		rname: vec!["www".to_string(), "example".to_string(), "com".to_string()],
		rtype: record_type::CNAME,
		rclass: 1,
		ttl: 100,
		rdata: vec![7, 'e' as u8, 'x' as u8, 'a' as u8, 'm' as u8, 'p' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8, 'o' as u8, 'm' as u8, 0],
	}, Resource {
		rname: vec!["example".to_string(), "com".to_string()],
		rtype: record_type::A,
		rclass: 1,
		ttl: 100,
		rdata: vec![127, 0, 0, 1],
	}], vec![], vec![]));
}
