use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use threadpool::ThreadPool;

use protocol::Resource;

use crate::config::{Config, Label, RnsHost, ZoneMatcher};
use crate::options::Options;
use crate::server::protocol::{Question, record_type};

mod protocol;

pub fn serve(options: Options, config: Config) {
	let udp_socket = UdpSocket::bind((options.listen_address, options.listen_port)).unwrap();
	let tcp_socket = TcpListener::bind((options.listen_address, options.listen_port)).unwrap();
	
	assert!(options.threads >= 1, "Thread count must be >=1");
	let pool = Arc::new(Mutex::new(ThreadPool::with_name("worker".to_string(), options.threads)));
	
	let udp = {
		let pool = pool.clone();
		let options = options.clone();
		let config = config.clone();
		thread::Builder::new().name("UDP server".to_string()).spawn(move || {
			loop {
				let mut buf = vec![0; 512];
				let (_size, src) = udp_socket.recv_from(&mut buf).unwrap();
				if options.verbose { println!("handling UDP request"); }
				
				let options = options.clone();
				let config = config.clone();
				let socket = udp_socket.try_clone().unwrap();
				let instant = Instant::now();
				pool.lock().unwrap().execute(move || {
					let message = handle_request(buf, &options, &config, false);
					
					socket.send_to(&message, src).unwrap();
					if options.verbose { println!("response took: {:?}", instant.elapsed()); }
				});
			}
		}).expect("failed to spawn thread")
	};
	
	let tcp = thread::Builder::new().name("UDP server".to_string()).spawn(move || {
		loop {
			let (mut stream, _src) = tcp_socket.accept().unwrap();
			if options.verbose { println!("handling TCP request"); }
			
			let message_size = stream.read_u16::<BigEndian>().unwrap();
			let mut buf: Vec<u8> = vec![0; message_size as usize];
			stream.read(buf.as_mut_slice()).unwrap();
			
			let options = options.clone();
			let config = config.clone();
			let instant = Instant::now();
			pool.lock().unwrap().execute(move || {
				let message = handle_request(buf, &options, &config, true);
				
				stream.write_u16::<BigEndian>(message.len() as u16).unwrap();
				stream.write(message.as_slice()).unwrap();
				if options.verbose { println!("response took: {:?}", instant.elapsed()); }
			});
		}
	}).expect("failed to spawn thread");
	
	udp.join().unwrap();
	tcp.join().unwrap();
}

fn handle_request(buf: Vec<u8>, options: &Options, config: &Config, tcp: bool) -> Vec<u8> {
	let mut message = protocol::parse(&buf);
	if options.verbose { println!("request: {:?}", message); }
	if message.header.qr {
		// this is actually a response...possibly a DDoS attempt?
		// drop it
		panic!("Cannot process a response as a request.");
	}
	
	assert_eq!(message.question.len(), 1);
	
	let question = &message.question[0];
	let (answer, mut authority, mut additional) = handle_dns(question, &options, &config);
	
	// always fill the authority section with something
	// be it an actual NS record from above (thus delegating this domain elsewhere)
	// or a re-search, which would generally be used to point back to this server
	if authority.is_empty() && question.qtype != record_type::NS {
		let mut ns_question = question.clone();
		ns_question.qtype = record_type::NS;
		let (_, mut _authority, mut _additional) = handle_dns(&ns_question, options, config);
		authority.append(&mut _authority);
		additional.append(&mut _additional);
	}
	
	message.header.qr = true;
	message.header.aa = true;
	message.header.ra = false;
	
	message.header.rcode = 0;
	message.answer = answer;
	message.authority = authority;
	message.additional = additional;
	
	if options.verbose { println!("response: {:?}", message); }
	return protocol::serialize(&message, tcp);
}

#[derive(Debug, PartialEq, Clone)]
enum Response {
	Ok(Vec<Resource>, Vec<Resource>, Vec<Resource>),
	#[allow(dead_code)]
	FormatError,
	ServerFailure,
	NameError,
	NotImplemented,
	#[allow(dead_code)]
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
fn resolver_lookup(question: Question, server: SocketAddr) -> Response {
	struct CacheEntry {
		response: (Vec<Resource>, Vec<Resource>, Vec<Resource>),
		cache_time: Instant,
		expiration: Instant,
	}
	lazy_static! {
		static ref CACHE: Mutex<HashMap<Question, CacheEntry>> = Mutex::new(HashMap::new());
	}
	
	{
		let cache: &mut HashMap<Question, CacheEntry> = &mut *CACHE.lock().unwrap();
		let cached = cache.get(&question);
		if let Some(entry) = cached {
			if entry.expiration > Instant::now() {
				let mut response = entry.response.clone();
				for record in response.0.iter_mut().chain(response.1.iter_mut()).chain(response.2.iter_mut()) {
					record.ttl -= entry.cache_time.elapsed().as_secs() as u32;
				}
				return Response::Ok(response.0, response.1, response.2);
			} else {
				cache.remove(&question);
			}
		}
	}
	
	match TcpStream::connect(server) {
		Err(_) => return Response::ServerFailure,
		Ok(mut stream) => {
			let request = protocol::serialize(&protocol::make_message_from_question(vec![question.clone()]), true);
			stream.write_u16::<BigEndian>(request.len() as u16).unwrap();
			stream.write(request.as_slice()).unwrap();
			
			let message_size = stream.read_u16::<BigEndian>().unwrap();
			let mut buffer: Vec<u8> = vec![0; message_size as usize];
			stream.read(buffer.as_mut_slice()).unwrap();
			
			let message = protocol::parse(buffer.as_slice());
			
			match message.header.rcode {
				1 => return Response::FormatError,
				2 => return Response::ServerFailure,
				3 => return Response::NameError,
				4 => return Response::NotImplemented,
				5 => return Response::Refused,
				_ => {}
			}
			
			{
				let mut least_expiration = u32::max_value();
				for record in message.answer.iter().chain(message.authority.iter()).chain(message.additional.iter()) {
					if record.ttl < least_expiration {
						least_expiration = record.ttl;
					}
				}
				
				let cache: &mut HashMap<Question, CacheEntry> = &mut *CACHE.lock().unwrap();
				cache.insert(question, CacheEntry {
					response: (message.answer.clone(), message.authority.clone(), message.additional.clone()),
					cache_time: Instant::now(),
					expiration: Instant::now() + Duration::from_secs(least_expiration as u64),
				});
			}
			
			return Response::Ok(message.answer, message.authority, message.additional);
		}
	}
}

fn does_match(matchers: &[ZoneMatcher], qname: &[String]) -> bool {
	'matcher: for zone_matcher in matchers {
		let mut qname = qname.iter().map(|label| label.to_lowercase()).rev().peekable();
		'label: for label in zone_matcher.iter().rev() {
			match label {
				Label::Basic(string) => {
					// if this label doesn't match exactly
					if let Some(value) = qname.next() {
						if &value != string {
							// try another matcher
							continue 'matcher;
						}
					} else {
						continue 'matcher;
					}
				}
				Label::Regex(eager, regex) => {
					if *eager {
						// currently unimplemented
						// do we want to consume everything possible or just what's needed to match?
						// originally, I was just going to consume labels until it matched (and that's what the below code does)
						// but that doesn't allow patterns such as /([a-z]+\.)*[a-z]+/
						// this is because it matches the first [a-z]+ and then dies
						unimplemented!();
						
						/*
						// eager mode we keep consuming labels until we match
						let mut growing_name = String::new();
						loop {
							match qname.next() {
								Some(label) => {
									if growing_name.len() > 0 {
										growing_name.insert(0, '.');
									}
									growing_name.insert_str(0, label);
									
									if regex.is_match(&growing_name) {
										// we've matched; next label
										continue 'label;
									}
								}
								None => {
									// we're out of labels with no match
									continue 'matcher;
								}
							}
						}*/
					} else {
						// if this regex doesn't match
						if let Some(label) = qname.next() {
							if !regex.is_match(&label) {
								// try another matcher
								continue 'matcher;
							}
						} else {
							continue 'matcher;
						}
					}
				}
				Label::Wildcard => {
					// wildcards must match one label
					// take one off
					if qname.next().is_none() {
						// if no more labels; try another matcher
						continue 'matcher;
					}
				}
				Label::SubWildcard => {
					// sub wildcards must match at least one label
					if qname.next().is_none() {
						continue 'matcher;
					}
					
					// and consume all of them
					while qname.peek().is_some() {
						qname.next();
					}
				}
				Label::AllWildcard => {
					// all wildcards can match any number of additional labels
					
					// drain everything
					while qname.peek().is_some() {
						qname.next();
					}
					
					// and match successfully
					break 'label;
				}
			}
		}
		
		// out of labels
		
		// ensure we're also out of names
		if qname.peek().is_none() {
			// great! everything lines up
			return true;
		}
	}
	
	// ran out of matchers; no match
	return false;
}

fn handle_dns(question: &Question, options: &Options, config: &Config) -> (Vec<Resource>, Vec<Resource>, Vec<Resource>) {
	let mut answer: Vec<Resource> = Vec::new();
	let mut authority: Vec<Resource> = Vec::new();
	let mut additional: Vec<Resource> = Vec::new();
	
	let qname: String = question.qname.join(".");
	
	for zone in &config.zones {
		if does_match(&zone.matchers, &question.qname) {
			match question.qtype {
				// CNAME
				_ if !zone.records.cname.is_empty() => {
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
						let question = Question {
							qname: new_name.split(".").map(|label| label.to_string()).collect(),
							qtype: question.qtype,
							qclass: 1,
						};
						let (mut cname_answer, _, _) = handle_dns(&question, options, config);
						if cname_answer.len() > 0 {
							answer.append(&mut cname_answer);
						} else {
							if let Response::Ok(mut cname_answer, _, _) = resolver_lookup(question, options.resolver) {
								answer.append(&mut cname_answer);
							}
						}
					}
				}
				
				// ANAME
				record_type::A | record_type::AAAA if !zone.records.aname.is_empty() => {
					for aname in &zone.records.aname {
						let new_name = rewrite_xname(aname.name.as_str(), qname.as_str());
						
						// follow the ANAME and lookup records there
						// (Note that this might trigger a stack overflow. We aren't handling this
						// right now and shouldn't be considered a security issue. It's the fault of
						// the configurer for not configuring it right.)
						let question = Question {
							qname: new_name.split(".").map(|label| label.to_string()).collect(),
							qtype: question.qtype,
							qclass: 1,
						};
						let mut response = handle_dns(&question, options, config);
						if response.0.len() == 0 {
							if let Response::Ok(answer, authority, additional) = resolver_lookup(question, options.resolver) {
								response = (answer, authority, additional);
							}
						}
						let aname_answer = response.0;
						if aname_answer.len() > 0 {
							let qname_split: Vec<String> = qname.split(".").map(|label| label.to_string()).collect();
							for mut resource in aname_answer {
								resource.rname = qname_split.clone();
								answer.push(resource);
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
					for ns in &zone.records.ns {
						// add the NS to the response
						authority.push(Resource {
							rname: question.qname.clone(),
							rtype: question.qtype,
							rclass: question.qclass,
							ttl: ns.ttl.as_secs() as u32,
							rdata: protocol::serialize_name(ns.name.split('.')),
						});
						
						// lookup A and AAAA records for this to go in the additional section
						let string_labels: Vec<String> = ns.name.split('.').map(|label| label.to_string()).collect();
						
						// lookup A
						let (mut answer, _, _) = handle_dns(&Question {
							qname: string_labels.clone(),
							qtype: record_type::A,
							qclass: 1,
						}, options, config);
						if answer.len() > 0 {
							additional.append(&mut answer);
						}
						
						// lookup AAAA
						let (mut answer, _, _) = handle_dns(&Question {
							qname: string_labels,
							qtype: record_type::AAAA,
							qclass: 1,
						}, options, config);
						if answer.len() > 0 {
							additional.append(&mut answer);
						}
					}
				}
				
				// SOA
				record_type::SOA => {}
				
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
				record_type::TXT => {}
				
				// SRV
				record_type::SRV => {}
				
				_ => {}
			}
			
			if answer.is_empty() && authority.is_empty() && question.qtype != record_type::NS {
				for rns in &zone.records.rns {
					match rns.host.clone() {
						RnsHost::SocketAddr(socket_addr) => {
							if let Response::Ok(mut rns_answer, mut rns_authority, _) = resolver_lookup((*question).clone(), socket_addr) {
								answer.append(&mut rns_answer);
								authority.append(&mut rns_authority);
							}
						}
						RnsHost::HostPort(host, port) => {
							fn handle_response(ans: Vec<Resource>, port: u16) -> Option<SocketAddr> {
								for record in ans {
									let mut cursor = Cursor::new(record.rdata);
									if record.rtype == record_type::A {
										return Some(SocketAddr::new(IpAddr::from([cursor.read_u8().unwrap(), cursor.read_u8().unwrap(), cursor.read_u8().unwrap(), cursor.read_u8().unwrap()]), port));
									}
									if record.rtype == record_type::AAAA {
										return Some(SocketAddr::new(IpAddr::from([cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap(), cursor.read_u16::<BigEndian>().unwrap()]), port));
									}
								}
								return None;
							}
							
							// lookup and attempt connection over IPv6
							for qtype in &[record_type::AAAA, record_type::A] {
								let ns_question = Question {
									qname: host.split(".").map(|label| label.to_string()).collect(),
									qtype: *qtype,
									qclass: 1,
								};
								let mut addr = None;
								if rns.external {
									if let Response::Ok(ans, _, _) = resolver_lookup(ns_question, options.resolver) {
										addr = handle_response(ans, port);
									}
								} else {
									let (ans, _, _) = handle_dns(&ns_question, options, config);
									if ans.len() > 0 {
										addr = handle_response(ans, port);
									} else {
										if let Response::Ok(ans, _, _) = resolver_lookup(ns_question, options.resolver) {
											addr = handle_response(ans, port);
										}
									}
								}
								
								if let Some(addr) = addr {
									if let Response::Ok(mut rns_answer, mut rns_authority, _) = resolver_lookup(question.clone(), addr) {
										answer.append(&mut rns_answer);
										authority.append(&mut rns_authority);
										
										if !answer.is_empty() || !authority.is_empty() {
											// only query up until we get an answer
											break;
										}
									}
								}
							}
						}
					}
				}
			}
			
			if !answer.is_empty() || !authority.is_empty() {
				// we've got an answer; break the search
				break;
			}
		}
	}
	
	return (answer, authority, additional);
}

#[cfg(test)]
mod test {
	use std::time::Duration;
	
	use crate::config::{AaaaRecord, ARecord, CnameRecord, Config, Label, MxRecord, NsRecord, Records, Zone};
	use crate::options::Options;
	use crate::regex::Regex;
	use crate::server::{does_match, handle_dns, rewrite_xname};
	use crate::server::protocol::{Question, record_type, Resource};
	
	#[test]
	fn test_does_match() {
		let com = &["com".to_string()];
		let example_com = &["example".to_string(), "com".to_string()];
		let www_example_com = &["www".to_string(), "example".to_string(), "com".to_string()];
		let lcom = Label::Basic("com".to_string());
		let lexample = Label::Basic("example".to_string());
		let lwww = Label::Basic("www".to_string());
		
		assert!(does_match(&[vec![Label::Basic("example".to_string())]], &["ExAmplE".to_string()]));
		
		assert!(does_match(&[vec![lcom.clone()]], com));
		assert!(!does_match(&[vec![lcom.clone()]], example_com));
		assert!(does_match(&[vec![lexample.clone(), lcom.clone()]], example_com));
		assert!(!does_match(&[vec![lexample.clone(), lcom.clone()]], com));
		assert!(does_match(&[vec![lwww.clone(), lexample.clone(), lcom.clone()]], www_example_com));
		
		assert!(!does_match(&[vec![Label::Wildcard, lcom.clone()]], com));
		assert!(does_match(&[vec![Label::Wildcard, lcom.clone()]], example_com));
		assert!(!does_match(&[vec![Label::Wildcard, lcom.clone()]], www_example_com));
		assert!(does_match(&[vec![Label::Wildcard, Label::Wildcard, lcom.clone()]], www_example_com));
		
		assert!(!does_match(&[vec![lwww.clone(), Label::Wildcard, lcom.clone()]], com));
		assert!(!does_match(&[vec![lwww.clone(), Label::Wildcard, lcom.clone()]], example_com));
		assert!(does_match(&[vec![lwww.clone(), Label::Wildcard, lcom.clone()]], www_example_com));
		
		assert!(!does_match(&[vec![Label::SubWildcard, lcom.clone()]], com));
		assert!(does_match(&[vec![Label::SubWildcard, lcom.clone()]], example_com));
		assert!(does_match(&[vec![Label::SubWildcard, lcom.clone()]], www_example_com));
		
		assert!(!does_match(&[vec![Label::AllWildcard, lcom.clone()]], &[]));
		assert!(does_match(&[vec![Label::AllWildcard, lcom.clone()]], com));
		assert!(does_match(&[vec![Label::AllWildcard, lcom.clone()]], example_com));
		assert!(does_match(&[vec![Label::AllWildcard, lcom.clone()]], www_example_com));
		
		assert!(does_match(&[vec![Label::Regex(false, Regex::new(r"com").unwrap())]], com));
		assert!(!does_match(&[vec![Label::Regex(false, Regex::new(r"com").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::Regex(false, Regex::new(r"c.m").unwrap())]], com));
		assert!(does_match(&[vec![Label::Regex(false, Regex::new(r"[a-z]{3}").unwrap())]], com));
		
		/*
		eager not yet implemented
		assert!(does_match(&[vec![Label::Regex(true, Regex::new(r"[a-z]+\.[a-z]+").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::Regex(true, Regex::new(r"([a-z]+\.)*[a-z]+").unwrap())]], com));
		assert!(does_match(&[vec![Label::Regex(true, Regex::new(r"([a-z]+\.)*[a-z]+").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::Regex(true, Regex::new(r"([a-z]+\.)*[a-z]+").unwrap())]], www_example_com));
		*/
		
		assert!(!does_match(&[vec![Label::Regex(false, Regex::new(r"[a-z]+").unwrap()), lcom.clone()]], com));
		assert!(does_match(&[vec![Label::Regex(false, Regex::new(r"[a-z]+").unwrap()), lcom.clone()]], example_com));
		
		assert!(does_match(&[vec![lexample.clone(), Label::Regex(false, Regex::new(r"com").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::Regex(false, Regex::new(r"example").unwrap()), lcom.clone()]], example_com));
		assert!(does_match(&[vec![Label::Wildcard, Label::Regex(false, Regex::new(r"com").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::SubWildcard, Label::Regex(false, Regex::new(r"com").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::AllWildcard, Label::Regex(false, Regex::new(r"com").unwrap())]], example_com));
		assert!(does_match(&[vec![Label::AllWildcard, Label::Regex(false, Regex::new(r"com").unwrap())]], com));
	}
	
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
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::A,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
			rname: vec!["example".to_string(), "com".to_string()],
			rtype: record_type::A,
			rclass: 1,
			ttl: 100,
			rdata: vec![10, 10, 10, 10],
		}], vec![], vec![]));
		
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::A,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
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
	fn test_case() {
		assert_eq!(handle_dns(&Question {
			qname: vec!["ExAmple".to_string(), "cOm".to_string()],
			qtype: record_type::A,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
			rname: vec!["ExAmple".to_string(), "cOm".to_string()],
			rtype: record_type::A,
			rclass: 1,
			ttl: 100,
			rdata: vec![10, 10, 10, 10],
		}], vec![], vec![]));
	}
	
	#[test]
	fn test_aaaa() {
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::AAAA,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
			rname: vec!["example".to_string(), "com".to_string()],
			rtype: record_type::AAAA,
			rclass: 1,
			ttl: 100,
			rdata: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
		}], vec![], vec![]));
		
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::AAAA,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
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
	fn test_ns() {
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::NS,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![],
					aaaa: vec![],
					ns: vec![NsRecord {
						ttl: Duration::from_secs(100),
						name: "ns.example.com".to_string(),
					}],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					rns: vec![],
				},
			}],
		}), (vec![], vec![Resource {
			rname: vec!["example".to_string(), "com".to_string()],
			rtype: record_type::NS,
			rclass: 1,
			ttl: 100,
			rdata: vec![2, 110, 115, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0],
		}], vec![]));
		
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::NS,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![],
					aaaa: vec![],
					ns: vec![NsRecord {
						ttl: Duration::from_secs(100),
						name: "ns.example.com".to_string(),
					}],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					rns: vec![],
				},
			}, Zone {
				matchers: vec![vec![Label::Basic("ns".to_string()), Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![ARecord {
						ttl: Duration::from_secs(100),
						ip4addr: "1.1.1.1".parse().unwrap(),
					}],
					aaaa: vec![],
					ns: vec![],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					rns: vec![],
				},
			}],
		}), (vec![], vec![Resource {
			rname: vec!["example".to_string(), "com".to_string()],
			rtype: record_type::NS,
			rclass: 1,
			ttl: 100,
			rdata: vec![2, 110, 115, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0],
		}], vec![Resource {
			rname: vec!["ns".to_string(), "example".to_string(), "com".to_string()],
			rtype: record_type::A,
			rclass: 1,
			ttl: 100,
			rdata: vec![1, 1, 1, 1],
		}]));
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
		assert_eq!(handle_dns(&Question {
			qname: vec!["www".to_string(), "example".to_string(), "com".to_string()],
			qtype: record_type::A,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}, Zone {
				matchers: vec![vec![Label::Basic("www".to_string()), Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
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
		
		assert_eq!(handle_dns(&Question {
			qname: vec!["www2".to_string(), "example".to_string(), "com".to_string()],
			qtype: record_type::A,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}, Zone {
				matchers: vec![vec![Label::Basic("www".to_string()), Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}, Zone {
				matchers: vec![vec![Label::Basic("www2".to_string()), Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
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
					rns: vec![],
				},
			}],
		}), (vec![Resource {
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
	
	#[test]
	fn test_mx() {
		assert_eq!(handle_dns(&Question {
			qname: vec!["example".to_string(), "com".to_string()],
			qtype: record_type::MX,
			qclass: 1,
		}, &test_options(), &Config {
			ttl: Duration::from_secs(1800),
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![],
					aaaa: vec![],
					ns: vec![],
					cname: vec![],
					aname: vec![],
					mx: vec![MxRecord {
						ttl: Duration::from_secs(100),
						priority: 10,
						host: "mail.example.com".to_string(),
					}],
					rns: vec![],
				},
			}],
		}), (vec![Resource {
			rname: vec!["example".to_string(), "com".to_string()],
			rtype: record_type::MX,
			rclass: 1,
			ttl: 100,
			rdata: vec![0, 10, 4, 'm' as u8, 'a' as u8, 'i' as u8, 'l' as u8, 7, 'e' as u8, 'x' as u8, 'a' as u8, 'm' as u8, 'p' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8, 'o' as u8, 'm' as u8, 0],
		}], vec![], vec![]));
	}
}
