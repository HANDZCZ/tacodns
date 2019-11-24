extern crate yaml_rust;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nom::branch::alt;
use nom::bytes::complete::{escaped, tag, take, take_while_m_n};
use nom::character::complete::none_of;
use nom::IResult;
use nom::multi::separated_list;
use nom::sequence::delimited;
use yaml_rust::{Yaml, yaml, YamlLoader};

use crate::config::ttl::Parse;
use crate::config::yaml_utils::ExpectStr;
use crate::config::yaml_utils::OptionalIndex;
use crate::regex::Regex;

mod yaml_utils;
mod ttl;

#[derive(Debug, PartialEq, Clone)]
pub enum Label {
	Basic(String),
	Regex(bool, Regex),
	Wildcard /* * */,
	SubWildcard /* ** */,
	AllWildcard /* *** */,
}

pub type ZoneMatcher = Vec<Label>;

#[derive(Debug, PartialEq, Clone)]
pub struct ARecord {
	pub ttl: Duration,
	pub ip4addr: Ipv4Addr,
}

#[derive(Debug, PartialEq, Clone)]
pub struct AaaaRecord {
	pub ttl: Duration,
	pub ip6addr: Ipv6Addr,
}

#[derive(Debug, PartialEq, Clone)]
pub struct NsRecord {
	pub ttl: Duration,
	pub name: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct CnameRecord {
	pub ttl: Duration,
	pub name: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct AnameRecord {
	pub ttl: Duration,
	pub name: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct MxRecord {
	pub ttl: Duration,
	pub priority: u16,
	pub host: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TxtRecord {
	pub ttl: Duration,
	pub data: String,
}

#[derive(Debug, PartialEq, Clone)]
pub enum RnsHost {
	SocketAddr(SocketAddr),
	HostPort(String, u16),
}

#[derive(Debug, PartialEq, Clone)]
pub struct RnsRecord {
	pub ttl: Duration,
	pub host: RnsHost,
	pub external: bool,
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct Records {
	pub a: Vec<ARecord>,
	pub aaaa: Vec<AaaaRecord>,
	pub ns: Vec<NsRecord>,
	pub cname: Vec<CnameRecord>,
	pub aname: Vec<AnameRecord>,
	pub mx: Vec<MxRecord>,
	pub txt: Vec<TxtRecord>,
	pub rns: Vec<RnsRecord>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Zone {
	pub matchers: Vec<ZoneMatcher>,
	pub records: Records,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Config {
	pub ttl: Duration,
	pub zones: Vec<Zone>,
}

const DEFAULT_TTL: Duration = Duration::from_secs(60 * 30);

pub fn parse(yaml_data: &str) -> Config {
	let docs = YamlLoader::load_from_str(yaml_data).unwrap();
	if docs.len() == 0 { panic!("No documents."); }
	if docs.len() > 1 { panic!("Expected only one document."); }
	let yaml = docs[0].as_hash().expect("Expected document to be mapping.");
	
	let ttl = match yaml.optional_index("ttl") {
		Some(ttl_value) => Duration::from_yaml(ttl_value),
		None => DEFAULT_TTL,
	};
	
	let zones_data = yaml.optional_index("zones").expect("Expected zones field.");
	let zones = parse_zones(zones_data, ttl);
	
	return Config {
		ttl,
		zones,
	};
}

fn parse_basic(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, value) = take_while_m_n(1, 63, |x| (x >= 'a' as u8 && x <= 'z' as u8) || (x >= 'A' as u8 && x <= 'Z' as u8) || (x >= '0' as u8 && x <= '9' as u8) || x == '-' as u8 || x == '_' as u8)(i)?;
	Ok((i, Label::Basic(String::from_utf8(value.to_vec()).unwrap().to_lowercase())))
}

fn parse_regex(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, value) = delimited(
		tag("/"),
		escaped(none_of("\\/"), '\\', take(1usize)),
		tag("/"),
	)(i)?;
	let pattern = String::from_utf8(value.to_vec()).unwrap()
		.replace(r"\/", "/");
	Ok((i, Label::Regex(pattern.contains(r"\."), Regex::new(&pattern).unwrap())))
}

fn parse_wildcard(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, _) = tag("*")(i)?;
	Ok((i, Label::Wildcard))
}

fn parse_subwildcard(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, _) = tag("**")(i)?;
	Ok((i, Label::SubWildcard))
}

fn parse_allwildcard(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, _) = tag("***")(i)?;
	Ok((i, Label::AllWildcard))
}

fn parse_label(i: &[u8]) -> IResult<&[u8], Label> {
	alt((parse_allwildcard, parse_subwildcard, parse_wildcard, parse_regex, parse_basic))(i)
}

fn parse_zone_matcher(i: &[u8]) -> IResult<&[u8], ZoneMatcher> {
	separated_list(tag("."), parse_label)(i)
}

fn parse_zone_matchers(i: &[u8]) -> IResult<&[u8], Vec<ZoneMatcher>> {
	separated_list(tag(","), parse_zone_matcher)(i)
}

fn parse_zones(yaml: &Yaml, default_ttl: Duration) -> Vec<Zone> {
	let yaml = yaml.as_hash().expect("Expected zones to be mapping.");
	
	let mut zones = Vec::new();
	
	for (key, value) in yaml {
		let (content, ttl, _) = parse_value_ttl(key.expect_str(), default_ttl);
		let zone_matchers = parse_zone_matchers(content.as_ref()).unwrap().1;
		
		let value = value.as_hash().expect(format!("Expected zone value to be mapping: {:?}", value).as_str());
		let records = parse_zone_content(value, ttl);
		
		zones.push(Zone {
			matchers: zone_matchers,
			records,
		});
	}
	
	return zones;
}

fn arrayify(value: Yaml) -> yaml::Array {
	match value {
		Yaml::Array(array) => array,
		Yaml::Null => vec![],
		value => vec![value],
	}
}

fn parse_value_ttl(value: &str, default_ttl: Duration) -> (&str, Duration, Vec<&str>) {
	let parts: Vec<&str> = value.split(' ').collect();
	
	let body = parts[0];
	
	let duration = Duration::parse(parts.last().unwrap());
	
	let flags = parts[1..parts.len() - if duration.is_ok() { 1 } else { 0 }].to_vec();
	
	return (body, duration.unwrap_or(default_ttl), flags);
}

fn parse_zone_content(zone: &yaml::Hash, ttl: Duration) -> Records {
	let mut records = Records::default();
	
	for (key, value) in zone {
		let (key_record_type, ttl, _) = parse_value_ttl(key.expect_str(), ttl);
		
		if key_record_type.to_uppercase().as_str() == key_record_type {
			let entries = arrayify(value.clone());
			match key_record_type {
				"A" => {
					for entry in entries {
						let (value, ttl, _) = parse_value_ttl(&entry.expect_str(), ttl);
						let ip4_addr: Ipv4Addr = value.parse().expect(format!("Value not valid IPv4 address: {:?}", value).as_str());
						records.a.push(ARecord {
							ttl,
							ip4addr: ip4_addr,
						});
					}
				}
				"AAAA" => {
					for entry in entries {
						let (value, ttl, _) = parse_value_ttl(&entry.expect_str(), ttl);
						let ip6_addr: Ipv6Addr = value.parse().expect(format!("Value not valid IPv6 address: {:?}", value).as_str());
						records.aaaa.push(AaaaRecord {
							ttl,
							ip6addr: ip6_addr,
						});
					}
				}
				"NS" => {
					for entry in entries {
						let (value, ttl, _) = parse_value_ttl(&entry.expect_str(), ttl);
						let mut nameserver = value.to_string();
						if nameserver.ends_with(".") { nameserver.split_off(nameserver.len() - 2); }
						records.ns.push(NsRecord {
							ttl,
							name: nameserver,
						});
					}
				}
				"CNAME" => {
					for entry in entries {
						let (value, ttl, _) = parse_value_ttl(&entry.expect_str(), ttl);
						records.cname.push(CnameRecord {
							ttl,
							name: value.to_string(),
						});
					}
				}
				"ANAME" => {
					for entry in entries {
						let (value, ttl, _) = parse_value_ttl(&entry.expect_str(), ttl);
						records.aname.push(AnameRecord {
							ttl,
							name: value.to_string(),
						});
					}
				}
				"MX" => {
					for entry in entries {
						match &entry {
							Yaml::String(string) => {
								let (value, ttl, _) = parse_value_ttl(&string, ttl);
								records.mx.push(MxRecord {
									ttl,
									priority: 10,
									host: value.to_string(),
								});
							}
							Yaml::Hash(hash) => {
								fn _ttl(hash: &yaml::Hash) -> Option<Duration> {
									Some(Duration::from_yaml(hash.optional_index("ttl")?))
								}
								let ttl = _ttl(&hash).unwrap_or(ttl);
								fn _priority(hash: &yaml::Hash) -> Option<i64> {
									Some(hash.optional_index("priority")?.as_i64().expect("Expected priority to be of type integer."))
								}
								let priority = _priority(&hash).unwrap_or(10);
								let host = hash.optional_index("host").expect("Expected host field.").as_str().expect("Expected host field to be a string.");
								records.mx.push(MxRecord {
									ttl,
									priority: priority as u16,
									host: host.to_string(),
								});
							}
							_ => panic!("Expected String, Array, or Hash: {:?}", entry),
						}
					}
				}
				"TXT" => {
					for entry in entries {
						match &entry {
							Yaml::String(string) => {
								let (value, ttl, flags) = parse_value_ttl(&string, ttl);
								let mut data = value.to_string();
								// add the flags back to the data
								// TODO: find a better way to do this, maybe quoting and validating flags?
								for flag in flags {
									data.push(' ');
									data.push_str(flag);
								}
								records.txt.push(TxtRecord {
									ttl,
									data,
								});
							}
							_ => panic!("Expected String or Array: {:?}", entry),
						}
					}
				}
				"RNS" => {
					for entry in entries {
						let (value, ttl, flags) = parse_value_ttl(&entry.expect_str(), ttl);
						
						// split off the port number from the host
						let split: Vec<&str> = value.split(":").collect();
						let (host, port): (&str, u16) = match split.len() {
							1 => (split[0], 53),
							2 => (split[0], split[1].parse().unwrap()),
							_ => panic!("Unexpected socket addr number"),
						};
						
						// try to parse the host into an IP
						let host = if let Ok(ip_addr) = host.parse() {
							RnsHost::SocketAddr(SocketAddr::new(ip_addr, port))
						} else {
							// if that fails, assume it's a DNS name
							RnsHost::HostPort(host.to_string(), port)
						};
						
						records.rns.push(RnsRecord {
							ttl,
							host,
							external: flags.contains(&"external"),
						});
					}
				}
				_ => panic!("Unknown record type: {:?}", key),
			}
		} else {
			unimplemented!("Nested zones not implemented yet.");
		}
	}
	
	return records;
}

trait FromTime<T> {
	fn from_yaml(yaml: &Yaml) -> T;
}

impl FromTime<Duration> for Duration {
	fn from_yaml(yaml: &Yaml) -> Duration {
		match yaml {
			Yaml::Integer(int) => {
				return Duration::from_secs(*int as u64);
			}
			Yaml::String(string) => {
				return Duration::parse(string).unwrap();
			}
			_ => panic!("Cannot create Duration from non Integer or String type: {:?}", yaml)
		}
	}
}

#[cfg(test)]
mod test {
	use std::time::Duration;
	
	use crate::config::{AaaaRecord, ARecord, Config, DEFAULT_TTL, Label, parse, parse_allwildcard, parse_basic, parse_regex, parse_subwildcard, parse_value_ttl, parse_wildcard, parse_zone_matcher, parse_zone_matchers, Records, TxtRecord, Zone};
	use crate::regex::Regex;
	
	#[test]
	fn test_parse_basic() {
		assert_eq!(parse_basic("test".as_ref()).unwrap().1, Label::Basic("test".to_string()));
		assert_eq!(parse_basic("test.".as_ref()).unwrap().1, Label::Basic("test".to_string()));
		assert_eq!(parse_basic("TeSt.".as_ref()).unwrap().1, Label::Basic("test".to_string()));
	}
	
	#[test]
	fn test_parse_regex() {
		assert_eq!(parse_regex("/test/".as_ref()).unwrap().1, Label::Regex(false, Regex::new(r"test").unwrap()));
		assert_eq!(parse_regex(r"/te\dst/".as_ref()).unwrap().1, Label::Regex(false, Regex::new(r"te\dst").unwrap()));
		assert_eq!(parse_regex(r"/te\/st/".as_ref()).unwrap().1, Label::Regex(false, Regex::new(r"te/st").unwrap()));
		
		assert_eq!(parse_regex(r"/abc\.xyz/".as_ref()).unwrap().1, Label::Regex(true, Regex::new(r"abc\.xyz").unwrap()));
		assert_eq!(parse_regex(r"/abc.xyz/".as_ref()).unwrap().1, Label::Regex(false, Regex::new(r"abc.xyz").unwrap()));
	}
	
	#[test]
	fn test_parse_wildcard() {
		assert_eq!(parse_wildcard("*".as_ref()).unwrap().1, Label::Wildcard);
	}
	
	#[test]
	fn test_parse_subwildcard() {
		assert_eq!(parse_subwildcard("**".as_ref()).unwrap().1, Label::SubWildcard);
	}
	
	#[test]
	fn test_parse_allwildcard() {
		assert_eq!(parse_allwildcard("***".as_ref()).unwrap().1, Label::AllWildcard);
	}
	
	#[test]
	fn test_parse_labels() {
		assert_eq!(parse_basic("test".as_ref()).unwrap().1, Label::Basic("test".to_string()));
		assert_eq!(parse_basic("test.".as_ref()).unwrap().1, Label::Basic("test".to_string()));
	}
	
	#[test]
	fn test_parse_zone_matcher() {
		assert_eq!(parse_zone_matcher("abc".as_ref()).unwrap().1, vec![Label::Basic("abc".to_string())]);
		assert_eq!(parse_zone_matcher("abc.xyz".as_ref()).unwrap().1, vec![Label::Basic("abc".to_string()), Label::Basic("xyz".to_string())]);
		assert_eq!(parse_zone_matcher("*.xyz".as_ref()).unwrap().1, vec![Label::Wildcard, Label::Basic("xyz".to_string())]);
		assert_eq!(parse_zone_matcher("/abc/./xyz/".as_ref()).unwrap().1, vec![Label::Regex(false, Regex::new(r"abc").unwrap()), Label::Regex(false, Regex::new(r"xyz").unwrap())]);
	}
	
	#[test]
	fn test_parse_zone_matchers() {
		assert_eq!(parse_zone_matchers("abc,123".as_ref()).unwrap().1, vec![vec![Label::Basic("abc".to_string())], vec![Label::Basic("123".to_string())]]);
		assert_eq!(parse_zone_matchers("abc,/123/".as_ref()).unwrap().1, vec![vec![Label::Basic("abc".to_string())], vec![Label::Regex(false, Regex::new(r"123").unwrap())]]);
	}
	
	#[test]
	fn test_parse_value_ttl() {
		assert_eq!(parse_value_ttl("test", Duration::from_secs(30)), ("test", Duration::from_secs(30), vec![]));
		assert_eq!(parse_value_ttl("test 1", Duration::from_secs(30)), ("test", Duration::from_secs(1), vec![]));
		assert_eq!(parse_value_ttl("test 1m", Duration::from_secs(30)), ("test", Duration::from_secs(60), vec![]));
	}
	
	#[test]
	fn test_a() {
		assert_eq!(parse(r"zones:
  example.com:
    A: 127.0.0.1"), Config {
			ttl: DEFAULT_TTL,
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![ARecord {
						ttl: DEFAULT_TTL,
						ip4addr: "127.0.0.1".parse().unwrap(),
					}],
					aaaa: vec![],
					ns: vec![],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					txt: vec![],
					rns: vec![],
				},
			}],
		});
	}
	
	#[test]
	fn test_aaaa() {
		assert_eq!(parse(r"zones:
  example.com:
    AAAA: ::1"), Config {
			ttl: DEFAULT_TTL,
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![],
					aaaa: vec![AaaaRecord {
						ttl: DEFAULT_TTL,
						ip6addr: "::1".parse().unwrap(),
					}],
					ns: vec![],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					txt: vec![],
					rns: vec![],
				},
			}],
		});
	}
	
	#[test]
	fn test_txt() {
		assert_eq!(parse(r"zones:
  example.com:
    TXT: hello world"), Config {
			ttl: DEFAULT_TTL,
			zones: vec![Zone {
				matchers: vec![vec![Label::Basic("example".to_string()), Label::Basic("com".to_string())]],
				records: Records {
					a: vec![],
					aaaa: vec![],
					ns: vec![],
					cname: vec![],
					aname: vec![],
					mx: vec![],
					txt: vec![TxtRecord {
						ttl: DEFAULT_TTL,
						data: "hello world".to_string(),
					}],
					rns: vec![],
				},
			}],
		});
	}
}
