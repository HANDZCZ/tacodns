extern crate yaml_rust;

use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice::SliceIndex;
use std::time::Duration;

use nom::{IResult, ParseTo};
use nom::branch::alt;
use nom::bytes::complete::{escaped, is_not, tag, take, take_till, take_while, take_while1, take_while_m_n};
use nom::character::{is_alphabetic, is_digit};
use nom::character::complete::{alpha0, alpha1, digit1, none_of, one_of};
use nom::combinator::{complete, opt};
use nom::multi::separated_list;
use nom::sequence::{delimited, pair, preceded};
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

#[derive(Debug, Default, PartialEq, Clone)]
pub struct Records {
	pub a: Vec<ARecord>,
	pub aaaa: Vec<AaaaRecord>,
	pub ns: Vec<NsRecord>,
	pub cname: Vec<CnameRecord>,
	pub aname: Vec<AnameRecord>,
	pub mx: Vec<MxRecord>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Zone {
	pub matchers: Vec<ZoneMatcher>,
	pub records: Records,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Config {
	pub ttl: Duration,
	pub authority: Vec<String>,
	pub zones: Vec<Zone>,
}

const DEFAULT_TTL: Duration = Duration::from_secs(60 * 30);

pub fn parse(yaml_data: &str) -> Config {
	let docs = YamlLoader::load_from_str(yaml_data).unwrap();
	if docs.len() == 0 { panic!("No documents."); }
	if docs.len() > 1 { panic!("Expected only one document."); }
	let yaml = docs[0].as_hash().expect("Expected document to be mapping.");
	
	let authority: Vec<String> = match yaml.optional_index("authority") {
		Some(authority_value) => {
			let mut authority = vec![];
			for entry in arrayify(authority_value.clone()) {
				match entry {
					Yaml::String(value) => authority.push(value),
					_ => panic!("Expected string values for authority entries. Got: {:?}", entry),
				}
			}
			authority
		}
		None => vec![],
	};
	
	let ttl = match yaml.optional_index("ttl") {
		Some(ttl_value) => Duration::from_yaml(ttl_value),
		None => DEFAULT_TTL,
	};
	
	let zones_data = yaml.optional_index("zones").expect("Expected zones field.");
	let zones = parse_zones(zones_data, ttl);
	
	return Config {
		ttl,
		authority,
		zones,
	};
}

fn parse_basic(i: &[u8]) -> IResult<&[u8], Label> {
	let (i, value) = take_while_m_n(1, 63, |x| (x >= 'a' as u8 && x <= 'z' as u8) || (x >= '0' as u8 && x <= '9' as u8) || x == '-' as u8)(i)?;
	Ok((i, Label::Basic(String::from_utf8(value.to_vec()).unwrap())))
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
		let (content, ttl) = parse_value_ttl(key.expect_str(), DEFAULT_TTL);
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

fn parse_value_ttl(value: &str, default_ttl: Duration) -> (&str, Duration) {
	let parts: Vec<&str> = value.split(' ').collect();
	
	match parts.len() {
		1 => (parts[0], default_ttl),
		2 => (parts[0], Duration::parse(parts[1]).unwrap()),
		_ => panic!("unexpected part count; perhaps you have spaces where they shouldn't be?"),
	}
}

fn parse_zone_content(zone: &yaml::Hash, ttl: Duration) -> Records {
	let mut records = Records::default();
	
	for (key, value) in zone {
		let (key_record_type, ttl) = parse_value_ttl(key.expect_str(), ttl);
		
		if key_record_type.to_uppercase().as_str() == key_record_type {
			let entries = arrayify(value.clone());
			match key_record_type {
				"A" => {
					for entry in entries {
						let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
						let ip4_addr: Ipv4Addr = value.parse().expect(format!("Value not valid IPv4 address: {:?}", value).as_str());
						records.a.push(ARecord {
							ttl,
							ip4addr: ip4_addr,
						});
					}
				}
				"AAAA" => {
					for entry in entries {
						let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
						let ip6_addr: Ipv6Addr = value.parse().expect(format!("Value not valid IPv6 address: {:?}", value).as_str());
						records.aaaa.push(AaaaRecord {
							ttl,
							ip6addr: ip6_addr,
						});
					}
				}
				"NS" => {
					for entry in entries {
						let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
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
						let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
						let mut name = value.to_string();
						records.cname.push(CnameRecord {
							ttl,
							name,
						});
					}
				}
				"ANAME" => {
					for entry in entries {
						let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
						let mut name = value.to_string();
						records.aname.push(AnameRecord {
							ttl,
							name,
						});
					}
				}
				"MX" => {
					for entry in entries {
						match &entry {
							Yaml::String(string) => {
								let (value, ttl) = parse_value_ttl(&entry.expect_str(), ttl);
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
	
	use crate::config::{AaaaRecord, ARecord, Config, DEFAULT_TTL, Label, parse, parse_allwildcard, parse_basic, parse_label, parse_regex, parse_subwildcard, parse_value_ttl, parse_wildcard, parse_zone_matcher, parse_zone_matchers, Records, Zone};
	use crate::regex::Regex;
	
	#[test]
	fn test_parse_basic() {
		assert_eq!(parse_basic("test".as_ref()).unwrap().1, Label::Basic("test".to_string()));
		assert_eq!(parse_basic("test.".as_ref()).unwrap().1, Label::Basic("test".to_string()));
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
		assert_eq!(parse_value_ttl("test", Duration::from_secs(30)), ("test", Duration::from_secs(30)));
		assert_eq!(parse_value_ttl("test 1", Duration::from_secs(30)), ("test", Duration::from_secs(1)));
		assert_eq!(parse_value_ttl("test 1m", Duration::from_secs(30)), ("test", Duration::from_secs(60)));
	}
	
	#[test]
	fn test_a() {
		assert_eq!(parse(r"zones:
  example.com:
    A: 127.0.0.1"), Config {
			ttl: DEFAULT_TTL,
			authority: vec![],
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
			authority: vec![],
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
				},
			}],
		});
	}
}
