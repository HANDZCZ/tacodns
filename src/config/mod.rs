extern crate yaml_rust;

use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice::SliceIndex;
use std::time::Duration;

use yaml_rust::{Yaml, yaml, YamlLoader};

use crate::regex::Regex;

#[derive(Debug, PartialEq, Clone)]
pub enum ZoneMatcher {
	Basic(String),
	Regex(Regex),
	List(Vec<ZoneMatcher>),
	Wildcard(Vec<String>, String),
}

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
	pub matcher: ZoneMatcher,
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
	
	let authority: Vec<String> = match yaml.get(&Yaml::String("authority".to_string())) {
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
	
	let ttl = match yaml.get(&Yaml::String("ttl".to_string())) {
		Some(ttl_value) => Duration::from_yaml(ttl_value),
		None => DEFAULT_TTL,
	};
	
	let zones_data = yaml.get(&Yaml::String("zones".to_string())).expect("Expected zones field.");
	let zones = parse_zones(zones_data, ttl);
	
	return Config {
		ttl,
		authority,
		zones,
	};
}

fn extract_ttl(yaml: &Yaml, default_duration: Duration) -> (&str, Duration) {
	let key = yaml.as_str().expect(format!("Expected string: {:?}", yaml).as_str());
	let key_parts: Vec<&str> = key.split(" ").collect();
	let key_value = key_parts[0];
	let ttl = if key_parts.len() > 1 { Duration::from_time(key_parts[1]) } else { default_duration };
	
	return (key_value, ttl);
}

fn parse_zones(yaml: &Yaml, default_ttl: Duration) -> Vec<Zone> {
	let yaml = yaml.as_hash().expect("Expected zones to be mapping.");
	
	let mut zones = Vec::new();
	
	for (key, value) in yaml {
		let (key_matcher, ttl) = extract_ttl(key, default_ttl);
		let zone_matcher = parse_zone_name(key_matcher);
		
		let value = value.as_hash().expect(format!("Expected zone value to be mapping: {:?}", value).as_str());
		let records = parse_zone_content(value, ttl);
		
		zones.push(Zone {
			matcher: zone_matcher,
			records,
		});
	}
	
	return zones;
}

fn parse_zone_name(zone_name: &str) -> ZoneMatcher {
	if zone_name.starts_with("/") && zone_name.ends_with("/") {
		return ZoneMatcher::Regex(Regex::new(&zone_name[1..zone_name.len() - 1]).expect(format!("Invalid regex: {:?}", zone_name).as_str()));
	} else {
		return ZoneMatcher::Basic(zone_name.to_string());
	}
}

fn arrayify(value: Yaml) -> yaml::Array {
	match value {
		Yaml::Array(array) => array,
		Yaml::Null => vec![],
		value => vec![value],
	}
}

fn parse_zone_content(zone: &yaml::Hash, ttl: Duration) -> Records {
	let mut records = Records::default();
	
	for (key, value) in zone {
		let (key_record_type, ttl) = extract_ttl(key, ttl);
		
		if key_record_type.to_uppercase().as_str() == key_record_type {
			let entries = arrayify(value.clone());
			match key_record_type {
				"A" => {
					for entry in entries {
						let (value, ttl) = extract_ttl(&entry, ttl);
						let ip4_addr: Ipv4Addr = value.parse().expect(format!("Value not valid IPv4 address: {:?}", value).as_str());
						records.a.push(ARecord {
							ttl,
							ip4addr: ip4_addr,
						});
					}
				}
				"AAAA" => {
					for entry in entries {
						let (value, ttl) = extract_ttl(&entry, ttl);
						let ip6_addr: Ipv6Addr = value.parse().expect(format!("Value not valid IPv6 address: {:?}", value).as_str());
						records.aaaa.push(AaaaRecord {
							ttl,
							ip6addr: ip6_addr,
						});
					}
				}
				"NS" => {
					for entry in entries {
						let (value, ttl) = extract_ttl(&entry, ttl);
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
						let (value, ttl) = extract_ttl(&entry, ttl);
						let mut name = value.to_string();
						records.cname.push(CnameRecord {
							ttl,
							name,
						});
					}
				}
				"ANAME" => {
					for entry in entries {
						let (value, ttl) = extract_ttl(&entry, ttl);
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
								let (value, ttl) = extract_ttl(&entry, ttl);
								records.mx.push(MxRecord {
									ttl,
									priority: 10,
									host: value.to_string(),
								});
							}
							Yaml::Hash(hash) => {
								fn _ttl(hash: &yaml::Hash) -> Option<Duration> {
									Some(Duration::from_yaml(hash.get(&Yaml::String("ttl".to_string()))?))
								}
								let ttl = _ttl(&hash).unwrap_or(ttl);
								fn _priority(hash: &yaml::Hash) -> Option<i64> {
									Some(hash.get(&Yaml::String("priority".to_string()))?.as_i64().expect("Expected priority to be of type integer."))
								}
								let priority = _priority(&hash).unwrap_or(10);
								let host = hash.get(&Yaml::String("host".to_string())).expect("Expected host field.").as_str().expect("Expected host field to be a string.");
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
	fn from_time(time: &str) -> T;
	fn from_yaml(yaml: &Yaml) -> T;
}

impl FromTime<Duration> for Duration {
	fn from_time(time: &str) -> Duration {
		// TODO units
		return Duration::from_secs(time.parse().expect(format!("Expected time to be just a number: {:?}", time).as_str()));
	}
	
	fn from_yaml(yaml: &Yaml) -> Duration {
		match yaml {
			Yaml::Integer(int) => {
				return Duration::from_secs(*int as u64);
			}
			Yaml::String(string) => {
				return Duration::from_time(string.as_str());
			}
			_ => panic!("Cannot create Duration from non Integer or String type: {:?}", yaml)
		}
	}
}

#[test]
fn test_a() {
	assert_eq!(parse(r"zones:
  example.com:
    A: 127.0.0.1"), Config {
		ttl: DEFAULT_TTL,
		authority: vec![],
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
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
			matcher: ZoneMatcher::Basic("example.com".to_string()),
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
