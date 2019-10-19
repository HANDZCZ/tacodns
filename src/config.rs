extern crate yaml_rust;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::time::Duration;

use yaml_rust::{Yaml, yaml, YamlLoader};

use crate::regex::Regex;

#[derive(Debug, PartialEq)]
pub enum ZoneMatcher {
	Basic(String),
	Regex(Regex),
	List(Vec<ZoneMatcher>),
	Wildcard(Vec<String>, String),
}

#[derive(Debug, PartialEq)]
pub struct Record {
	pub ttl: Duration,
	pub data: Box<[u8]>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Records {
	pub a: Vec<Record>,
	pub aaaa: Vec<Record>,
}

#[derive(Debug, PartialEq)]
pub struct Zone {
	pub matcher: ZoneMatcher,
	pub records: Records,
}

#[derive(Debug, PartialEq)]
pub struct Config {
	pub zones: Vec<Zone>,
}

const DEFAULT_TTL: Duration = Duration::from_secs(60 * 30);

pub fn parse(yaml_data: &str) -> Config {
	let docs = YamlLoader::load_from_str(yaml_data).unwrap();
	if docs.len() == 0 { panic!("No documents."); }
	if docs.len() > 1 { panic!("Expected only one document."); }
	let yaml = docs[0].as_hash().expect("Expected document to be mapping.");
	
	let ttl = match yaml.get(&Yaml::String("ttl".to_string())) {
		Some(ttl_value) => Duration::from_yaml(ttl_value),
		None => DEFAULT_TTL,
	};
	
	let zones_data = yaml.get(&Yaml::String("zones".to_string())).expect("Expected zones field.");
	let zones = parse_zones(zones_data, ttl);
	
	return Config {
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

fn parse_zone_content(zone: &yaml::Hash, ttl: Duration) -> Records {
	let mut records = Records::default();
	
	for (key, value) in zone {
		let (key_record_type, ttl) = extract_ttl(key, ttl);
		
		if key_record_type.to_uppercase().as_str() == key_record_type {
			fn arrayify(value: Yaml) -> yaml::Array {
				match value {
					Yaml::Array(array) => array,
					Yaml::Null => vec![],
					value => vec![value],
				}
			}
			let entries = arrayify(value.clone());
			match key_record_type {
				"A" => {
					for record in entries {
						let (value, ttl) = extract_ttl(&record, ttl);
						let ip4_addr: Ipv4Addr = value.parse().expect(format!("Value not valid IPv4 address: {:?}", value).as_str());
						records.a.push(Record {
							ttl,
							data: Box::new(ip4_addr.octets()),
						});
					}
				}
				"AAAA" => {
					for record in entries {
						let (value, ttl) = extract_ttl(&record, ttl);
						let ip6_addr: Ipv6Addr = value.parse().expect(format!("Value not valid IPv6 address: {:?}", value).as_str());
						records.aaaa.push(Record {
							ttl,
							data: Box::new(ip6_addr.octets()),
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
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![Record {
					ttl: DEFAULT_TTL,
					data: Box::new([127, 0, 0, 1]),
				}],
				aaaa: vec![],
			},
		}]
	});
}

#[test]
fn test_aaaa() {
	assert_eq!(parse(r"zones:
  example.com:
    AAAA: ::1"), Config {
		zones: vec![Zone {
			matcher: ZoneMatcher::Basic("example.com".to_string()),
			records: Records {
				a: vec![],
				aaaa: vec![Record {
					ttl: DEFAULT_TTL,
					data: Box::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
				}],
			},
		}]
	});
}
