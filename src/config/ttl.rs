use std::time::Duration;

use crate::regex::Regex;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub struct NotATtlError;

pub trait Parse<T, E> {
	fn parse(str: &str) -> Result<T, E>;
}

impl Parse<Duration, NotATtlError> for Duration {
	fn parse(time: &str) -> Result<Duration, NotATtlError> {
		let regex = Regex::new(r"^(\d+)([smhdw])?$").unwrap();
		let captures = match regex.captures(time) {
			Some(value) => value,
			None => return Err(NotATtlError {}),
		};
		
		let number: u64 = captures.get(1).unwrap().as_str().parse().unwrap();
		let units = match captures.get(2) {
			None => "s",
			Some(value) => value.as_str(),
		};
		
		let secs = match units {
			"s" => number,
			"m" => number * 60,
			"h" => number * 60 * 60,
			"d" => number * 60 * 60 * 24,
			"w" => number * 60 * 60 * 24 * 7,
			_ => panic!("unknown unit: {}", units),
		};
		
		Ok(Duration::from_secs(secs))
	}
}

#[cfg(test)]
mod test {
	mod parse_ttl {
		use std::time::Duration;
		
		use crate::config::ttl::Parse;
		
		fn parse_ttl(time: &str) -> Duration {
			Duration::parse(time).unwrap()
		}
		
		#[test]
		fn no_units() {
			assert_eq!(parse_ttl("0"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1"), Duration::from_secs(1));
			assert_eq!(parse_ttl("5"), Duration::from_secs(5));
			assert_eq!(parse_ttl("5000"), Duration::from_secs(5000));
		}
		
		#[test]
		fn seconds() {
			assert_eq!(parse_ttl("0s"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1s"), Duration::from_secs(1));
			assert_eq!(parse_ttl("5s"), Duration::from_secs(5));
			assert_eq!(parse_ttl("5000s"), Duration::from_secs(5000));
		}
		
		#[test]
		fn minutes() {
			assert_eq!(parse_ttl("0m"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1m"), Duration::from_secs(60));
			assert_eq!(parse_ttl("5m"), Duration::from_secs(5 * 60));
			assert_eq!(parse_ttl("5000m"), Duration::from_secs(5000 * 60));
		}
		
		#[test]
		fn hours() {
			assert_eq!(parse_ttl("0h"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1h"), Duration::from_secs(60 * 60));
			assert_eq!(parse_ttl("5h"), Duration::from_secs(5 * 60 * 60));
			assert_eq!(parse_ttl("5000h"), Duration::from_secs(5000 * 60 * 60));
		}
		
		#[test]
		fn days() {
			assert_eq!(parse_ttl("0d"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1d"), Duration::from_secs(60 * 60 * 24));
			assert_eq!(parse_ttl("5d"), Duration::from_secs(5 * 60 * 60 * 24));
			assert_eq!(parse_ttl("5000d"), Duration::from_secs(5000 * 60 * 60 * 24));
		}
		
		#[test]
		fn weeks() {
			assert_eq!(parse_ttl("0w"), Duration::from_secs(0));
			assert_eq!(parse_ttl("1w"), Duration::from_secs(60 * 60 * 24 * 7));
			assert_eq!(parse_ttl("5w"), Duration::from_secs(5 * 60 * 60 * 24 * 7));
			assert_eq!(parse_ttl("5000w"), Duration::from_secs(5000 * 60 * 60 * 24 * 7));
		}
	}
}
