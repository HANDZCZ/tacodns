extern crate regex;

use std::ops::Deref;

/// Because regex::Regex doesn't support trait PartialEq, we implement that in this file
#[derive(Debug)]
pub struct Regex(regex::Regex);

impl Regex {
	pub fn new(regex: &str) -> Result<Regex, regex::Error> {
		regex::Regex::new(regex).map(|regex| Regex(regex))
	}
}

impl Deref for Regex {
	type Target = regex::Regex;
	
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl PartialEq<Regex> for Regex {
	fn eq(&self, other: &Regex) -> bool {
		self.as_str() == other.as_str()
	}
}
