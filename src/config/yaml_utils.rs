use super::yaml_rust::Yaml;
use super::yaml_rust::yaml::Hash;

pub trait ExpectStr {
	fn expect_str(&self) -> &str;
}

impl ExpectStr for Yaml {
	fn expect_str(&self) -> &str {
		self.as_str().expect(&format!("Expected string: {:?}", self))
	}
}

pub trait OptionalIndex<I, O> {
	fn optional_index(&self, index: I) -> Option<O>;
}

impl<'a> OptionalIndex<&'a str, &'a Yaml> for &'a Hash {
	fn optional_index(&self, index: &'a str) -> Option<&'a Yaml> {
		self.get(&Yaml::String(index.to_owned()))
	}
}
