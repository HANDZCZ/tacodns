use std::borrow::Cow;
use std::fs::read_to_string;
use std::net::{IpAddr, SocketAddr};

use resolv_conf::Config;

#[derive(Clap)]
#[clap(version = "0.1", author = "Chris Smith")]
#[derive(Debug, Clone)]
pub struct Options {
	#[clap(short = "l", long = "listen", default_value = "0.0.0.0")]
	pub listen_address: IpAddr,
	
	#[clap(short = "p", long = "port", default_value = "53")]
	pub listen_port: u16,
	
	#[clap(long = "verbose")]
	pub verbose: bool,
	
	#[clap(short = "c", long = "config", default_value = "/etc/tacodns.yml")]
	pub config: String,
	
	#[clap(long = "config-env")]
	pub config_env: Option<String>,
	
	/// Total number of threads.
	#[clap(long = "threads", default_value = "4")]
	pub threads: usize,
	
	/// Server and port to use to lookup records that aren't hosted here. Surround IPv6 addresses in
	/// square brackets.
	#[clap(long = "resolver", raw(default_value = "read_from_resolv_conf()"))]
	pub resolver: SocketAddr,
}

fn read_from_resolv_conf() -> &'static str {
	let config = Config::parse(read_to_string("/etc/resolv.conf").unwrap()).unwrap();
	let nameserver = config.nameservers.get(0).unwrap();
	return Box::leak(format!("{}:53", nameserver).into_boxed_str());
}

pub fn parse() -> Options {
	Options::parse()
}
