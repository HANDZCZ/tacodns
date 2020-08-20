use std::fs::read_to_string;
use std::net::{IpAddr, SocketAddr};

use resolv_conf::Config;

use crate::clap::Clap;

/// A powerful, developer-friendly, authoritative DNS server.
#[derive(Clap)]
#[clap(version = "0.1", author = "Chris Smith")]
#[derive(Debug, Clone)]
pub struct Options {
	/// The address to listen on.
	#[clap(short = "l", long = "listen", default_value = "0.0.0.0")]
	pub listen_address: IpAddr,
	
	/// The port to listen on. This is for both UDP and TCP.
	#[clap(short = "p", long = "port", default_value = "53")]
	pub listen_port: u16,
	
	/// Enable verbose mode.
	#[clap(long = "verbose")]
	pub verbose: bool,
	
	/// Path to your YAML configuration file.
	#[clap(short = "c", long = "config", default_value = "/etc/tacodns.yml")]
	pub config: String,
	
	/// Overrides `--config`, allowing you to provide configuration directly from an environment
	/// variable. Provide the name of the environment variable you will use e.g. TACODNS.
	#[clap(long = "config-env")]
	pub config_env: Option<String>,
	
	/// Number of worker threads. In addition to the number listed here, there are two more threads:
	/// one blocking waiting for UDP packets and the other blocking waiting for TCP connections.
	#[clap(long = "threads", default_value = "4")]
	pub threads: usize,
	
	/// Server and port to use to lookup records that aren't hosted here. Surround IPv6 addresses in
	/// square brackets.
	#[clap(long = "resolver", default_value = read_from_resolv_conf())]
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
