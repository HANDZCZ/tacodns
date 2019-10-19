use std::net::IpAddr;

#[derive(Clap)]
#[clap(version = "0.1", author = "Chris Smith")]
#[derive(Debug)]
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
}

pub fn parse() -> Options {
	Options::parse()
}
