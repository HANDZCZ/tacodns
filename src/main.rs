#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static; // would put this in options.rs, but #[macro_use] can only be done in crate root

use std::{env, fs::read_to_string};

mod options;
mod config;
mod server;
mod regex;

fn main() {
	let opts = options::parse();
	if opts.verbose { println!("{:?}", opts); }
	
	let config_data = if let Some(config_env) = &opts.config_env {
		env::var(config_env).expect(format!("Missing {:?} environment variable.", opts.config_env).as_str())
	} else {
		read_to_string(&opts.config).unwrap()
	};
	let config = config::parse(config_data.as_str());
	if opts.verbose { println!("{:?}", config) }
	
	server::serve(opts, config);
}
