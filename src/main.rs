#[macro_use]
extern crate clap; // would put this in options.rs, but #[macro_use] can only be done in crate root

mod options;
mod protocol;

use std::net::UdpSocket;
use protocol::Resource;

fn main() {
	let opts = options::parse();
	if opts.verbose { println!("{:?}", opts); }
	
	let socket = UdpSocket::bind((opts.listen_address, opts.listen_port)).unwrap();
	
	loop {
		let mut buf = [0; 512];
		let (_size, src) = socket.recv_from(&mut buf).unwrap();
		
		let mut request = match protocol::parse(&buf) {
			Ok(message) => message,
			Err(error) => {
				eprintln!("Error while parsing DNS request: {:?}", error);
				continue;
			}
		};
		if opts.verbose { println!("request: {:?}", request); }
		
		request.header.qr = true;
		request.header.aa = true;
		request.header.ra = true;
		request.header.rcode = 0;
		request.answer = Vec::with_capacity(request.question.len());
		for question in &request.question {
			// respond to all A requests with 127.0.0.1
			if question.qtype == 1 {
				request.answer.push(Resource {
					rname: question.qname.clone(),
					rtype: 1,
					rclass: 1,
					ttl: 1800,
					rdata: vec![127, 0, 0, 1],
				});
			}
		}
		request.authority = Vec::new();
		request.additional = Vec::new();
		
		if opts.verbose { println!("response: {:?}", request); }
		let response = protocol::serialize(&request);
		socket.send_to(response.as_slice(), &src).unwrap();
	}
}
