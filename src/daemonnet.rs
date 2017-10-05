
use bytes::{BytesMut, Buf, BufMut};
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::collections::{VecDeque};
use base64::{encode, decode};
use edcert::ed25519;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use mio::udp::*;
use serialization;
use types::{ENDPOINT, DATAGRAM};

const BUFFER_CAPACITY:usize = 800;
const LISTENER: Token = Token(0);
const SENDER: Token = Token(1);

fn daemon_net(
	rx_ip: String, 
	rx_port: String,
	pub_key: String,
	pay_addr: String,
	tx_ip: String,
	tx_port: String,
	multicast_ip: String,
	secret: [u8; 64]
){
	let mut ludpnet;
	let mut profile = Vec::new();
		profile.push(pub_key.to_string());
		profile.push(pay_addr.to_string());
		profile.push(tx_ip.to_string());
		profile.push(tx_port.to_string());	
	ludpnet = LudpNet::new(rx_ip, rx_port, profile, secret);
	ludpnet.start_net(multicast_ip);
	println!("damenet");
}

pub fn UDPsocket(
	ipadr: &String, 
	port: &String
) -> (UdpSocket, Ipv4Addr) {
	let ip_and_port = format!("{}:{}", ipadr.clone(),port);
	let ip4addr: Ipv4Addr = ipadr.parse().unwrap();
	let saddr: SocketAddr = ip_and_port.parse().unwrap();
	let socket = match UdpSocket::bind(&saddr) {
		Ok(s) => s,
		Err(e) => panic!("Failed to establish bind socket {}", e)
	};
	(socket,ip4addr.clone())
}


pub struct LudpNet {
	tx: UdpSocket,
	rx: UdpSocket,
	profile: Vec<String>,
    secret: [u8; 64],
    saddr: Ipv4Addr,
    shutdown: bool,
	pub send_queue: VecDeque<DATAGRAM>,
}

impl LudpNet {
	pub fn new(
		rx_ip: String, 
		rx_udp: String,
        pro_vec: Vec<String>,
		secret: [u8; 64]
	) -> LudpNet {
		let (rx_udpsock, ip4addr) = UDPsocket(&rx_ip, &rx_udp);
		let (tx_udpsock, _) = UDPsocket(&pro_vec[2], &pro_vec[3]);
		LudpNet {
			tx: tx_udpsock,
			rx: rx_udpsock,
			saddr: ip4addr,
			secret: secret,
			profile: pro_vec,
			shutdown: false,
			send_queue: VecDeque::new()
		}
	}

	pub fn parse_packet(&mut self , buf: BytesMut) { 
		let pfile = self.profile.iter().map(|s| s).collect();
        match serialization::on_ping(buf, &pfile, &self.secret){
			Some(dgram) => {self.send_queue.push_back(dgram);},
			_ => {}
		}; 

	}
	
///To add either threadpool or Eventloop or Poll. 
	pub fn read_udpsocket(&mut self, _: &mut Poll, token: Token, _: Ready) {
		match token {
			LISTENER => {
				let mut buf: BytesMut = BytesMut::with_capacity(BUFFER_CAPACITY);
				match self.rx.recv_from(&mut buf[..]) {
					Ok(Some((len, address))) => {self.parse_packet(buf);},
					Ok(_) => {},
					Err(e) => { println!("Error reading UDP packet: {:?}", e);},
				};
				self.shutdown = true;
				//comment out when in production mode
            },
            _ => ()
		}

	}
		
	
	pub fn send_packet(&mut self,  _: &mut Poll, token: Token, _: Ready) {
		 match token {
            SENDER => {
				while let Some(datagram) = self.send_queue.pop_front() {
					match self.tx.send_to(&datagram.payload, &datagram.sock_addr) {
						Ok(Some(size)) if size == datagram.payload.len() => {},
						Ok(Some(_)) => {
							println!("UDP sent incomplete datagramm");
						},
						Ok(None) => {
							self.send_queue.push_front(datagram);
							return;
						},
						Err(e) => {
							println!("Error send UDP:: {:?} and the sock_addr is {:?}", e, &datagram.sock_addr);
							return;
						}
			        };
		        };
            },
            _ => ()
        }
	}
	
	
	pub fn start_net(&mut self, multicastip: String) {
		println!("Readable");
		let mut poll = Poll::new().unwrap();
		self.rx.join_multicast_v4(&multicastip.parse().unwrap(), &self.saddr).unwrap();

	
		poll.register(&self.tx, SENDER, Ready::writable(), PollOpt::edge()).unwrap();

		poll.register(&self.rx, LISTENER, Ready::readable(), PollOpt::edge()).unwrap();	
		
		let mut events = Events::with_capacity(1024);
		
		while !self.shutdown {
			poll.poll(&mut events, None).unwrap();
            println!("Readable");
			for event in &events {
				if event.readiness().is_readable() {
					println!("Readable");
					self.read_udpsocket(&mut poll, event.token(), event.readiness());
				}

				if event.readiness().is_writable() {
					println!("Writable");
					self.send_packet(&mut poll, event.token(), event.readiness());
				}
			}
        }
	}		

	pub fn close(self){
		drop(self.tx);
		drop(self.rx);
	}
}



#[cfg(test)]
mod test {
	use time;
	use serialization;
	use edcert::ed25519;
	use base64::{decode, encode};
	use bytes::{BufMut, BytesMut};
	use daemonnet::{LudpNet, UDPsocket, daemon_net};


	fn encodeVal(
		udp_port: String, 
		ip_address: String
	)-> (String, String, String, [u8; 64]){
		let (psk, msk) = ed25519::generate_keypair();
		return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
	
	}
	
	fn pong_host() -> (BytesMut, String, [u8; 64]) {
		let (ip_addr, udp_port, pub_key, secret) = encodeVal(
			"41235".to_string(), 
			"224.0.0.3".to_string());
		let cloned_pub_key = pub_key.clone();
		let mut vec = Vec::new();
		vec.push(&pub_key);
		vec.push(&cloned_pub_key);
		vec.push(&ip_addr);
		vec.push(&udp_port);
		let bytes = serialization::payload(&vec, 45, &secret, "ipv4_hello_confirm".to_string()) ;
		return (bytes, pub_key.clone(), secret);		
	}
	
    #[test]
	fn test_udp_socket_send_recv() {
		let (mbytes, pub_key, secret) = pong_host();
		let (ip_addr, udp_port) = (
			encode(&"41235".to_string()), 
			encode(&"224.0.0.3".to_string()));
		let cloned_pub_key = pub_key.clone();
		let mut vec = Vec::new();
		vec.push(pub_key.to_string());
		vec.push(cloned_pub_key.to_string());
		vec.push("224.0.0.3".to_string());
		vec.push("41235".to_string());
		let seqnum = 45;
		let mut daem = LudpNet::new( "224.0.0.0".to_string(), "56731".to_string(), vec.clone(), secret);	
		daem.parse_packet(mbytes);
		assert_eq!(1, daem.send_queue.len());

	}
	
	
	fn daemonnet_send_packet() {
		let (mut mbytes, pub_key, secret) = pong_host();
		let cloned_pub_key = pub_key.clone();
		daemon_net(
			"224.0.0.3".to_string(),
			"41235".to_string(),
			cloned_pub_key,
			pub_key,
			"224.0.0.4".to_string(),
			"41233".to_string(),
		    "227.1.1.100".to_string(),
		    secret
		);
	}


}
