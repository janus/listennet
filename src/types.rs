use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;
use std::fmt;
use base64::encode;


pub struct EndPoint<'a> {
    pub ip_address: &'a str,
    pub udp_port: &'a str,
}

#[derive(Debug)]
pub struct Datagram {
    pub sock_addr: SocketAddr,
    pub payload: BytesMut,
}

pub struct Profile<'a> {
    pub pub_key: &'a str,
    pub pay_addr: &'a str,
    pub endpoint: EndPoint<'a>,
}

pub struct HelloData {
    pub kind: u8,
    pub pub_key: [u8; 32],
    pub pay_addr: String,
    pub timestamp: i64,
    pub sock_addr: SocketAddr,
    pub sig: Vec<u8>,
}


impl <'a>fmt::Display for Profile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.pub_key, self.pay_addr, self.endpoint.ip_address, self.endpoint.udp_port)
    }
}

impl fmt::Display for HelloData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {}",
            encode(&self.pub_key),
            self.pay_addr,
            encode(&self.sock_addr.ip().to_string()),
            encode(&self.sock_addr.port().to_string()),
            self.timestamp
        )
    }
}

