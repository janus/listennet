use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;

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


pub struct HelloNetworkData {
    pub packet_type: u8,
    pub pub_key: Vec<u8>,
    pub pay_addr: String,
    pub seqnum: i32,
    pub timestamp: u32,
    pub sock_addr: SocketAddr,
    pub sig: Vec<u8>,
}


pub enum PacketType {
	Hello,
	Hello_confirm,
	Unknown
}
