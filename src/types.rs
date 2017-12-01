use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;

pub struct ENDPOINT<'a> {
    pub ip_address: &'a str,
    pub udp_port: &'a str,
}

pub struct DATAGRAM {
    pub sock_addr: SocketAddr,
    pub payload: BytesMut,
}


pub struct PROFILE<'a> {
    pub pub_key: &'a str,
    pub pay_addr: &'a str,
    pub endpoint: ENDPOINT<'a>,
}

pub struct NETWORK_DATA {
    pub hd: String,
    pub udp_port: String,
    pub pub_key: String,
    pub pay_addr: String,
    pub seqnum: String,
    pub tme: String,
    pub ip_address: String,
    pub sig: String,
}
