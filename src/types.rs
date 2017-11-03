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
    pub pay_addr:  &'a str,
    pub endpoint:  ENDPOINT<'a>,
}

