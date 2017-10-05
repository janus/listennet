use bytes::{BufMut, BytesMut};
use std::net::SocketAddr;

pub struct ENDPOINT {
	pub ip_address: String,
	pub udp_port: String
}

pub struct DATAGRAM {
	pub sock_addr: SocketAddr,
	pub payload: BytesMut
}
