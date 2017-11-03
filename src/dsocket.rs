use mio::udp::*;
use std::net::SocketAddr;


pub fn UDPsocket(ipadr: &str, port: &str) -> UdpSocket {
    let ip_and_port = format!("{}:{}", ipadr.clone(), port);
    let saddr: SocketAddr = ip_and_port.parse().unwrap();
    let socket = match UdpSocket::bind(&saddr) {
        Ok(s) => s,
        Err(e) => panic!("Failed to establish bind socket {}", e),
    };
    socket
}