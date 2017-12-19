use mio::udp::*;
use std::net::SocketAddr;
use serialization::decode_str;
use types::NETWORK_DATA;


pub fn UDPsocket(ipadr: &str, port: &str) -> UdpSocket {
    let ip_and_port = format!("{}:{}", ipadr, port);
    let saddr: SocketAddr = ip_and_port.parse::<SocketAddr>().unwrap();
    let socket = match UdpSocket::bind(&saddr) {
        Ok(s) => s,
        Err(e) => panic!("Failed to establish bind socket {}", e),
    };
    socket
}


pub fn create_sockaddr(net_data: &NETWORK_DATA) -> Option<SocketAddr> {
    let ip_address = decode_str(&net_data.ip_address);
    let port = decode_str(&net_data.udp_port);
    let addr = format!("{}:{}", ip_address, port);
    if let Ok(saddr) = addr.parse::<SocketAddr>() {
		return Some(saddr);
    }
    //println!("Failed to parse SocketAddr");
    None
}
