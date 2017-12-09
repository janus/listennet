use mio::udp::*;
use std::net::SocketAddr;
use serialization::decode_str;
use types::HelloNetworkData;


pub fn udp_socket(ipadr: &str, port: &str) -> UdpSocket {
    let ip_and_port = format!("{}:{}", ipadr, port);
    let saddr: SocketAddr = ip_and_port.parse::<SocketAddr>().unwrap();
    let socket = match UdpSocket::bind(&saddr) {
        Ok(s) => s,
        Err(e) => panic!("Failed to establish bind socket {}", e),
    };
    socket
}


pub fn create_sockaddr(addr: &str) -> Option<SocketAddr> {
    if let Ok(saddr) = addr.parse::<SocketAddr>() {
        return Some(saddr);
    }
    //println!("Failed to parse SocketAddr");
    None
}
