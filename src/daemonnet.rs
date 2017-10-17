use bytes::{BytesMut, Buf, BufMut};
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
//use std::net::UdpSocket;
use mio::udp::*;
use serialization;
use types::{ DATAGRAM};


const BUFFER_CAPACITY: usize = 800;
const LISTENER: Token = Token(0);
const SENDER: Token = Token(1);

fn daemon_net(
    cast_ip: &str,
    rx_ip: &str,
    rx_port: &str,
    pub_key: &str,
    pay_addr: &str,
    tx_ip: &str,
    tx_port: &str,
    multicast_ip: &str,
    secret: [u8; 64],
) {
    let mut ludpnet;
    let mut profile = Vec::new();
    profile.push(pub_key);
    profile.push(pay_addr);
    profile.push(tx_ip);
    profile.push(tx_port);
    ludpnet = LudpNet::new(cast_ip,  profile, secret);
    ludpnet.start_net(multicast_ip,rx_ip, rx_port,tx_ip,tx_port );
}

pub fn UDPsocket(ipadr: &str, port: &str) -> UdpSocket {
    let ip_and_port = format!("{}:{}", ipadr.clone(), port);
    let saddr: SocketAddr = ip_and_port.parse().unwrap();
    let socket = match UdpSocket::bind(&saddr) {
        Ok(s) => s,
        Err(e) => panic!("Failed to establish bind socket {}", e),
    };
    socket
}

pub struct Socket_Network{
    pub sock: UdpSocket
}
pub struct LudpNet<'a> {
    profile: Vec<&'a str>,
    secret: [u8; 64],
    saddr: Ipv4Addr,
    shutdown: bool,
    pub send_queue: VecDeque<DATAGRAM>,
}

impl<'a>  LudpNet<'a> {
    pub fn new(cast_ip: &str, pro_vec: Vec<&'a str>, secret: [u8; 64]) -> LudpNet<'a> {

        let ip4addr = cast_ip.parse().unwrap();
        LudpNet {
            saddr: ip4addr,
            secret: secret,
            profile: pro_vec,
            shutdown: false,
            send_queue: VecDeque::new(),
        }
    }

    pub fn parse_packet(&mut self, buf: BytesMut) {
        match serialization::on_ping(buf, &self.profile, &self.secret) {
            Some(dgram) => {
                self.send_queue.push_back(dgram);
            }
            _ => {}
        };
    }

    pub fn read_udpsocket(&mut self, rx: &UdpSocket, _: &mut Poll, token: Token, _: Ready) {
        match token {
            LISTENER => {
                let mut buf: BytesMut = BytesMut::with_capacity(BUFFER_CAPACITY);
                match rx.recv_from(&mut buf[..]) {
                    Ok(Some((_, _))) => {
                        self.parse_packet(buf);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error reading UDP packet: {:?}", e);
                    }
                };
                self.shutdown = true;
                //comment out when in production mode
            }
            _ => (),
        }
    }

    pub fn send_packet(&mut self, tx: &UdpSocket, _: &mut Poll, token: Token, _: Ready) {
        match token {
            SENDER => {
                while let Some(datagram) = self.send_queue.pop_front() {
                    match tx.send_to(&datagram.payload, &datagram.sock_addr) {
                        Ok(Some(size)) if size == datagram.payload.len() => {}
                        Ok(Some(_)) => {
                            println!("UDP sent incomplete datagramm");
                        }
                        Ok(None) => {
                            self.send_queue.push_front(datagram);
                            return;
                        }
                        Err(e) => {
                            println!(
                                "Error send UDP:: {:?} and the sock_addr is {:?}",
                                e,
                                &datagram.sock_addr
                            );
                            return;
                        }
                    };
                }
            }
            _ => (),
        }
    }

    /**
     * Enables the network to run event poll
     */
    pub fn start_net(&mut self, multicastip: &str,
         rx_ip: &str, 
         rx_udp: &str,
         tx_ip: &str,
         tx_port: &str
         ) {
        
        let mut poll = Poll::new().unwrap();
        let rx_udpsock = UDPsocket( &rx_ip, &rx_udp);
        let tx_udpsock = UDPsocket(&tx_ip, &tx_port);


        rx_udpsock.join_multicast_v4(&multicastip.parse().unwrap(), &self.saddr).unwrap();

        poll.register(&tx_udpsock, SENDER, Ready::writable(), PollOpt::edge())
            .unwrap();

        poll.register(&rx_udpsock, LISTENER, Ready::readable(), PollOpt::edge())
            .unwrap();

        let mut events = Events::with_capacity(1024);

        
        while !self.shutdown {
            poll.poll(&mut events, None).unwrap();
            for event in &events {
                if event.readiness().is_readable() {
                    self.read_udpsocket(&rx_udpsock, &mut poll, event.token(), event.readiness());
                }
                if event.readiness().is_writable() {
                    self.send_packet(&tx_udpsock,&mut poll, event.token(), event.readiness());
                }
            }
        }
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


    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
    }

    fn pong_host() -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41238", "224.0.0.3");
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(&pub_key);
        vec.push(&cloned_pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        let vec_st: Vec<&str> = vec.iter().map(|s| s as &str).collect();
        let bytes = serialization::payload(&vec_st, 45, &secret, "hello_confirm");
        return (bytes, pub_key.clone(), secret);
    }

    #[test]
    fn test_udp_socket_send_recv() {
        let (mbytes, pub_key, secret) = pong_host();
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(pub_key);
        vec.push(cloned_pub_key);
        vec.push("224.0.0.3".to_string());
        vec.push("41215".to_string());
        let vec_st: Vec<&str> = vec.iter().map(|s| s as &str).collect();
        let mut daem = LudpNet::new(
            "0.0.0.0",
            vec_st,
            secret,
        );
        daem.parse_packet(mbytes);
        assert_eq!(1, daem.send_queue.len());
    }

    #[test]
    fn daemonnet_send_packet() {
        let (_, pub_key, secret) = pong_host();
        daemon_net(
            "0.0.0.0",
            "224.0.0.3",
            "44235",
            &pub_key.clone(),
            &pub_key,
            "224.0.0.4",
            "42233",
            "227.1.1.100",
            secret,
        );
    }

}
