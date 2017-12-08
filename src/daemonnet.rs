use bytes::{BytesMut, Buf, BufMut};
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use mio::udp::*;
use types::{DATAGRAM, PROFILE, ENDPOINT};


const BUFFER_CAPACITY: usize = 800;
const LISTENER: Token = Token(0);
const SENDER: Token = Token(1);

//const CUSTOM_SOCKET: usize = 1;

//const DEFAULT_SOCKET: usize = 0;

/**
 * Why using mio? It has non-block feasture enabled.
 * This is the only function that one needs to call
 * It runs forever that means that it would be on its on thread
 * Once this function is called the udpsocket is started, it would join
 * a multicast, and listens to incoming packets. Any packet with correct
 * protocol would be accepted, and parsed. And it would extract destination
 * end point from the packet. With this end point it would send respond containing
 * its payment address , public key, sequence number,...
 *         let rx_udpsock = UDPsocket("224.0.0.7", "42235");
 * let tx_udpsock = UDPsocket("224.0.0.4", "42239");
 *   let saddr: Ipv4Addr = "0.0.0.0".parse().unwrap();
 * rx_udpsock.join_multicast_v4(&"227.1.1.100".parse().unwrap(), &saddr).unwrap();
 * let (_, pub_key, secret) = pong_host("hello");
 * daemon_net(
 * &pub_key.clone(),
 * &pub_key,
 * "224.0.0.4",
 *  "42239",
 * tx_udpsock,
 * rx_udpsock,
 * serialization::on_ping,
 *   secret,
 * );
 *
 */



pub struct LudpNet<'a> {
    profile: PROFILE<'a>,
    secret: [u8; 64],
    shutdown: bool,
    pub send_queue: VecDeque<DATAGRAM>,
}

impl<'a> LudpNet<'a> {
    pub fn new(profile: PROFILE<'a>, secret: [u8; 64]) -> LudpNet<'a> {
        LudpNet {
            secret,
            profile,
            shutdown: false,
            send_queue: VecDeque::new(),
        }
    }

    pub fn read_udpsocket(
        &mut self,
        rx: &UdpSocket,
        callback: fn(&BytesMut, &PROFILE, &[u8; 64]) -> Option<DATAGRAM>,
        _: &mut Poll,
        token: Token,
        _: Ready,
    ) {
        match token {
            LISTENER => {
                let mut buf: BytesMut = BytesMut::with_capacity(BUFFER_CAPACITY);
                match rx.recv_from(&mut buf[..]) {
                    Ok(Some((_, _))) => {
                        if let Some(dgram) = callback(&buf, &self.profile, &self.secret) {
                            self.send_queue.push_back(dgram);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        println!("Error reading UDP packet: {:?}", e);
                    }
                };
                self.shutdown = true;
                //comment out when in production mode
            }
            _ => {}
        }
    }

    pub fn send_packet(&mut self, tx: &UdpSocket, _: &mut Poll, token: Token, _: Ready) {
        match token {
            SENDER => {
                while let Some(datagram) = self.send_queue.pop_front() {
                    match tx.send_to(&datagram.payload, &datagram.sock_addr) {
                        Ok(Some(size)) if size == datagram.payload.len() => {}
                        Ok(Some(_)) => {
                            //println!("UDP sent incomplete datagram");
                            self.send_queue.push_front(datagram);
                        }
                        Ok(None) => {
                            self.send_queue.push_front(datagram);
                        }
                        Err(e) => {
                            // println!(
                            //    "Error send UDP:: {:?} and the sock_addr is {:?}",
                            //    e,
                            //    &datagram.sock_addr
                            // );
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
    pub fn start_net(
        &mut self,
        tx: UdpSocket,
        rx: UdpSocket,
        callback: fn(&BytesMut, &PROFILE, &[u8; 64]) -> Option<DATAGRAM>,
    ) {
        let mut poll = Poll::new().unwrap();
        poll.register(&tx, SENDER, Ready::writable(), PollOpt::edge())
            .unwrap();

        poll.register(&rx, LISTENER, Ready::readable(), PollOpt::edge())
            .unwrap();

        let mut events = Events::with_capacity(1024);

        while !self.shutdown {
            poll.poll(&mut events, None).unwrap();
            for event in &events {
                if event.readiness().is_readable() {
                    self.read_udpsocket(&rx, callback, &mut poll, event.token(), event.readiness());
                }
                if event.readiness().is_writable() {
                    self.send_packet(&tx, &mut poll, event.token(), event.readiness());
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
    use base64::encode;
    use bytes::{BufMut, BytesMut};
    use types::{DATAGRAM, PROFILE, ENDPOINT};
    use daemonnet::LudpNet;
    use dsocket::udp_socket;
    use std::net::Ipv4Addr;
    use handle::handler;
    use mio::udp::*;
    use std::str;

    fn daemon_net(
        profile: PROFILE,
        tx: UdpSocket,
        rx: UdpSocket,
        callback: fn(&BytesMut, &PROFILE, &[u8; 64]) -> Option<DATAGRAM>,
        secret: [u8; 64],
    ) {
        let mut ludpnet = LudpNet::new(profile, secret);
        ludpnet.start_net(tx, rx, callback);
    }

    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
    }

    fn build_profile<'a>(
        ip_address: &'a str,
        udp_port: &'a str,
        pub_key: &'a str,
        pay_addr: &'a str,
    ) -> PROFILE<'a> {
        let endpoint = ENDPOINT {
            ip_address,
            udp_port: udp_port,
        };
        PROFILE {
            pub_key,
            pay_addr,
            endpoint,
        }
    }

    fn pong_host(hd: &str) -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41238", "224.0.0.3");
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        //let vec_st: Vec<&str> = vec.iter().map(|s| s as &str).collect();
        let bytes = serialization::payload(&profile, 45, &secret, hd);
        return (bytes, pub_key.clone(), secret);
    }


	#[test]
    fn test_udp_socket_send_recv() {
        let (mbytes, pub_key, secret) = pong_host("hello");
        let cloned_pub_key = pub_key.clone();
        let ip_addr = "224.0.0.3";
        let udp_port = "41215";
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);

        let daem = LudpNet::new(profile, secret);
        handler(&mbytes, &daem.profile, &daem.secret);
        assert_eq!(0, daem.send_queue.len());
    }

    //#[test]
    fn daemonnet_send_packet() {
        let rx_udpsock = udp_socket("224.0.0.7", "42234");
        let tx_udpsock = udp_socket("224.0.0.4", "42238");

        let saddr: Ipv4Addr = "0.0.0.0".parse().unwrap();
        rx_udpsock
            .join_multicast_v4(&"227.1.1.100".parse().unwrap(), &saddr)
            .unwrap();

        let (_, pub_key, secret) = pong_host("hello");
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile("224.0.0.4", "42238", &pub_key, &cloned_pub_key);
        daemon_net(profile, tx_udpsock, rx_udpsock, handler, secret);
    }


}
