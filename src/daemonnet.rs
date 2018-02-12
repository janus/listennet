use bytes::{Buf, BufMut, BytesMut};
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use mio::udp::*;
use types::{Datagram, EndPoint, Profile};
use serialization::hello_datagram;
use neighbors::Neighbors;
use time;

const BUFFER_CAPACITY: usize = 1400;
const LISTENER: Token = Token(0);
const SENDER: Token = Token(1);

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

//#[derive(Clone)]
pub struct LudpNet<'a> {
    pub profile: Profile<'a>,
    pub secret: [u8; 64],
    shutdown: bool,
    discover: bool,
    set_time: i64,
    pub sock_addr: SocketAddr,
    pub queue: VecDeque<Datagram>,
    pub nodes: Neighbors,
}

impl<'a> LudpNet<'a> {
    pub fn new(profile: Profile<'a>, secret: [u8; 64], sock_addr: SocketAddr) -> LudpNet<'a> {
        LudpNet {
            secret,
            profile,
            shutdown: false,
            discover: true,
            set_time: time::get_time().sec,
            sock_addr: sock_addr,
            queue: VecDeque::new(),
            nodes: Neighbors::new(),
        }
    }

    pub fn time_to_discover_neighbors(&mut self) {
        if self.discover {
            let rst = hello_datagram(&self);
            self.queue.push_front(rst);
            self.discover = false;
            self.nodes = Neighbors::new();
            self.set_time = time::get_time().sec + 600; //Added 10 minutes
        } else {
            if self.set_time < time::get_time().sec {
                self.discover = true;
            }
        }
    }

    pub fn read_udpsocket(
        &mut self,
        rx: &UdpSocket,
        callback: fn(&BytesMut, &LudpNet) -> Option<Datagram>,
        _: &mut Poll,
        token: Token,
        _: Ready,
    ) {
        match token {
            LISTENER => {
                let mut buf: BytesMut = BytesMut::with_capacity(BUFFER_CAPACITY);
                match rx.recv_from(&mut buf[..]) {
                    Ok(Some((_, _))) => {
                        if let Some(dgram) = callback(&buf, &self) {
                            self.queue.push_back(dgram);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        trace!("Error reading UDP packet: {:?}", e);
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
                self.time_to_discover_neighbors();
                while let Some(datagram) = self.queue.pop_front() {
                    match tx.send_to(&datagram.payload, &datagram.sock_addr) {
                        Ok(Some(size)) if size == datagram.payload.len() => {}
                        Ok(Some(_)) => {
                            trace!("UDP sent incomplete datagram");
                            self.queue.push_front(datagram);
                        }
                        Ok(None) => {
                            self.queue.push_front(datagram);
                        }
                        Err(e) => {
                            trace!(
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
    pub fn start_net(
        &mut self,
        tx: UdpSocket,
        rx: UdpSocket,
        callback: fn(&BytesMut, &LudpNet) -> Option<Datagram>,
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
    use types::{Datagram, EndPoint, Profile};
    use daemonnet::LudpNet;
    use dsocket::{create_sockaddr, udp_socket};
    use std::net::Ipv4Addr;
    use handle::handler;
    use mio::udp::*;
    use std::str;

    fn build_profile<'a>(
        ip_address: &'a str,
        udp_port: &'a str,
        pub_key: &'a str,
        pay_addr: &'a str,
    ) -> Profile<'a> {
        let endpoint = EndPoint {
            ip_address,
            udp_port: udp_port,
        };
        Profile {
            pub_key,
            pay_addr,
            endpoint,
        }
    }

    //#[test]
    fn daemonnet_send_packet() {
        let rx_udpsock = udp_socket("224.0.0.7", "42234");
        let tx_udpsock = udp_socket("224.0.0.4", "42238");
        let saddr: Ipv4Addr = "0.0.0.0".parse().unwrap();
        rx_udpsock
            .join_multicast_v4(&"227.1.1.100".parse().unwrap(), &saddr)
            .unwrap();

        let pub_key = "tthjsj==";
        let prv_key = "oouryhHJJ==";
        let pay_addr = "ouehjddjk=";
        let ip_addr = "224.0.0.4";
        let udp_port = "42238";
        let sock_addr = create_sockaddr(&format!("{}:{}", "224.0.0.4", "42238")).unwrap();
        //let profile = build_profile(&encode(&ip_addr), &encode(&udp_port), &pub_key, &pay_addr);
        //let mut ludpnet = LudpNet::new(profile, prv_key.as_bytes(), sock_addr);
        //ludpnet.start_net(tx_udpsock, rx_udpsock, handler);

        //daemon_net(profile, tx_udpsock, rx_udpsock, handler, secret);
    }

}
