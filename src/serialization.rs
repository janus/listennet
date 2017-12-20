
use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use types::{Datagram, Profile, HelloData};
use std::net::SocketAddr;
use dsocket::create_sockaddr;
use std::net;

use std::num;
use base64;


const BUFFER_CAPACITY_MESSAGE: usize = 1400;
const VEC_LEN: usize = 8;
const HELLO: u8 = 16;
const HELLO_CONFIRM: u8 = 42;
const TIME: u8 = 48;
const TIME_CONFIRM: u8 = 52;


#[derive(Debug, Error)]
pub enum Error {
    Utf8Error(str::Utf8Error),
    ParseIntError(num::ParseIntError),
    DecodeError(base64::DecodeError),
    AddrParseError(net::AddrParseError),

    #[error(msg_embedded, no_from, non_std)]
    RuntimeError(String),
}

pub fn decode_str(mstr: &str) -> String {
    if let Ok(val) = decode(&mstr) {
        if let Ok(val_str) = String::from_utf8(val) {
            return val_str;
        }
    }
    return "".to_string();
}



/**
 * Builds the packet.. It is a BytesMut
 */
fn payload(profile: &Profile, seqnum: u32, secret: &[u8; 64], packet_type: u8) -> BytesMut {
    let timestamp = time::get_time().sec;
    let msg = format!(
        "{} {} {} {} {} {}",
        profile.pub_key,
        profile.pay_addr,
        profile.endpoint.ip_address,
        profile.endpoint.udp_port,
        timestamp,
        seqnum
    );
    let mut pkt_bytes = BytesMut::with_capacity(1400);
    pkt_bytes.put::<u8>(packet_type);
    pkt_bytes.put(" ");
    
    let sig = ed25519::sign(msg.as_bytes(), secret);
    let imsg = format!("{} {}",msg, encode(&sig));
    pkt_bytes.put(imsg);
    pkt_bytes

}


pub fn make_hello_packet(profile: &Profile, seqnum: u32, secret: &[u8; 64]) -> BytesMut {
    payload(profile, seqnum, secret, HELLO)

}

pub fn make_hello_confirm_packet(profile: &Profile, seqnum: u32, secret: &[u8; 64]) -> BytesMut {
    payload(profile, seqnum, secret, HELLO_CONFIRM)

}

/**
 * Not related to this project but for learning
 * 
 * 
 */
pub fn get_time_packet(seqnum: u32) ->BytesMut {
    let timestamp = time::get_time().sec;
    let mut pkt_bytes = BytesMut::with_capacity(1400);
    pkt_bytes.put::<u8>(TIME_CONFIRM);
    pkt_bytes.put(" ");
    let msg = format!("{} {}",timestamp, seqnum);
    pkt_bytes.put(msg);
    pkt_bytes

}

/**
 * Returns either nothing or a struct Datagram, which contains
 * endpoint address and packet to be sent
 *
 */
pub fn hello_reply_datagram(
    hello_data: &HelloData,
    profile: &Profile,
    secret: &[u8; 64],
    seqnum: u32,
) -> Datagram {
    let total_seqnum = hello_data.seqnum + seqnum;
    
    Datagram {
        sock_addr: hello_data.sock_addr,
        payload: make_hello_confirm_packet(profile, total_seqnum, secret)
    }
}


pub fn from_bytes(packet: &BytesMut) -> Result<HelloData, Error> {
    let str_buf = str::from_utf8(&packet[..])?;
    let vec: Vec<&str> = str_buf.split_whitespace().collect();
    if vec.len() == VEC_LEN {
        let addr = format!("{}:{}", decode_str(vec[3]), decode_str(vec[4]));
        let hello_network_data = HelloData {
            packet_type: packet[0],
            pub_key: decode(vec[1])?,
            pay_addr: vec[2].to_string(),
            timestamp: vec[5].parse()?,
            seqnum: vec[6].parse()?,
            sock_addr: addr.parse::<SocketAddr>()?,
            sig: decode(vec[7])?
        };
        return Ok(hello_network_data);
    }
    Err(Error::RuntimeError("Bad packet".to_string()))
}


pub fn serialize_payload(net_data: &HelloData) -> String {
    format!(
        " {} {} {} {} {} {} ",
        encode(&net_data.pub_key),
        net_data.pay_addr,
        encode(&net_data.sock_addr.ip().to_string()),
        encode(&net_data.sock_addr.port().to_string()),
        net_data.timestamp,
        net_data.seqnum
    )
}


#[cfg(test)]
mod test {
    use std::str;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use types::{Datagram, Profile, EndPoint, HelloData};
    use handle::handler;
    use std::net::{IpAddr, Ipv4Addr};

    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
    }

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

    fn pong_host() -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41235", "224.0.0.3");
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let packet = serialization::make_hello_confirm_packet(&profile, 45, &secret);
        return (packet, pub_key.clone(), secret);
    }

    #[test]
    fn serialization_test_header_msg() {
        let (packet, _, _) = pong_host();
        let packet_type: u8 = 42;
        assert_eq!(packet[0], packet_type);
    }


    #[test]
    fn test_received_packet() {
        let packet_type: u8 = 16;
        let pub_key = "Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=";

        let pay_addr = "AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIp\
        NLTGK9Tjom/BWDSUGPl+nafzlHDTY\
        W7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda\
        3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1\
        nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x\
        5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby\
        6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw\
        3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==";

        let ip_address = "224.0.0.4";
        let udp_port = 42238;
        let timestamp = 1512275605 as u64;
        let sig = "OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2DkgsMsng4rJwZWMfhdc3SxOCk/I70nMg\
        BMwT3eCheSpstx1o4QCw==";
        let seqnum = 89;

        let nt_packet = b"\x10 Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9T\
         jom/BWDSUGPl+nafzlHDTYW7hdI4yZ5\
         ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOd\
         J/MTyBlWXFCR+HAo3FXRitBqxiX1nKh\
         XpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0\
         Ww68/eIFmb1zuUFljQJKprrX88XypNDv\
         jYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8\
         b+gw3r3+1nKatmIkjn2so1d01QraTlMq\
         VSsbxNrRFi9wrf+M7Q== MjI0LjAuMC40 NDIyMzg= 1512275605 89 \
         OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2Dkgs\
         Msng4rJwZWMfhdc3SxOCk/I70nMgBMwT3eCheSpstx1o4QCw==";

        let rslt = BytesMut::from(&nt_packet[..]);
        let nt_data: HelloData = serialization::from_bytes(&rslt).unwrap();

        assert_eq!(nt_data.packet_type, packet_type);
        assert_eq!(encode(&nt_data.pub_key), pub_key);
        assert_eq!(nt_data.pay_addr, pay_addr);
        assert_eq!(
            nt_data.sock_addr.ip(),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 4))
        );
        assert_eq!(nt_data.sock_addr.port(), udp_port);
        assert_eq!(nt_data.timestamp, timestamp);
        assert_eq!(encode(&nt_data.sig), sig);

    }
}
