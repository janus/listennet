
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
use daemonnet::LudpNet;

const BUFFER_CAPACITY_MESSAGE: usize = 1400;
const VEC_LEN: usize = 7;
const HELLO: u8 = 16;
const HELLO_CONFIRM: u8 = 42;


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
fn payload(profile: &Profile, secret: &[u8; 64], pkt_type: u8) -> BytesMut {
    let timestamp = time::get_time().sec;
    let msg = format!("{} {}", profile, timestamp);
    let sig = ed25519::sign(msg.as_bytes(), secret);
    let imsg = format!(" {} {}", msg, encode(&sig));

    let mut pkt_bytes = BytesMut::with_capacity(1400);
    pkt_bytes.put::<u8>(pkt_type);
    pkt_bytes.put(imsg);
    pkt_bytes
}

pub fn hello_packet(profile: &Profile,  secret: &[u8; 64]) -> BytesMut {
    payload(profile, secret, HELLO)
    //use random to generate number
}

pub fn hello_confirm_packet(profile: &Profile,  secret: &[u8; 64]) -> BytesMut {
    payload(profile, secret, HELLO_CONFIRM)
}

/**
 * Returns either nothing or a struct Datagram, which contains
 * endpoint address and packet to be sent
 *
 */
pub fn reply_hello_datagram(data: &HelloData, ldnet: &LudpNet) -> Datagram {
    Datagram {
        sock_addr: ldnet.sock_addr,
        payload: hello_confirm_packet(&ldnet.profile, &ldnet.secret)
    }
}

pub fn hello_datagram(ldnet: &LudpNet)-> Datagram {
    Datagram {
        sock_addr: ldnet.sock_addr,
        payload: hello_packet(&ldnet.profile, &ldnet.secret)
    }
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut rtn = [0; 32];
    for i in 0..rtn.len() {
        rtn[i] = bytes[i];
    }
    rtn
}

pub fn from_packet(packet: &BytesMut) -> Result<HelloData, Error> {
    let str_buf = str::from_utf8(&packet[..])?;
    let vec: Vec<&str> = str_buf.split_whitespace().collect();
    let timestamp =  vec[5].parse::<i64>()?;
    
    //if !(timestamp + 90 > time::get_time().sec){
    //    return Err(Error::RuntimeError("Stale timestamp".to_owned()));
    //}
    //uncomment the above when not in test mode
    println!("{}", "Inside From Packet");
    let pub_key_vec = decode(vec[1])?;
    if vec.len() == VEC_LEN {
        let addr = format!("{}:{}", decode_str(vec[3]), decode_str(vec[4]));
        let hello_network_data = HelloData {
            kind: packet[0],
            pub_key: from_slice(&pub_key_vec),
            pay_addr: vec[2].to_owned(),
            timestamp,
            sock_addr: addr.parse::<SocketAddr>()?,
            sig: decode(vec[6])?
        };
        return Ok(hello_network_data);
    }
    Err(Error::RuntimeError("Bad packet".to_string()))
}


#[cfg(test)]
mod test {
    use std::str;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use types::{Datagram,  EndPoint, HelloData};
    use std::net::{IpAddr, Ipv4Addr};
    use time;


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
        let timestamp = 1512275605 as i64;
        //let timestamp = time::get_time().sec;
        let sig = "OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2DkgsMsng4rJwZWMfhdc3SxOCk/I70nMg\
        BMwT3eCheSpstx1o4QCw==";


        let nt_packet = b"\x10 Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9T\
         jom/BWDSUGPl+nafzlHDTYW7hdI4yZ5\
         ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOd\
         J/MTyBlWXFCR+HAo3FXRitBqxiX1nKh\
         XpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0\
         Ww68/eIFmb1zuUFljQJKprrX88XypNDv\
         jYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8\
         b+gw3r3+1nKatmIkjn2so1d01QraTlMq\
         VSsbxNrRFi9wrf+M7Q== MjI0LjAuMC40 NDIyMzg= 1512275605 \
         OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2Dkgs\
         Msng4rJwZWMfhdc3SxOCk/I70nMgBMwT3eCheSpstx1o4QCw==";

        let rslt = BytesMut::from(&nt_packet[..]);
        let nt_data: HelloData = serialization::from_packet(&rslt).unwrap();

        assert_eq!(nt_data.kind, packet_type);
        assert_eq!(encode(&nt_data.pub_key), pub_key);
        assert_eq!(nt_data.pay_addr, pay_addr);
        assert_eq!(
            nt_data.sock_addr.ip(),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 4))
        );
        assert_eq!(nt_data.sock_addr.port(), udp_port);
        assert_eq!(nt_data.timestamp, timestamp);
        assert_eq!(encode(&nt_data.sig), sig);

        //let (pk, mk) = ed25519::generate_keypair();
        //println!("{}", encode(&mk[..]));
        //println!("{}", encode(&mk[32..]));


    }
}
