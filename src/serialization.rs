use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use std::net::SocketAddr;
use types::{DATAGRAM, PROFILE, ENDPOINT};

const BUFFER_CAPACITY_MESSAGE: usize = 400;

const HELLO: &'static str = "hello";

const HELLO_CONFIRM: &'static str = "hello_confirm";

pub fn decode_key(mstr: &str) -> Vec<u8> {
    match decode(&mstr) {
        Ok(v) => {
            return v;
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return Vec::new();
        }
    };
}

pub fn decode_str(mstr: &str) -> String {
    match decode(&mstr) {
        Ok(v) => {
            match String::from_utf8(v) {
                Ok(v) => {
                    return v;
                }
                Err(e) => {
                    println!("Failed utf8 conversion  {}", e);
                    return "".to_string();
                }
            };
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return "".to_string();
        }
    };
}

/**
 * Builds the packet.. It is a BytesMut
 */
pub fn payload(
    profile: &PROFILE,
    seqnum: i32,
    secret: &[u8; 64],
    hd: &str
) -> BytesMut {
    let sig;
    let tme = time::get_time().sec + 70;
    let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
    let msg = format!(
        "{} {} {} {} {} {} {}",
        hd,
        profile.pub_key,
        profile.pay_addr,
        profile.endpoint.ip_address,
        profile.endpoint.udp_port,
        tme,
        seqnum
    );
    sig = ed25519::sign(msg.as_bytes(), secret);
    rslt.put(msg);
    rslt.put(" ");
    rslt.put(encode(&sig));
    rslt
}


pub fn parse_packet(buf: &BytesMut, profile: &PROFILE,secret: &[u8; 64] )->Option<DATAGRAM> {
    on_ping(&buf, &profile, &secret) 
}
/**
 * This is where packet from multicast is verified(hash) by ed25519 curve   
 */
pub fn on_ping(packet: &BytesMut, profile: &PROFILE, secret: &[u8; 64]) -> Option<DATAGRAM> {
    let vec_str: Vec<&str>;
    let payload;
    let pub_key;
    let sig;
    if check_size(&packet) && match_header(&packet) {
        vec_str = bytes_vec(&packet);
        payload = extract_payload(&vec_str);
        pub_key = decode_key(&vec_str[1]);
        sig = decode_key(&vec_str[vec_str.len() - 1]);
 
        if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {
            match hello_reply_datagram(&vec_str, profile, secret) {
                Some(v) => { return Some(v); }
                _ => { return None;}
            };
        }   
    }
    return None;
}

/**
 * Returns either nothing or a struct Datagram, which contains
 * endpoint address and packet to be sent
 * 
 */
pub fn hello_reply_datagram(
    vec_str: &Vec<&str>,
    profile: &PROFILE,
    secret: &[u8; 64],
) -> Option<DATAGRAM> {
    let pay_load;
    let datagrm;
    let seqnum;
    let sock_addr: SocketAddr = match create_sockaddr(&vec_str) {
        Some(v) => v,
        _ => {
            println!("{:?}", vec_str);
            return None;
        }
    };

    seqnum = match vec_str[vec_str.len() - 2].parse::<i32>() {
        Ok(v) => v,
        Err(e) => {
            println!("Failed to parse num {:?}", e);
            return None;
        }
    };

    pay_load = payload(&profile, seqnum, secret, HELLO_CONFIRM);
    datagrm = DATAGRAM { sock_addr,  payload: pay_load };
    return Some(datagrm);
}

pub fn create_sockaddr(vec_str: &Vec<&str>) -> Option<SocketAddr> {
    let ip_addr = format!("{}", vec_str[vec_str.len() - 5]);
    let udp_port = format!("{}", vec_str[vec_str.len() - 4]);
    let ip = decode_str(&ip_addr);
    let port = decode_str(&udp_port);
    let addr = format!("{}:{}", ip, port);
    let saddr: SocketAddr = match addr.parse() {
        Ok(v) => v,
        Err(e) => {
            println!("{:?}", e);
            return None;
        }
    };
    return Some(saddr);
}

pub fn match_header(packet: &BytesMut) -> bool {
    match str::from_utf8(&packet[0..5]) {
        Ok(v) => {return HELLO == v;}
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            return false;
        }
    };
}

pub fn check_size(packet: &BytesMut) -> bool {
    packet.len() > 200
}

fn bytes_vec(packet: &BytesMut) -> Vec<&str> {
    let str_buf = match str::from_utf8(&packet[..]) {
        Ok(v) => v,
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            ""
        }
    };
    str_buf.split_whitespace().collect()
}

fn extract_payload(vec: &Vec<&str>) -> String {
    vec[0..7].join(" ")
}

#[cfg(test)]
mod test {
    use std::str;
    use time;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use types::{DATAGRAM, PROFILE, ENDPOINT};

    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
    }
 
    fn build_profile<'a>(ip_address: &'a str,udp_port: &'a str,pub_key: &'a str,
    pay_addr: &'a str )->PROFILE<'a>{
        let endpoint = ENDPOINT {ip_address, udp_port: udp_port};
        PROFILE {
            pub_key,
            pay_addr,
            endpoint
        }
    }
    fn pong_host(hd: &str) -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41235", "224.0.0.3");
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let bytes = serialization::payload(&profile, 45, &secret, hd);
        return (bytes, pub_key.clone(), secret);
    }

    #[test]
    fn serialization_test_header_msg() {
        let (mbytes, _, _) = pong_host("hello_confirm");
        let header_str = str::from_utf8(&mbytes[0..13]).expect("Found invalid UTF-8");
        assert_eq!(header_str, "hello_confirm");
    }

    #[test]
    fn serialization_on_pong_sockaddr() {
        let (mbytes, pub_key, secret) = pong_host("hello");
        let ip_addr = encode("224.0.0.3");
        let udp_port = encode("41235");

        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let soc = "224.0.0.3:41235".parse().unwrap();
        match serialization::on_ping(&mbytes, &profile, &secret) {
            Some(n) => { assert_eq!(n.sock_addr, soc); }
            _ => { assert!(false);}
        }
    }

    #[test]
    fn serialization_on_pong_packet() {
        let (mbytes, pub_key, secret) = pong_host("hello");
        let (ip_addr, udp_port) = (
            encode("41235"),
            encode("224.0.0.3"),
        );
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let seqnum = 45;
        let rtn_pkt = serialization::payload(&profile, seqnum, &secret,"hello");
        match serialization::on_ping(&mbytes, &profile, &secret) {
            Some(n) => {
                assert_eq!(&n.payload[0..5], &rtn_pkt[0..5]);
            }
            _ => { assert!(false);}

        }
    }
}
