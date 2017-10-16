use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use std::net::SocketAddr;
use types::DATAGRAM;

const BUFFER_CAPACITY_MESSAGE: usize = 400;

pub fn decode_key(mstr: &str) -> Option<Vec<u8>> {
    match decode(&mstr) {
        Ok(v) => {
            return Some(v);
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return None;
        }
    };
}

pub fn decode_str(mstr: &str) -> Option<String> {
    match decode(&mstr) {
        Ok(v) => {
            match String::from_utf8(v) {
                Ok(v) => {
                    return Some(v);
                }
                Err(e) => {
                    println!("Failed utf8 conversion  {}", e);
                    return None;
                }
            };
        }
        Err(e) => {
            println!("Failed to decode  {}", e);
            return None;
        }
    };
}

/**
 * Builds the packet.. It is a BytesMut
 */
pub fn payload(
    profile: &Vec<&str>,
    seqnum: i32,
    secret: &[u8; 64],
    header_msg: &str,
) -> BytesMut {
    let sig;
    let tme = time::get_time().sec + 70;
    let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
    let msg = format!(
        "{} {} {} {} {} {} {}",
        header_msg,
        profile[0],
        profile[1],
        profile[2],
        profile[3],
        tme,
        seqnum
    );
    sig = ed25519::sign(msg.as_bytes(), secret);
    rslt.put(msg);
    rslt.put(" ");
    rslt.put(encode(&sig));
    rslt
}

/**
 * This is where packet from multicat is verified(hash)   
 */
pub fn on_ping(packet: BytesMut, profile: &Vec<&str>, secret: &[u8; 64]) -> Option<DATAGRAM> {
    let vec_str: Vec<&str>;
    let payload;
    let pub_key;
    let sig;
    if check_size(&packet) && match_header(&packet) {
        vec_str = bytes_vec(&packet);
        payload = extract_payload(&vec_str);
        pub_key = match decode_key(&vec_str[1]) {
            Some(v) => v,
            _ => { return None; }
        };
        sig = match decode_key(&vec_str[vec_str.len() - 1]) {
            Some(v) => v,
            _ => { return None; }
        };
        if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {
            match create_datagram(vec_str, profile, secret) {
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
pub fn create_datagram(
    vec_str: Vec<&str>,
    profile: &Vec<&str>,
    secret: &[u8; 64],
) -> Option<DATAGRAM> {
    let pay_load;
    let hd;
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

    hd = "hello_confirm";
    pay_load = payload(&profile, seqnum, secret, hd);
    datagrm = DATAGRAM { sock_addr,  payload: pay_load };
    return Some(datagrm);
}

pub fn create_sockaddr(vec_str: &Vec<&str>) -> Option<SocketAddr> {
    let ip_addr = format!("{}", vec_str[vec_str.len() - 5]);
    let udp_port = format!("{}", vec_str[vec_str.len() - 4]);
    let ip = match decode_str(&ip_addr) {
        Some(v) => v,
        _ => {
            return None;
        }
    };
    let port = match decode_str(&udp_port) {
        Some(v) => v,
        _ => {
            return None;
        }
    };
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
    match str::from_utf8(&packet[0..13]) {
        Ok(v) => {return "hello_confirm" == v;}
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

    fn encodeVal(udp_port: &str, ip_address: &str) -> (String, String, String, [u8; 64]) {
        let (psk, msk) = ed25519::generate_keypair();
        return (encode(&ip_address), encode(&udp_port), encode(&psk), msk);
    }

    fn pong_host() -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) =
            encodeVal("41235", "224.0.0.3");
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
    fn serialization_test_header_msg() {
        let (mbytes, _, _) = pong_host();
        let header_str = str::from_utf8(&mbytes[0..13]).expect("Found invalid UTF-8");
        assert_eq!(header_str, "hello_confirm");
    }

    #[test]
    fn serialization_on_pong_sockaddr() {
        let (mbytes, pub_key, secret) = pong_host();
        let (ip_addr, udp_port) = (
            encode("41235"),
            encode("224.0.0.3"),
        );
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(&pub_key);
        vec.push(&cloned_pub_key);
        vec.push(&ip_addr);
        vec.push(&udp_port);
        let vec_st: Vec<&str> = vec.iter().map(|s| s as &str).collect();
        let soc = "224.0.0.3:41235".parse().unwrap();
        match serialization::on_ping(mbytes, &vec_st, &secret) {
            Some(n) => {
                assert_eq!(n.sock_addr, soc);
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn serialization_on_pong_packet() {
        let (mbytes, pub_key, secret) = pong_host();
        let (ip_addr, udp_port) = (
            encode("41235"),
            encode("224.0.0.3"),
        );
        let cloned_pub_key = pub_key.clone();
        let mut vec = Vec::new();
        vec.push(pub_key);
        vec.push(cloned_pub_key);
        vec.push(ip_addr);
        vec.push(udp_port);
        let seqnum = 45;
        let hd = "hello_confirm";
        let vec_st: Vec<&str> = vec.iter().map(|s| s as &str).collect();
        let rtn_pkt = serialization::payload(&vec_st.clone(), seqnum, &secret, hd);
        match serialization::on_ping(mbytes.clone(), &vec_st, &secret) {
            Some(n) => {
                assert_eq!(&n.payload[..], &rtn_pkt[..]);
            }
            _ => {
                assert!(false);
            }

        }
    }
}
