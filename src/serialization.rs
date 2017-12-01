use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use std::net::SocketAddr;
use types::{DATAGRAM, PROFILE, NETWORK_DATA};
use dsocket::create_sockaddr;

const BUFFER_CAPACITY_MESSAGE: usize = 400;

const VEC_LEN: usize = 8;

const HELLO: &'static str = "hello";

const HELLO_CONFIRM: &'static str = "hello_confirm";


pub fn decode_key(mstr: &str) -> Vec<u8> {
    if let Ok(v) =  decode(&mstr) {
        return v;
    }
    return Vec::new();
}

pub fn decode_str(mstr: &str) -> String {
    if let Ok(v) = decode(&mstr) {
		if let Ok(vv) = String::from_utf8(v) {
			return vv; 
		}		
    }
    return "".to_string();
}

/**
 * Builds the packet.. It is a BytesMut
 */
pub fn payload(profile: &PROFILE, seqnum: usize, secret: &[u8; 64], hd: &str) -> BytesMut {
    let tme = time::get_time().sec + 70;
    let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);
    
    let mut msg = format!(
        "{} {} {} {} {} {} {}",
        hd,
        profile.pub_key,
        profile.pay_addr,
        profile.endpoint.ip_address,
        profile.endpoint.udp_port,
        tme,
        seqnum
    );
    let sig = ed25519::sign(msg.as_bytes(), secret);
    rslt.put(msg);
    rslt.put(" ");
    rslt.put(encode(&sig));
    rslt
}


/**
 * Returns either nothing or a struct Datagram, which contains
 * endpoint address and packet to be sent
 * 
 */
pub fn hello_reply_datagram(
    net_data: &NETWORK_DATA,
    profile: &PROFILE,
    secret: &[u8; 64],
    seqnum: i32
) -> Option<DATAGRAM> {
	
    if let Some(sock_addr) = create_sockaddr(&net_data) {
		if let Ok(net_seqnum) = net_data.seqnum.parse::<i32>() {
			let mut total_seqnum  = net_seqnum + seqnum;
			let datagrm = DATAGRAM {
				sock_addr,
				payload: payload(&profile, total_seqnum as usize, secret, HELLO_CONFIRM),
			};
			return Some(datagrm);
		}
    }
    None
}


pub fn from_bytes(packet: &BytesMut) -> Option<NETWORK_DATA> {
    if let Ok(str_buf) = str::from_utf8(&packet[..]){
		let vec: Vec<&str> = str_buf.split_whitespace().collect();
		if vec.len() == VEC_LEN {
			let network_data = NETWORK_DATA {
				hd: vec[0].to_string(),
				pub_key: vec[1].to_string(),
				pay_addr: vec[2].to_string(),
				ip_address: vec[3].to_string(),
				udp_port: vec[4].to_string(),
				tme: vec[5].to_string(),
				seqnum: vec[6].to_string(),
				sig: vec[7].to_string()
			};
			return Some(network_data);
		}
	}
    None
}

pub fn extract_payload(net_data: &NETWORK_DATA) -> String {
    format!(
		"{} {} {} {} {} {} {}",
		net_data.hd,
        net_data.pub_key,
        net_data.pay_addr,
        net_data.ip_address,
        net_data.udp_port,
        net_data.tme,
        net_data.seqnum
    )
}

#[cfg(test)]
mod test {
    use std::str;
    use time;
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use types::{DATAGRAM, PROFILE, ENDPOINT, NETWORK_DATA};
    use handle::handler;

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
        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41235", "224.0.0.3");
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
        match handler(&mbytes, &profile, &secret) {
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
        let (mbytes, pub_key, secret) = pong_host("hello");
        let (ip_addr, udp_port) = (encode("41235"), encode("224.0.0.3"));
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let seqnum = 45;
        let rtn_pkt = serialization::payload(&profile, seqnum, &secret, "hello");
        match handler(&mbytes, &profile, &secret) {
            Some(n) => {
                assert_eq!(&n.payload[0..5], &rtn_pkt[0..5]);
            }
            _ => {
                assert!(false);
            }

        }
    }
}
