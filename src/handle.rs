use serialization::{from_bytes,extract_payload,hello_reply_datagram,decode_key,decode_str};
use bytes::{BufMut, BytesMut};
use std::str;
use edcert::ed25519;
use types::{DATAGRAM, PROFILE, NETWORK_DATA};

const HELLO: &'static str = "hello";


/**
 * This is where packet from multicast is verified(hash) by ed25519 curve   
 */
pub fn handler(packet: &BytesMut, profile: &PROFILE, secret: &[u8; 64]) -> Option<DATAGRAM> {
    if check_size(&packet) && match_header(&packet) {
		if let Some(net_data) = from_bytes(&packet) {
			let payload = extract_payload(&net_data);
			let pub_key = decode_key(&net_data.pub_key);
			let sig = decode_key(&net_data.sig);

			if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {
				if let Some(v) =  hello_reply_datagram(&net_data, profile, secret, packet.len() as i32) {
					return Some(v);
				}
			}	
		}
    }
    None
}

pub fn match_header(packet: &BytesMut) -> bool {
	if let Ok(v) = str::from_utf8(&packet[0..5]){
		return HELLO == v;
	}
	
	//println!("Found invalid UTF-8");
	false
}


pub fn check_size(packet: &BytesMut) -> bool {
    packet.len() > 200
}
