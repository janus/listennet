use serialization::{bytes_vec,extract_payload,hello_reply_datagram,decode_key};
use bytes::{BufMut, BytesMut};
use std::str;
use edcert::ed25519;
use types::{DATAGRAM, PROFILE};

const HELLO: &'static str = "hello";

//pub fn parse_packet(buf: &BytesMut, profile: &PROFILE,secret: &[u8; 64] )->Option<DATAGRAM> {
//    on_ping(&buf, &profile, &secret)
//}
/**
 * This is where packet from multicast is verified(hash) by ed25519 curve   
 */
pub fn handler(packet: &BytesMut, profile: &PROFILE, secret: &[u8; 64]) -> Option<DATAGRAM> {
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
                Some(v) => {
                    return Some(v);
                }
                _ => {
                    return None;
                }
            };
        }
    }
    return None;
}

pub fn match_header(packet: &BytesMut) -> bool {
    match str::from_utf8(&packet[0..5]) {
        Ok(v) => {
            return HELLO == v;
        }
        Err(e) => {
            println!("Found invalid UTF-8 {:?}", e);
            return false;
        }
    };
}

pub fn check_size(packet: &BytesMut) -> bool {
    packet.len() > 200
}