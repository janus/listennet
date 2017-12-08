use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use types::{DATAGRAM, PROFILE, HELLONETWORKDATA};
use dsocket::create_sockaddr;

const BUFFER_CAPACITY_MESSAGE: usize = 1300;
const VEC_LEN: usize = 8;
const HELLO: &'static str = "hello";
const HELLO_CONFIRM: &'static str = "hello_confirm";


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
pub fn payload(profile: &PROFILE, seqnum: usize, secret: &[u8; 64], hd: &str) -> BytesMut {
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
    hello_data: &HELLONETWORKDATA,
    profile: &PROFILE,
    secret: &[u8; 64],
    seqnum: i32,
) -> Option<DATAGRAM> {

    if let Some(sock_addr) = create_sockaddr(&hello_data) {
        if let Ok(net_seqnum) = hello_data.seqnum.parse::<i32>() {
            let total_seqnum = net_seqnum + seqnum;

            let payload = payload(&profile, total_seqnum as usize, secret, HELLO_CONFIRM);
            let datagrm = DATAGRAM { sock_addr, payload };
            return Some(datagrm);
        }
    }
    None
}


pub fn from_bytes(packet: &BytesMut) -> Option<HELLONETWORKDATA> {
    if let Ok(str_buf) = str::from_utf8(&packet[..]) {

        let vec: Vec<&str> = str_buf.split_whitespace().collect();
        if vec.len() == VEC_LEN {
            let hello_network_data = HELLONETWORKDATA {
                hd: vec[0].to_string(),
                pub_key: vec[1].to_string(),
                pay_addr: vec[2].to_string(),
                ip_address: vec[3].to_string(),
                udp_port: vec[4].to_string(),
                tme: vec[5].to_string(),
                seqnum: vec[6].to_string(),
                sig: vec[7].to_string(),
            };
            return Some(hello_network_data);
        }
    }
    None
}

pub fn extract_payload(net_data: &HELLONETWORKDATA) -> String {
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
    use serialization;
    use edcert::ed25519;
    use base64::{decode, encode};
    use bytes::{BufMut, BytesMut};
    use types::{DATAGRAM, PROFILE, ENDPOINT, HELLONETWORKDATA};
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

    #[test]
    fn test_received_packet() {
        let hd = "hello";
        let pub_key = "Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=";

        let pay_addr = "AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==";

        let ip_address = "224.0.0.4";
        let udp_port = "42238";
        let tme = "1512275605";
        let sig = "OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2DkgsMsng4rJwZWMfhdc3SxOCk/I70nMgBMwT3eCheSpstx1o4QCw==";
        let seqnum = 89;

        let mut rslt = BytesMut::with_capacity(1400);

        let nt_packet = "hello Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q== MjI0LjAuMC40 NDIyMzg= 1512275605 89 OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2DkgsMsng4rJwZWMfhdc3SxOCk/I70nMgBMwT3eCheSpstx1o4QCw==";

        rslt.put(nt_packet);

        let nt_data: HELLONETWORKDATA = serialization::from_bytes(&rslt).unwrap();

        assert_eq!(nt_data.hd, hd);
        assert_eq!(nt_data.pub_key, pub_key);
        assert_eq!(nt_data.pay_addr, pay_addr);
        assert_eq!(serialization::decode_str(&nt_data.ip_address), ip_address);
        assert_eq!(serialization::decode_str(&nt_data.udp_port), udp_port);
        assert_eq!(nt_data.tme, tme);
        assert_eq!(nt_data.sig, sig);

    }
}
