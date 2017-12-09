use bytes::{BufMut, BytesMut};
use time;
use std::str;
use edcert::ed25519;
use base64::{decode, encode};
use types::{Datagram, Profile, HelloNetworkData};
use dsocket::create_sockaddr;

const BUFFER_CAPACITY_MESSAGE: usize = 1400;
const VEC_LEN: usize = 8;
const HELLO: u8 = 16;
const HELLO_CONFIRM: u8 = 32;


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
pub fn payload(profile: &Profile, seqnum: usize, secret: &[u8; 64], packet_type: u8) -> BytesMut {
    let timestamp = time::get_time().sec + 70;
    let mut rslt = BytesMut::with_capacity(BUFFER_CAPACITY_MESSAGE);

    let msg = format!(
        "{} {} {} {} {} {} {}",
        packet_type,
        profile.pub_key,
        profile.pay_addr,
        profile.endpoint.ip_address,
        profile.endpoint.udp_port,
        timestamp,
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
    hello_data: &HelloNetworkData,
    profile: &Profile,
    secret: &[u8; 64],
    seqnum: i32,
) -> Datagram {

    let total_seqnum = hello_data.seqnum + seqnum;
    let payload = payload(&profile, total_seqnum as usize, secret, HELLO_CONFIRM);
    Datagram {
        sock_addr: hello_data.sock_addr,
        payload,
    }
}


pub fn from_bytes(packet: &BytesMut) -> Option<HelloNetworkData> {
    if let Ok(str_buf) = str::from_utf8(&packet[..]) {

        let vec: Vec<&str> = str_buf.split_whitespace().collect();
        if vec.len() == VEC_LEN {
            let packet_type = vec[0].parse::<u8>().unwrap_or(0 as u8);
            let pub_key = decode(vec[1]).unwrap_or(Vec::new());
            let ip_address = decode_str(vec[3]);
            let port = decode_str(vec[4]);
            let addr = format!("{}:{}", ip_address, port);
            let sock_addr = match create_sockaddr(&addr) {
                Some(saddr) => saddr,
                None => {
                    return None;
                }
            };
            let sig = decode(vec[7]).unwrap_or(Vec::new());
            let seqnum = vec[6].parse::<i32>().unwrap_or(0 as i32);
            let timestamp = vec[5].parse::<u32>().unwrap_or(0 as u32);

            let hello_network_data = HelloNetworkData {
                packet_type,
                pub_key,
                pay_addr: vec[2].to_string(),
                timestamp,
                seqnum,
                sock_addr,
                sig,
            };
            return Some(hello_network_data);
        }
    }
    None
}

pub fn extract_payload(net_data: &HelloNetworkData) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        net_data.packet_type,
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
    use types::{Datagram, Profile, EndPoint, HelloNetworkData};
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

    fn pong_host(packet_type: u8) -> (BytesMut, String, [u8; 64]) {
        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41235", "224.0.0.3");
        let cloned_pub_key = pub_key.clone();
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &cloned_pub_key);
        let bytes = serialization::payload(&profile, 45, &secret, packet_type);
        return (bytes, pub_key.clone(), secret);
    }

    #[test]
    fn serialization_test_header_msg() {
        let (mbytes, _, _) = pong_host(32);
        let header_str = str::from_utf8(&mbytes[0..2]).expect("Found invalid UTF-8");
        let packet_type = header_str.parse::<u8>().unwrap_or(0 as u8);
        assert_eq!(packet_type, 32);
    }


    #[test]
    fn test_received_packet() {
        let packet_type = 16;
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
        let timestamp = 1512275605 as u32;
        let sig = "OhWwXXH7e2O7YFk5P7UFfq/4tkb+g2uSI2DkgsMsng4rJwZWMfhdc3SxOCk/I70nMg\
        BMwT3eCheSpstx1o4QCw==";
        let seqnum = 89;

        let mut rslt = BytesMut::with_capacity(1400);

        let nt_packet = "16 Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=
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

        rslt.put(nt_packet);

        let nt_data: HelloNetworkData = serialization::from_bytes(&rslt).unwrap();

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
