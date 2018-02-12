use serialization::{from_packet, reply_hello_datagram};
use types::{Datagram, Profile};
use daemonnet::LudpNet;
use bytes::{BufMut, BytesMut};
use std::str;
use edcert::ed25519;
use base64::{decode, encode};


const HELLO: u8 = 0x10;
const HELLO_CONFIRM: u8 = 0x2a;

/**
 * This is where packet from multicast is verified(hash) by ed25519 curve
 */
pub fn handler(packet: &BytesMut, ldnet: &mut LudpNet) -> Option<Datagram> {
    match from_packet(packet) {
        Ok(deserialized_pkt) => {
            match packet[0] {
                HELLO => {
                    let payload = format!("{}", deserialized_pkt);
                    if ed25519::verify(payload.as_bytes(), &deserialized_pkt.sig, &deserialized_pkt.pub_key) {
                        return Some(reply_hello_datagram(&deserialized_pkt, &ldnet));
                    }
                    trace!("Bad Signature");
                },
                HELLO_CONFIRM => {
                    ldnet.nodes.add_neighbor(&deserialized_pkt);
                    return None;
                },
                _ => {
                    trace!("Bad packet header type");
                }
            }
        }
        Err(e) => {
            trace!("Failed: {:?} @ <from_packet funtion>", e);
        }
    }
    None  
}


#[cfg(test)]
mod test {
    use serialization;
    use edcert::ed25519;
    use base64::{encode, decode};
    use bytes::{BufMut, BytesMut};
    use types::{Profile, EndPoint, HelloData};
    use handle::handler;
    use std::str;
    use std::net::{IpAddr, Ipv4Addr};
    use dsocket::create_sockaddr;
    use daemonnet::LudpNet;



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

    fn from_slice(bytes: &[u8]) -> [u8; 64] {
        let mut rtn = [0; 64];
        for i in 0..rtn.len() {
            rtn[i] = bytes[i];
        }
        rtn
    }

    fn header(packet: &BytesMut) -> String {
        if let Ok(v) = str::from_utf8(&packet[0..13]) {
            return v.to_string();
        }
        "".to_string()
    }

    #[test]
    fn test_process_received_hello_packet() {
        let udp_port = "41238";
        let ip_addr = "224.0.0.3";
        let pub_key = "W3vmCmsid9xPltL8NpMRWuf+wZoV4fzmGy8OYZblXVI=";
        let secret = "VlHDUVCldrXr0X/EZSg2QLVMLDeTvOcH3nMMdDaNDCRbe+YKayJ33E+W0vw2kxFa5/7BmhXh/OYbLw5hluVdUg==".as_bytes();
        let pay_addr = "AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+\
        nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlW\
        XFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww\
        68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86\
        Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==";
        let ip_addr_encoded = encode(&ip_addr);
        let udp_port_encoded = &encode(&udp_port);
        let profile = build_profile(&ip_addr_encoded, &udp_port_encoded, &pub_key, &pay_addr);

        let nt_packet =
            b"\x10 W3vmCmsid9xPltL8NpMRWuf+wZoV4fzmGy8OYZblXVI= \
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7h\
         dI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3F\
         XRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zu\
         UFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r\
         3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q== \
		 MjI0LjAuMC40 NDIyMzg= 1512275605 \
		 BSMbTjMWMj2izhJao/zlt3sFS+w15YZaPy2PbM2FgyMgrMjl7NGhnAv+lZ8Lv5VbBDjWkQRS1NRGHckJqO1wAQ==";


        let rslt = BytesMut::from(&nt_packet[..]);
        let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.3","41238")).unwrap();
        let n_secret = decode(secret).unwrap();
        let mut ldnet = LudpNet::new(profile, from_slice(&n_secret), sock_addr);
        let datagram = handler(&rslt, &mut ldnet).unwrap();
        assert_eq!(42, datagram.payload[0]); //Packet Header confirm
        //println!("{:?}", &datagram.payload);
        //let packet_type_hello_confirm = 42 as u8; //hello_confirm  packet type

    }


}
