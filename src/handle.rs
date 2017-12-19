use serialization::{from_bytes, extract_payload, hello_reply_datagram};
use bytes::{BufMut, BytesMut};
use std::str;
use edcert::ed25519;
use base64::decode;
use base64::encode;
use types::{Datagram, Profile, PacketType};

const HELLO: u8 = 0x10;
const HELLO_CONFIRM: u8 = 0x2a;

/**
 * This is where packet from multicast is verified(hash) by ed25519 curve
 */
pub fn handler(packet: &BytesMut, profile: &Profile, secret: &[u8; 64]) -> Option<Datagram> {
    match packet_type(packet) {
        PacketType::Hello => {
            match from_bytes(packet) {
                Ok(hello_data) => {
                    let payload = extract_payload(&hello_data);
                    let len = packet.len() - hello_data.sig.len() - 1;
                    if ed25519::verify(payload.as_bytes(), &hello_data.sig, &hello_data.pub_key) {
                        let v = hello_reply_datagram(&hello_data, profile, secret, len as u32);
                        return Some(v);
                    }
                    trace!("Bad Signature");
                }

                Err(e) => {
                    trace!("Failed: {:?} @ <from_bytes funtion>", e);
                }
            }
        }
        _ => {}
    }
    trace!("Bad packet header type");
    None
}


pub fn packet_type(packet: &BytesMut) -> PacketType {
    match packet[0] {
        HELLO => PacketType::Hello,
        HELLO_CONFIRM => PacketType::Hello_confirm,
        _ => PacketType::Unknown,
    }
}



#[cfg(test)]
mod test {
    use serialization;
    use edcert::ed25519;
    use base64::encode;
    use bytes::{BufMut, BytesMut};
    use types::{Profile, EndPoint, HelloNetworkData};
    use handle::handler;
    use std::str;
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

    fn header(packet: &BytesMut) -> String {
        if let Ok(v) = str::from_utf8(&packet[0..13]) {
            return v.to_string();
        }
        "".to_string()
    }



    #[test]
    fn test_process_received_packet() {

        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41238", "224.0.0.3");
        let pay_addr = "AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+\
        nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlW\
        XFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww\
        68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86\
        Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==";
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &pay_addr);


        let nt_packet =
            b"\x10 Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s= \
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7h\
         dI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3F\
         XRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zu\
         UFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r\
         3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q== \
		 MjI0LjAuMC40 NDIyMzg= 1512275605 89 \
		 rSdupHKPpZ463vg0DcwmB033R0Nm7yynYgf5lLCqXVxvAX3k3LssWR+paXDkDDrtsji14A+eTfXY7rpQs34oCg==";


        let rslt = BytesMut::from(&nt_packet[..]);

        let datagram = handler(&rslt, &profile, &secret).unwrap();

        let packet_type_hello_confirm = 42 as u8; //hello_confirm  packet type

        let nt_data: HelloNetworkData = serialization::from_bytes(&datagram.payload).unwrap();
        assert_eq!(
            nt_data.sock_addr.ip(),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 3))
        );
        assert_eq!(nt_data.sock_addr.port(), 41238);
        assert_eq!(nt_data.packet_type, packet_type_hello_confirm);

    }



}
