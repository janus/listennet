use serialization::{from_bytes, extract_payload, hello_reply_datagram};
use bytes::{BufMut, BytesMut};
use std::str;
use edcert::ed25519;
use base64::decode;
use types::{DATAGRAM, PROFILE};

const HELLO: &'static str = "hello";


/**
 * This is where packet from multicast is verified(hash) by ed25519 curve
 */
pub fn handler(packet: &BytesMut, profile: &PROFILE, secret: &[u8; 64]) -> Option<DATAGRAM> {
    match header_type(packet) {
		Some(ref vv) if vv == HELLO => {		
			if let Some(hello_data) = from_bytes(packet) {
				let payload = extract_payload(&hello_data);
				let pub_key = decode(&hello_data.pub_key).unwrap_or(Vec::new());
				let sig = decode(&hello_data.sig).unwrap_or(Vec::new());

                let len  = packet.len() - sig.len();
				if ed25519::verify(payload.as_bytes(), &sig, &pub_key) {
					if let Some(v) = hello_reply_datagram(&hello_data, profile, secret,len as i32){
						return Some(v);
					}
				}
			}
		},
		Some(_) => {},
		None => {}
    }
    None
}


pub fn header_type(packet: &BytesMut) -> Option<String> {
    if let Ok(v) = str::from_utf8(&packet[0..5]) {
        return Some(v.to_string());
    }
    None
}



#[cfg(test)]
mod test {
    use serialization;
    use edcert::ed25519;
    use base64::encode;
    use bytes::{BufMut, BytesMut};
    use types::{PROFILE, ENDPOINT, HELLONETWORKDATA};
    use handle::handler;
    use std::str;


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

    fn header(packet: &BytesMut) -> String {
        if let Ok(v) = str::from_utf8(&packet[0..13]) {
            return v.to_string();
        }
        "".to_string()
    }



    #[test]
    fn test_process_received_packet() {

        let (ip_addr, udp_port, pub_key, secret) = encodeVal("41238", "224.0.0.3");
        let pay_addr = "AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==";
        let profile = build_profile(&ip_addr, &udp_port, &pub_key, &pay_addr);

        let mut rslt = BytesMut::with_capacity(1400);

        let nt_packet = "hello Ea5pbdL9KkvKcpdkpQwiJfb8tq68Xl5T5Erihf7Zx0s=
         AAAAB3NzaC1yc2EAAAABIwAAAQEAklOUpkDHrfHY17SbrmTIpNLTGK9Tjom/BWDSUGPl+nafzlHDTYW7hdI4yZ5ew18JH4JW9jbhUFrviQzM7xlELEVf4h9lFX5QVkbPppSwg0cda3Pbv7kOdJ/MTyBlWXFCR+HAo3FXRitBqxiX1nKhXpHAZsMciLq8V6RjsNAQwdsdMFvSlVK/7XAt3FaoJoAsncM1Q9x5+3V0Ww68/eIFmb1zuUFljQJKprrX88XypNDvjYNby6vw/Pb0rwert/EnmZ+AW4OZPnTPI89ZPmVMLuayrD2cE86Z/il8b+gw3r3+1nKatmIkjn2so1d01QraTlMqVSsbxNrRFi9wrf+M7Q==
		 MjI0LjAuMC40 NDIyMzg= 1512275605 89
		 4qBNrBNA9wdMxfmUZxL9kP+X/1wFzgSeWkoN4TXs7YdkWA0VIWGqRGEe8Czw1M/gwd1xk1P6egp+deQ6STejBg==";

        rslt.put(nt_packet);

        let datagram = handler(&rslt, &profile, &secret).unwrap();
        
        assert_eq!(header(&datagram.payload), "hello_confirm");

        let nt_data: HELLONETWORKDATA = serialization::from_bytes(&datagram.payload).unwrap();
        assert_eq!(serialization::decode_str(&nt_data.ip_address), "224.0.0.3");
        assert_eq!(serialization::decode_str(&nt_data.udp_port), "41238");

    }



}
