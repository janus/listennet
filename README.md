
# Daemon listener



Neighbour Discovery 

 Host participate is a member of multicast  neighbor discovery network, it runs on the background and listens for incomming message from the multcast. When it reads  a "Hello" message (Header), verify the hash and process the rest of the information. It would respond with a "Hello Confirm" message which would include its public key, payment address, and endpoint. This is also signed. 
When such messages come along they will respond by sending their profile back.

1.	 
    - Hello header message structure
		- public_key ::= encoded public_key
		- payment_address ::= encoded public_key_t
		- ip_address ::= encoded ip_address
		- udp_port ::= encoded udp_port
		- created_time ::= encoded timestamp,


	 - Hello_Confirm header message structure
		- public_key ::= encoded public_key
		- payment_address ::= encoded public_key_t
		- ip_address ::= encoded ip_address
		- udp_port ::= encoded udp_port
		- created_time ::= encoded timestamp,
	


The above payload is hash signed and  result appended.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
listenet = "0.1.0"
```

And this in your crate root:

```rust
extern crate listenet;
```

To get started:
```
use::listenet::daemonnet::{daemon_net};
use::listenet::Neighbor;
use::dsocket::{udp_socket, create_sockaddr};
use::handle::handler;

let (pub_key, secret) = ed25519::generate_keypair() // From decert crate
let sock_addr = create_sockaddr(&format!("{}:{}","224.0.0.3","41238")).unwrap(); //This is SocketAddr, however you may "use dsocket" module which has create_sockaddr

//All the fields below are &'a str, check file types.rs
let endpoint = EndPoint {
	ip_address,
	udp_port,
};
let proffile = Profile {
	pub_key,
	pay_addr,
	endpoint,
};
//Profile contains the host public key , payment address, and endpoint (its field are encoded.
let tx_udpsock = udp_socket("224.0.0.3","41238");
let rx_udpsock = udp_socket("224.0.0.3","41231");
let mut ludpnet = LudpNet::new(profile, secret, sock_addr);

ludpnet.start_net(tx_udpsock, rx_udpsock, handler);

Obey the types. pub_key and pay_addr are encoded version of public address
rx_ip and rx_port is used for joining multicast. tx_ip and rx_ip should be valid 
udp IP addresses.  multicast_ip is the muticast ip. cast_ip is the ip address the reciever will use to join multicast
```