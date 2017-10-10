
# Daemon listener



Ping Pong Neighbour Discovery 

The Pong host participate is a member of multicast  neighbor discovery network, it runs on the background and listens for incomming message from the multcast. When it reads  a "ipv4_hello" message header, then it would parse the remaining packet. Verify the hash and decode the rest of the information. It would extract endpoint to send response to.
When such messages come along they will respond by sending their profile back.

1.	At the Pong (daemon).
	- It reads the above , if header is correct, it then splits the received message
	- It would verify the hash sign using public key. If it passes, it would build and send return payload
	- base64 ecode and decode are used
	- Hello_message ::= "ipv4_hello_confirm"
	- Hello_message is not encoded , just plane ascii.
	- It is the playload header.
    
    - Following the header are 
		- public_key ::= encoded public_key
		- payment_address ::= encoded public_key_t
		- ip_address ::= encoded ip_address
		- udp_port ::= encoded udp_port
		- created_time_utc ::= encoded timestamp,
		- seqnum ::= integer

The above payload is hash signed and the hash result appended to the protocol message.

The seqnum will be used to avoid cheating from pongs. And the table would be 
checked for nodes that are not atcive, and such nodes would be removed.

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
daemon_net(
    rx_ip: String,
    rx_port: String,
    pub_key: String,
    pay_addr: String,
    tx_ip: String,
    tx_port: String,
    multicast_ip: String,
    secret: [u8; 64],
);
Obey the types. pub_key and pay_addr are encoded version of public address
rx_ip and rx_port is used for joining multicast. tx_ip and rx_ip should be valid 
udp IP addresses.  multicast_ip is the muticast ip
```