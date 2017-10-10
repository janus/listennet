
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
