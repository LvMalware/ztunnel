# ZTunnel

This library provides a simple protocol based on SSH's Binary Packet Protocol (BPP), that can be used to establish a secure end-to-end encrypted tunnel between a client and a server.

Key-exchange is performed using `X25519Kyber768`, that is Ellipitic Curve Diffe-Hellman (ECDH) using curve X25519 + the post-quantum Key-Encapsulation Mechanism (KEM) called Kyber. This way, the communication remains secure as long as at least one of the two algorithms is unbroken. All data is then transmitted using `AES-256-GCM`. 

This protocol is useful to protect against eavesdropping and in the latest versions, it also includes a method to validate each peer's X25519 public keys during key-exchange, which can prevent Man-In-The-Middle (MITM) attacks.

> Note: Although this protocol offers quantum resistance against eavesdropping, the mechanism used to protect against MITM depends only on validating the X25519 public keys, which is not quantum resistant by itself. If an attacker manages to somehow compromise the security of the ECC curve in use, this protocol will not be able to protect the communication against active MITM.
