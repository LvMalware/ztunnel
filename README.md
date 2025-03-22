# ZTunnel

This library provides a simple protocol based on SSH's Binary Packet Protocol (BPP), that can be used to establish a secure end-to-end encrypted tunnel between a client and a server.

Key-exchange is performed using `X25519Kyber768`, that is Ellipitic Curve Diffe-Hellman (ECDH) using curve X25519 ECDH + the post-quantum Key-Encapsulation Mechanism (KEM) called Kyber. This way, the communication remains secure as long as at least one of the two algorithms is unbroken. All data is then transmitted using `AES-256-GCM`. 

Note: This protocol is useful to protect against eavesdropping, but currently it *can't* protect against active man-in-the-middle attacks. Future versions might include a method to validate each peer's public keys during key-exchange, invalidating such attacks.
