ppe - peer to peer encryption protocol based on Curve25519
=====

Inspired by [curve_tun](https://github.com/jlouis/curve_tun).

WARNING: This is alpha-code. Do not use it in a project.

This document describes the ppe protocol. It provides cryptographic tunnels over stream transport like TCP and packet transport like UDP in order to build secure communication between endpoints which provide *confidentiality* and *integrity* while also providing a certain amount of *availability*.

The protocol also provides *active forward secrecy* against attackers. I.e., an attacker who is a man-in-the-middle and has the ability to act and change data. Even in that case, the protocol provides forward secrecy. Naturally, this also means the protocol is safe against a *passive* adversary.

Build
-----

```
$ go get github.com/ArtemKulyabin/cryptostack/ppe
```

Security
-------------

A cryptographic system is no more safe than its weakest link.

* PROTOCOL.md — describes the protocol design, which owes much, if not everything, to Dan J. Bernstein.

### Specific attack vectors:

The specific security considerations and mitigations goes here in the future. System description is not entirely done, and there are parts which have been fully implemented or verified yet.

* No way to disable or downgrade encryption: The protocol doesn not allow for any kind of protocol downgrade, either to an earlier variant of the protocol, nor to an earlier or less safe suite of ciphers. The ciphers used are selected by Schwabe, Lange and Bernstein (between 2007–2011) and they are used as-is.
