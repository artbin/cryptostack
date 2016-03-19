# Protocol overview

The communication protocol proceeds, by first handshaking the connection and setting up the cryptographic channel. Then it exchanges messages on the channel. The handshake initializes a second ephermeral key-set in order to achieve forward secrecy.

A keypair is defined as `(K, Ks)` where `K` is the public part and `Ks` is the secret part. Everywhere, a key ending in the "s" character designate a secret key. We define the notation `Box[X](Cs -> S)` to mean a secure *box* primitive which *encrypts* and *authenticates* the message `X`from a client to a server. The client uses `Cs` to sign the message and uses `S` to encrypt the message destined for the server. For secret-key cryptography we define `SecretBox[X](Ks)` as a secret box encrypted (and authenticated) by the (secret) key `Ks`.

Implementation uses the `crypto_box` primitive of NaCl/libsodium to implement `Box[…](K1s -> K2)` and uses `crypto_secretbox` to implement `SecretBox[…](KS)`.

Throughout the description, we assume a keypair `(C, Cs)` for the client and `(S, Ss)` for the server. We also use ephermeral keys for the client, `(EC, ECs)` and for the server, `(ES, ESs)`. The protocol also uses *nonces* in quite a few places and their generation are described below. First the general communication. Details follow.

It assumed the client already have access to the public key of the server, `S` and that the server already has access to the clients public key `C`.

Stream and packet transport:

| Client  | Server     |
|---------|------------|
| 1. Generate `(EC, ECs)` | |
| 2. Hello: send `(EC, Box[Ctag](ECs -> S))` | |
| | 3. Generate `(ES, ESs)` |
| | 4. Cookie ack: send `Box[ES, Ctag, Stag](Ss -> EC)` |
| 5. Vouch: send `Box[C,V](ECs -> ES)` | |
| *bi-directional flow from here on out* | |
| 6. Msg: send `Box[…](ECs -> ES)` | |
| | 7. Msg: send `Box[…](ESs -> EC)` |

Packet transport for udp based protocols like dns and dht:

| Client  | Server     |
|---------|------------|
| 1. Generate `(EC, ECs)` | |
| 2. Msg: send `(EC, Box[…](ECs -> S))` | |
| | 3. Msg: send `Box[…](Ss -> EC)` |
| *bi-directional flow from here on out* | |
| 4. Msg: send `Box[…](ECs -> S)` | |
| | 5. Msg: send `Box[…](Ss -> EC)` |

1. The client generates a new keypair. This keypair is ephemeral for the lifetime of the connection. Once the connection dies, the secret key of this connection is thrown away and since it never leaves the client, it means that nobody is able to understand messages on the connection from then on. This construction provides forward secrecy for the client.

2. The client advertises the ephemeral public key and boxes a Ctag random.
3. The server generates a keypair. This is also ephemeral, but on the server side. It provides forward secrecy for the server-end.
4. The server generates a Stag random.
5. The client reflects the Stag and *vouches* for its key. Here `V = Box[EC, Stag](Cs -> S)`.
6. A message can be sent from the client to the server. It has to be boxed properly.
7. A message can be sent from the server to the client.

From step 6 and onwards, the message flow is bidirectional. Until connection termination, which is simply just terminating the transport connection like one would normally do.
