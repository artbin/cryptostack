# jsign

Tool to sign files and verify signatures

## Introduction

Jsign tool is heavily inspired by [minisign](https://github.com/jedisct1/minisign) and [asignify](https://github.com/vstakhov/asignify). It uses [blake2b](https://blake2b.net/) as the hash function and the highly secure Ed25519 public-key signature system. The keys are serialized in json.

## Key features

- Modern cryptography primitives (ed25519, curve25519, blake2b)
- Protecting secret keys by passwords using pbkdf2-blake2b routine

## Usage samples

Here are some (descriptive) usage examples of `jsign` utility:

- Generate keypair:

```
$ jsign generate skey pkey
$ jsign generate --no-password skey pkey
```

- Sign files

```
$ jsign sign skey file
```

- Verify signature

```
$ jsign verify pkey file
```

## Cryptographic basis

For digital signatures `jsign` uses `ed25519` algorithm which is blazingly fast and
proven to be secure even without random oracle (based on Schnorr scheme).

To sign a file, `jsign` does the following steps:

1. Opens secret key file (decrypting it if needed)
2. Calculates digest of a file
3. Calculates ed25519 signature
4. Write digest and signature to the output file in json format

To verify signature, `jsign` loads public key, verifies the signature in the same
way, load file digest and verify corresponding file agains that digest.

Hence, `jsign` only sign digests of files and not files themselves, and a signature
contains both digests and its ed25519 signature.

## Keys storage

Secret key for `jsign` can be encrypted using password-based key derivation function,
namely `pbkdf2-blake2b`. This function can be tuned for the number of rounds to increase
amount of work required for an adversary to brute-force the encryption password into
a valid encryption key.

`jsign` uses the json format for keys and signatures,  [doc](https://godoc.org/github.com/ArtemKulyabin/cryptostack).
