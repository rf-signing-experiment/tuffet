# Test data

- `crypto/`: keys and signatures generated with OpenSSL 3, used to check that
  signatures from another implementation verify (RSA-PSS with SHA-256 and
  maximum and digest-length salts, RSA-PSS with SHA-384 and SHA-512,
  DER-encoded ECDSA, Ed25519, ML-DSA) and that PKCS#8 keys load. The ML-DSA
  signatures are of the [TAP 21] message for `message.txt`; the ML-DSA-44 and
  -87 keys are in OpenSSL's default form (seed and expanded key), the
  ML-DSA-65 key is seed-only, and `ml-dsa-44.expanded.key.pem` is the
  ML-DSA-44 key without its seed. The RSA keys of unusual sizes test the
  key size limits: `rsa1024.pub.pem`, `rsa2047.*` (with
  `rsa2047-pss.sig`, an RSA-PSS SHA-256 signature with a digest-length
  salt), `rsa8192.pub.pem` and `rsa8200.pub.pem`, made with
  `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:BITS`. The
  private keys are test keys only.
- `python-tuf/`: the test repository of the TUF reference implementation,
  copied unmodified from
  <https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data/repository>.
  python-tuf is dual-licensed under the MIT and Apache 2.0 licenses,
  Copyright (c) 2010 New York University.

## Regenerating the signatures

The signatures in `crypto/` are of `message.txt`, which has no trailing
newline. After changing it or a key, regenerate them all by running this in
`crypto/` (ML-DSA needs OpenSSL 3.5 or later):

```sh
m=message.txt
openssl pkeyutl -sign -rawin -inkey ed25519.key.pem -in $m -out ed25519.sig
openssl dgst -sha256 -sign p256.key.pem -out p256.sig $m
openssl dgst -sha384 -sign p384.key.pem -out p384.sig $m
# RSA-PSS; MGF1 uses the same hash as the digest (OpenSSL's default).
pss() { openssl dgst -$1 -sign $2.key.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:$3 -out $4 $m; }
pss sha256 rsa     digest rsa-pss-saltdigest.sig
pss sha256 rsa     max    rsa-pss-saltmax.sig
pss sha384 rsa     digest rsa-pss-sha384.sig
pss sha512 rsa     digest rsa-pss-sha512.sig
pss sha256 rsa2047 digest rsa2047-pss.sig
# Pure ML-DSA with an empty context, of the TAP 21 message: the bytes
# "tuf\x01" followed by the SHA-512 digest of the payload.
{ printf 'tuf\x01'; openssl dgst -sha512 -binary $m; } > tap21.bin
for n in 44 65 87; do openssl pkeyutl -sign -rawin -inkey ml-dsa-$n.key.pem -in tap21.bin -out ml-dsa-$n.sig; done
rm tap21.bin
```

[TAP 21]: https://github.com/theupdateframework/taps/blob/master/tap21.md
