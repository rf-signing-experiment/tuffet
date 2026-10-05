# Test data

- `crypto/`: keys and signatures generated with OpenSSL 3, used to check that
  signatures from another implementation verify (RSA-PSS with SHA-256 and
  maximum and digest-length salts, RSA-PSS with SHA-384 and SHA-512,
  DER-encoded ECDSA, Ed25519, ML-DSA) and that PKCS#8 keys load. The ML-DSA
  signatures are of the [TAP 21] message for `message.txt`; the ML-DSA-44 and
  -87 keys are in OpenSSL's default form (seed and expanded key), the
  ML-DSA-65 key is seed-only, and `ml-dsa-44.expanded.key.pem` is the
  ML-DSA-44 key without its seed. The private keys are test keys only.
- `python-tuf/`: the test repository of the TUF reference implementation,
  copied unmodified from
  <https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data/repository>.
  python-tuf is dual-licensed under the MIT and Apache 2.0 licenses,
  Copyright (c) 2010 New York University.

[TAP 21]: https://github.com/theupdateframework/taps/blob/master/tap21.md
