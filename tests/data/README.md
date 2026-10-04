# Test data

- `crypto/`: keys and signatures generated with OpenSSL 3, used to check that
  signatures from another implementation verify (RSA-PSS with maximum and
  digest-length salts, DER-encoded ECDSA, Ed25519) and that PKCS#8 keys load.
  The private keys are test keys only.
- `python-tuf/`: the test repository of the TUF reference implementation,
  copied unmodified from
  <https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data/repository>.
  python-tuf is dual-licensed under the MIT and Apache 2.0 licenses,
  Copyright (c) 2010 New York University.
