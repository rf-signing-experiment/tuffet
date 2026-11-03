# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

<!-- next-header -->
## [Unreleased] - ReleaseDate

## [0.1.0] - 2026-11-03

### Added

- First release: a client for The Update Framework, following version 1.0.36
  of the specification.
- `Updater`: the complete client workflow, over a `Transport` and a
  `MetadataStore`, with filesystem and in-memory implementations of both.
- `TrustedMetadata` and `TargetSearch`: the verification rules and the
  delegation search, without I/O.
- `metadata`: types for reading, creating and signing TUF metadata.
- Signature schemes: Ed25519, ECDSA (P-256 and P-384), RSASSA-PSS (SHA-256,
  SHA-384 and SHA-512) and ML-DSA (TAP 21).
- Cryptography backends `rustcrypto` (default) and `aws-lc-rs`.

<!-- next-url -->
[Unreleased]: https://github.com/rf-signing-experiment/tuffet/compare/tuffet-v0.1.0...HEAD
[0.1.0]: https://github.com/rf-signing-experiment/tuffet/compare/dd52c7a...tuffet-v0.1.0
