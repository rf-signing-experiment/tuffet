# Testing rftuf

rftuf implements the client side of [the TUF specification](../../../tuf-spec.md)
(version 1.0.36). The tests are organized so that a reviewer can check,
section by section, that each requirement of the specification is enforced,
and that each attack it lists is detected.

## Strategy

| Layer | Where | What it shows |
| --- | --- | --- |
| Specification | `tests/workflow`, `tests/metadata` | Every rule of sections 4 (formats) and 5 (client workflow), through the public API. Each module covers one section; each test names the step it checks. |
| Cryptography | `tests/crypto` | Each key type and signature scheme (4.2.2, TAP 21), against keys and signatures made by OpenSSL. |
| I/O | `tests/io` | The built-in transports and stores, and an updater on a repository on disk. |
| Interoperability | `tests/interop.rs` | The reference implementation's (python-tuf's) repository: its metadata verifies and re-encodes, and an updater updates from it. |
| Backends | `cargo test` with each crypto feature | The whole suite passes with `rustcrypto` and with `aws-lc-rs`; `src/crypto/backend_parity.rs` checks that the two agree. |
| Conformance | [`conformance/`](../../conformance/) | The [tuf-conformance] suite, which tests the client against other implementations' behavior. |

Unit tests in `src/` are only for what the public API cannot reach:
`src/paths.rs` and the backend parity check. The HTTP transport has its own
tests in [`rftuf-http/tests`](../../rftuf-http/tests/).

The verification rules are tested on `TrustedMetadata`, which applies them
without I/O, so each test can feed it exactly the metadata it needs. What the
`Updater` adds (file names, download limits, persistence, the target search)
is tested on an `Updater` that updates from a generated repository.

## Running

```sh
cargo test -p rftuf                                        # rustcrypto backend
cargo test -p rftuf --no-default-features -F aws-lc-rs     # aws-lc-rs backend
cargo test -p rftuf --all-features                         # both, plus backend parity
cargo test -p rftuf --test workflow update_root            # one section (5.3)
SNAPSHOTS=overwrite cargo test -p rftuf --test metadata    # accept changed snapshots
```

## Layout

Each test target lists its modules in specification order in its `main.rs`.

- [`workflow/`](workflow/): section 5, the client workflow.
  `update_start_time` (5.1), `trusted_root` (5.2), `update_root` (5.3),
  `update_timestamp` (5.4), `update_snapshot` (5.5), `update_targets`
  (5.6.1 to 5.6.6), `target_search` (5.6.7), `fetch_target` (5.7),
  `consistent_snapshots` (6.2), `update_cycles` (repeated updates and
  recovery from failures), `call_order` (the order `TrustedMetadata`
  enforces) and `pouf` (TAP 11).
- [`metadata/`](metadata/): section 4, metadata formats.
  `canonical_json` (4.1), `envelope` (4.2.1), `keys` (4.2.2), `date_time`
  (4.2.3), `common_fields` (SPEC_VERSION, VERSION and EXPIRES), `root`
  (4.3), `snapshot` (4.4), `targets` (4.5), `path_patterns` (PATHPATTERN
  and "path_hash_prefixes"), `timestamp` (4.6), `unrecognized_fields` (the
  introduction of section 4), `signatures` (THRESHOLD),
  `file_verification` (LENGTH and HASHES) and `serialization` (the encoding
  of each role, as snapshots).
- [`crypto/`](crypto/): `hashing`, `schemes` (what every scheme does),
  `ed25519`, `ecdsa`, `rsa`, `ml_dsa` (TAP 21), `public_keys` and
  `signers`.
- [`io/`](io/): `filesystem_transport`, `memory_transport`, `stores` and
  `repository_on_disk`.
- [`interop.rs`](interop.rs): python-tuf's repository.
- [`support/`](support/): what the targets share (see below).
- [`data/`](data/): fixtures; see its [README](data/README.md).

## Attacks

The attacks of 1.5.2 ("Goals to protect against specific attacks"), and the
tests that show each is detected:

| Attack | Tests |
| --- | --- |
| Arbitrary installation | Signature thresholds at each step: `update_root` (5.3.4), `update_timestamp` (5.4.2), `update_snapshot` (5.5.3), `update_targets` (5.6.3), `metadata::signatures`; cached metadata signed with rotated-out keys (`*_signed_with_a_rotated_out_key_*`). Targets: `fetch_target::rejects_a_target_with_other_content`. |
| Endless data | The download limits: `root_downloads_are_limited_to_root_max_length`, `timestamp_downloads_are_limited_to_timestamp_max_length`, `snapshot_downloads_are_limited_to_*`, `targets_downloads_are_limited_to_*`, `fetch_target::stops_downloading_a_target_at_its_listed_length`, `metadata::file_verification`. |
| Extraneous dependencies | Delegations are only trusted for their paths: `target_search::only_delegations_trusted_for_the_target_path_are_followed`, `a_target_must_be_in_the_trusted_paths_of_every_role_in_the_chain`, `a_terminating_delegation_ends_the_search`. |
| Fast-forward | `update_root::recovers_from_a_fast_forward_attack_on_{timestamp,snapshot,targets}` (5.3.11). |
| Indefinite freeze | Expiry at each step: `rejects_an_expired_final_root` (5.3.10), `rejects_an_expired_timestamp` (5.4.4), `rejects_an_expired_snapshot` and `an_expired_trusted_snapshot_is_not_used` (5.5.6), `rejects_expired_targets` and `rejects_expired_delegated_targets` (5.6.5); the boundary in `update_start_time`; `update_cycles::a_failed_update_ends_the_trust_in_earlier_metadata`. |
| Malicious mirrors | Not applicable: rftuf does not support the mirrors role. |
| Mix-and-match | Hashes and versions from timestamp and snapshot: `snapshot_must_match_the_hashes_listed_in_timestamp` (5.5.2), `snapshot_version_must_match_timestamp` (5.5.4), `targets_must_match_the_hashes_listed_in_snapshot` (5.6.2), `targets_version_must_match_snapshot` (5.6.4), and their delegated counterparts. |
| Rollback | `new_root_version_must_be_exactly_one_more` (5.3.5), `rejects_a_timestamp_rollback` and `timestamp_must_not_roll_back_the_snapshot_version` (5.4.3), `snapshot_must_not_roll_back_targets_metadata` and `snapshot_must_keep_listing_targets_metadata` (5.5.5). |
| Key compromise | Thresholds above 1: `root_rotation_example_of_the_specification` (6.1), `*_must_be_signed_by_a_threshold_of_*_keys`, `metadata::signatures::a_key_counts_once_even_under_several_key_ids`. |
| Wrong software installation | Target hashes and lengths in `fetch_target`. A role that several roles delegate to is only trusted through the delegations whose keys sign it: `update_targets::a_role_must_satisfy_each_delegation_it_is_used_through`, `target_search::a_role_reached_through_another_delegation_is_verified_again`. |

## Conventions

- **Spec references.** A module's doc comment names its section. A test's
  doc comment names the steps it checks, quoting the specification where
  the wording matters, and its name states the rule:
  `snapshot_must_not_roll_back_targets_metadata`.
- **Errors.** `assert_err!(result, Error::Rollback { role, trusted: 2, new: 1 } if role == "timestamp")`
  checks the error variant and its fields, and shows the actual result if it
  does not match.
- **Determinism.** Expiry is checked against a fixed update start time,
  `support::now()`. Keys are Ed25519 keys derived from names
  (`support::keys::key("root")`), and Ed25519 signatures are deterministic,
  so metadata is the same in every run and with either backend.
- **Snapshots.** Tests that check generated output, such as the JSON
  encoding of metadata, compare it with files in `metadata/snapshots/` (or
  inline `str![]` values) using [snapbox]. After an intentional change, run
  the tests with `SNAPSHOTS=overwrite` and review the diff.
- **Known deviations** are tests marked `#[ignore]` with the reason. They
  state what the specification requires, and fail until rftuf complies.
- **Tests must be able to fail.** A test only shows that a rule is enforced
  if breaking the rule makes it fail. When adding or changing a check in
  `src/`, break it on purpose and see a test fail, and run [cargo-mutants]
  (see below).

## Code Coverage

Coverage shows what the tests run,

```sh
cargo llvm-cov -p rftuf --summary-only    # coverage
```
## Test repositories

`support::TestRepo` is a repository built with rftuf's public metadata API.
It publishes to an in-memory transport; `TestRepo::builder()` configures it,
and its methods change and publish its metadata the way a repository would
(6.3: targets, then snapshot, then timestamp).

```rust
let mut repo = TestRepo::builder()
    .consistent_snapshots()
    .keys(RoleType::Root, 3, 2) // three root keys, two of which must sign
    .meta_hashes()              // timestamp and snapshot list hashes
    .build();
repo.delegate("targets", Delegation::to("a").paths(&["a/*"]).terminating());
repo.add_target("a", "a/file", b"content");
repo.commit(); // a.json and targets.json, then snapshot, then timestamp

repo.rotate_key(RoleType::Timestamp); // in the next root version
repo.publish_root();
repo.publish_timestamp(); // signed with the new key

let mut client = repo.client(); // an Updater shipped with 1.root.json
client.refresh().unwrap();
assert_eq!(client.find("a/file").as_deref(), Some("a"));
assert_eq!(
    repo.requests()[..3],
    ["2.root.json", "3.root.json", "timestamp.json"]
);
```

The payloads (`repo.root`, `repo.timestamp`, `repo.snapshot`,
`repo.targets[role]`) are public, to be changed before publishing them, and
`repo.sign` and `TestRepo::sign_with` sign arbitrary payloads, for forged or
replayed metadata. `repo.trusted()` and `repo.trusted_with_timestamp()`
(`_snapshot`, `_targets`) give a `TrustedMetadata` at the corresponding
point of the workflow. `repo.transport.fail(name)` simulates a network
failure, and `client.restart()` a client restarted on the same local
storage.

## Differences from the specification

There are no known deviations: a test that shows one would be marked
`#[ignore]` with the reason, as described under Conventions.

Deliberate differences, described in the crate documentation, are tested
as rftuf's behavior:

- Key IDs are not recomputed (4.3); keys are compared by key material when
  counting signatures: `metadata::keys::key_ids_are_not_recomputed`,
  `a_key_id_only_names_a_key_in_the_metadata_that_lists_it`.
- When the new timestamp has the trusted version (5.4.3.1), the update goes
  on with the trusted metadata, as in python-tuf:
  `update_timestamp::a_timestamp_with_the_trusted_version_is_discarded_without_error`.
- Metadata that cannot be downloaded or verified during a target search is
  reported as an error rather than as a missing target (5.6.7):
  `target_search::reports_delegated_metadata_that_cannot_be_downloaded_or_validated`.
- The mirrors role and multiple repositories (TAP 4) are not supported.

[snapbox]: https://docs.rs/snapbox
[tuf-conformance]: https://github.com/theupdateframework/tuf-conformance
