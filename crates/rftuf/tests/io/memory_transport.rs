//! `MemoryTransport` serves files held in memory, which can be changed at any
//! time.

use std::assert_matches;

use futures_executor::block_on;
use rftuf::transport::{MemoryTransport, Transport, TransportError};

use crate::support::read;

#[test]
fn serves_the_files_it_holds() {
    let transport = MemoryTransport::new();
    transport.insert_metadata("timestamp.json", b"one".to_vec());
    transport.insert_metadata("timestamp.json", b"two".to_vec());
    transport.insert_target("dir/file", b"target".to_vec());
    assert_eq!(
        read(block_on(
            transport.fetch_metadata("timestamp.json", u64::MAX)
        )),
        b"two"
    );
    assert_eq!(
        read(block_on(transport.fetch_target("dir/file", u64::MAX))),
        b"target"
    );

    // Metadata and targets are separate.
    assert_matches!(
        block_on(transport.fetch_target("timestamp.json", u64::MAX)).map(drop),
        Err(TransportError::NotFound)
    );

    transport.remove_metadata("timestamp.json");
    transport.remove_target("dir/file");
    assert_matches!(
        block_on(transport.fetch_metadata("timestamp.json", u64::MAX)).map(drop),
        Err(TransportError::NotFound)
    );
    assert_matches!(
        block_on(transport.fetch_target("dir/file", u64::MAX)).map(drop),
        Err(TransportError::NotFound)
    );
}
