//! `MemoryTransport` serves files held in memory, which can be changed at any
//! time.

use futures_executor::block_on;
use futures_util::TryStreamExt;
use rftuf::transport::{ByteStream, MemoryTransport, Transport, TransportError};

use crate::support::assert_err;

fn read(stream: ByteStream) -> Vec<u8> {
    block_on(stream.map_ok(|chunk| chunk.to_vec()).try_concat()).unwrap()
}

#[test]
fn serves_the_files_it_holds() {
    let transport = MemoryTransport::new();
    transport.insert_metadata("timestamp.json", b"one".to_vec());
    transport.insert_metadata("timestamp.json", b"two".to_vec());
    transport.insert_target("dir/file", b"target".to_vec());
    assert_eq!(
        read(block_on(transport.fetch_metadata("timestamp.json")).unwrap()),
        b"two"
    );
    assert_eq!(
        read(block_on(transport.fetch_target("dir/file")).unwrap()),
        b"target"
    );

    // Metadata and targets are separate.
    assert_err!(
        block_on(transport.fetch_target("timestamp.json")),
        TransportError::NotFound(_)
    );

    transport.remove_metadata("timestamp.json");
    transport.remove_target("dir/file");
    assert_err!(
        block_on(transport.fetch_metadata("timestamp.json")),
        TransportError::NotFound(name) if name == "timestamp.json"
    );
    assert_err!(
        block_on(transport.fetch_target("dir/file")),
        TransportError::NotFound(name) if name == "dir/file"
    );
}
