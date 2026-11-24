//! Authentication utilities for AnyTLS protocol

use crate::padding::PaddingFactory;
use crate::util::{AnyTlsError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Compute SHA256 hash of password
pub fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

/// Multi-user credential table, keyed by `SHA256(password)` like
/// upstream's `userMap` — the username is what `Metadata.in_user`
/// stamps on the authenticated flow.
pub type UserMap = HashMap<[u8; 32], String>;

/// Authenticate a client connection against a multi-user table.
///
/// Same wire contract as [`authenticate_client`] — `SHA256(password)`
/// (32 bytes), `padding0_length` (u16be), `padding0` — but the digest
/// is looked up in `users` and the matching username returned. An
/// unknown digest is an [`AnyTlsError::AuthenticationFailed`] so the
/// caller can distinguish "wrong password → close silently" from
/// session-protocol errors.
pub async fn authenticate_user<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    users: &UserMap,
) -> Result<String> {
    let mut password_hash = [0u8; 32];
    reader.read_exact(&mut password_hash).await?;

    let Some(user) = users.get(&password_hash) else {
        return Err(AnyTlsError::AuthenticationFailed);
    };
    let user = user.clone();

    let mut padding_len_bytes = [0u8; 2];
    reader.read_exact(&mut padding_len_bytes).await?;
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
    // Discard padding in bounded chunks — a declared 64 KiB must not
    // become one up-front allocation, and a short read must fail (not be
    // silently accepted like `take().read_to_end` would).
    let mut remaining = padding_len;
    let mut scratch = [0u8; 4096];
    while remaining > 0 {
        let chunk = remaining.min(scratch.len());
        reader.read_exact(&mut scratch[..chunk]).await?;
        remaining -= chunk;
    }

    Ok(user)
}

/// Authenticate a client connection (server side)
///
/// Reads authentication data from the connection:
/// - SHA256(password) (32 bytes)
/// - padding0_length (2 bytes, big-endian)
/// - padding0 (variable length)
pub async fn authenticate_client<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    expected_password_hash: &[u8; 32],
    _padding_factory: &Arc<PaddingFactory>,
) -> Result<()> {
    // Read SHA256(password)
    let mut password_hash = [0u8; 32];
    reader.read_exact(&mut password_hash).await?;

    // Verify password
    if password_hash != *expected_password_hash {
        return Err(AnyTlsError::AuthenticationFailed);
    }

    // Read padding0_length
    let mut padding_len_bytes = [0u8; 2];
    reader.read_exact(&mut padding_len_bytes).await?;
    let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;

    // Read padding0
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        reader.read_exact(&mut padding).await?;
        // Padding is discarded
    }

    Ok(())
}

/// Send authentication data (client side)
///
/// Writes authentication data to the connection:
/// - SHA256(password) (32 bytes)
/// - padding0_length (2 bytes, big-endian)
/// - padding0 (variable length)
pub async fn send_authentication<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    password_hash: &[u8; 32],
    padding_factory: &Arc<PaddingFactory>,
) -> Result<()> {
    // Get padding0 length from padding scheme
    let padding_sizes = padding_factory.generate_record_payload_sizes(0);
    let padding_len = padding_sizes.first().copied().unwrap_or(0);

    // Ensure padding_len is non-negative
    let padding_len = if padding_len < 0 {
        0
    } else {
        padding_len as u16
    };

    // Coalesce the entire auth record — SHA256(password) (32) + padding0
    // length (2) + padding0 — into a single buffer and write it in one shot.
    //
    // The reference anytls server (anytls-go / sing-anytls) authenticates with
    // a *single* read off the TLS connection (`ReadOnceFrom`), then parses 32
    // + 2 bytes from that buffer. Each `write_all` on a rustls TLS stream
    // emits its own TLS record, so issuing three separate writes produces
    // three TLS records: the server's single read returns only the first
    // 32-byte record and then EOFs reading the 2-byte padding length,
    // yielding `EOF: read padding length: fallback disabled` and tearing the
    // session down before SYNACK. The Go client builds the whole header in
    // one buffer and `WriteTo`s it once (sing-anytls client.go); mirror that.
    let mut buf = Vec::with_capacity(32 + 2 + padding_len as usize);
    buf.extend_from_slice(password_hash);
    buf.extend_from_slice(&padding_len.to_be_bytes());
    if padding_len > 0 {
        buf.resize(buf.len() + padding_len as usize, 0);
    }

    writer.write_all(&buf).await?;
    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::PaddingFactory;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWrite, duplex};

    /// A writer that records every `poll_write` call verbatim.
    ///
    /// Used to assert that [`send_authentication`] emits the entire auth
    /// record in a *single* write — the property the reference anytls server
    /// (anytls-go / sing-anytls) depends on. That server authenticates with
    /// one `ReadOnceFrom(conn)` then parses `SHA256(password) (32) + padding0
    /// length (2) + padding0` from that one buffer. On a rustls TLS stream one
    /// `write_all` is one TLS record, so splitting the auth across multiple
    /// writes makes the server's single read return only the first record and
    /// EOF on the padding length (`EOF: read padding length: fallback
    /// disabled`), tearing the session down before SYNACK.
    ///
    /// A real-TLS single-read test is *not* a reliable guard here: rustls
    /// coalesces multiple already-arrived records into one `poll_read`, so it
    /// would false-pass under the old multi-write code. This recorder pins
    /// the precise cause instead — the whole record is written in a single
    /// `poll_write` — which is what yields one TLS record on the wire.
    #[derive(Default)]
    struct WriteRecorder {
        writes: Vec<Vec<u8>>,
    }

    impl AsyncWrite for WriteRecorder {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            // Always accept the full buffer so `write_all` resolves in a
            // single `poll_write` — matching a real TLS stream that takes the
            // whole (small) record at once.
            self.writes.push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_authentication_success() {
        let password = "test_password";
        let password_hash = hash_password(password);

        let (mut client, mut server) = duplex(1024);
        let padding = PaddingFactory::default();

        // Client sends authentication
        send_authentication(&mut client, &password_hash, &padding)
            .await
            .unwrap();

        // Server authenticates
        authenticate_client(&mut server, &password_hash, &padding)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let password = "test_password";
        let password_hash = hash_password(password);
        let wrong_hash = hash_password("wrong_password");

        let (mut client, mut server) = duplex(1024);
        let padding = PaddingFactory::default();

        // Client sends authentication with correct password
        send_authentication(&mut client, &password_hash, &padding)
            .await
            .unwrap();

        // Server authenticates with wrong password - should fail
        let result = authenticate_client(&mut server, &wrong_hash, &padding).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AnyTlsError::AuthenticationFailed
        ));
    }

    #[tokio::test]
    async fn test_hash_password() {
        let hash1 = hash_password("test");
        let hash2 = hash_password("test");
        let hash3 = hash_password("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    /// Regression for the all-AnyTLS-nodes-handshake-failed bug: the whole
    /// auth record must leave in one `poll_write` so it becomes a single TLS
    /// record on the wire — see [`WriteRecorder`] for why this is the
    /// invariant, and why a real-TLS single-read test can't pin it.
    #[tokio::test]
    async fn send_authentication_writes_whole_record_in_one_call() {
        let password = "regression-password";
        let password_hash = hash_password(password);
        let padding = PaddingFactory::default();

        let mut writer = WriteRecorder::default();
        send_authentication(&mut writer, &password_hash, &padding)
            .await
            .expect("send_authentication must succeed");

        assert_eq!(
            writer.writes.len(),
            1,
            "auth record must be a single write (one TLS record on the wire); got {} writes",
            writer.writes.len()
        );

        // Default scheme pkt 0 is `0=30-30` → 30 bytes of zero padding.
        let record = &writer.writes[0];
        assert_eq!(record.len(), 32 + 2 + 30, "full auth record length");
        assert_eq!(
            &record[..32],
            password_hash.as_slice(),
            "password hash prefix"
        );
        let padding_len = u16::from_be_bytes([record[32], record[33]]);
        assert_eq!(padding_len, 30, "padding0 length field");
        assert!(
            record[34..].iter().all(|&b| b == 0),
            "padding0 must be zero-filled"
        );
    }
}
