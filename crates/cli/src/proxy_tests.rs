use super::*;
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncReadExt, ReadBuf};

struct CountingReader(Arc<AtomicUsize>);

impl AsyncRead for CountingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = buffer.remaining();
        buffer.initialize_unfilled().fill(0x42);
        buffer.advance(count);
        self.0.fetch_add(count, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

struct BlockedWriter(Option<tokio::sync::oneshot::Sender<()>>);

impl AsyncWrite for BlockedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(ready) = self.0.take() {
            let _ = ready.send(());
        }
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn backpressure_bounds_read_ahead_and_cancellation_interrupts_a_blocked_write() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let bytes = Arc::new(AtomicUsize::new(0));
        let (blocked_tx, blocked_rx) = tokio::sync::oneshot::channel();
        let (_held, pending_reader) = tokio::io::duplex(8);
        let cancellation = CancellationToken::new();
        let proxy = copy_until_cancelled(
            CountingReader(bytes.clone()),
            tokio::io::sink(),
            pending_reader,
            BlockedWriter(Some(blocked_tx)),
            cancellation.clone(),
        );
        tokio::pin!(proxy);
        tokio::select! {
            result = &mut proxy => panic!("blocked proxy completed: {result:?}"),
            ready = blocked_rx => ready.unwrap(),
        }
        let read_ahead = bytes.load(Ordering::SeqCst);
        assert!(read_ahead > 0);
        // Tokio copy has an 8 KiB buffer. A blocked peer must not cause
        // unbounded input buffering or repeated reads in a busy loop.
        assert!(read_ahead <= 8192, "read ahead {read_ahead} bytes");
        cancellation.cancel();
        assert_eq!(proxy.await.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert_eq!(bytes.load(Ordering::SeqCst), read_ahead);
    })
    .await
    .expect("cancellation failed to interrupt backpressure");
}

struct FailedIo;

impl AsyncRead for FailedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}

impl AsyncWrite for FailedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::NotConnected.into()))
    }
}

#[tokio::test]
async fn read_write_and_shutdown_errors_in_either_direction_do_not_wait_for_idle_peer() {
    for reverse in [false, true] {
        for stage in ["read", "write", "shutdown"] {
            let (reader, writer, expected): (
                Box<dyn AsyncRead + Unpin>,
                Box<dyn AsyncWrite + Unpin>,
                _,
            ) = match stage {
                "read" => (
                    Box::new(FailedIo),
                    Box::new(tokio::io::sink()),
                    io::ErrorKind::ConnectionReset,
                ),
                "write" => (
                    Box::new(std::io::Cursor::new(b"payload")),
                    Box::new(FailedIo),
                    io::ErrorKind::BrokenPipe,
                ),
                _ => (
                    Box::new(tokio::io::empty()),
                    Box::new(FailedIo),
                    io::ErrorKind::NotConnected,
                ),
            };
            let (_held, pending) = tokio::io::duplex(8);
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                if reverse {
                    copy_bidirectional_split(pending, writer, reader, tokio::io::sink()).await
                } else {
                    copy_bidirectional_split(reader, tokio::io::sink(), pending, writer).await
                }
            })
            .await
            .expect("proxy waited for idle peer after an I/O failure");
            assert_eq!(
                result.unwrap_err().kind(),
                expected,
                "reverse={reverse}, stage={stage}"
            );
        }
    }
}

#[tokio::test]
async fn multi_megabyte_full_duplex_transfer_makes_progress_with_tiny_buffers() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (left_client, left_proxy) = tokio::io::duplex(257);
        let (right_proxy, right_client) = tokio::io::duplex(257);
        let (mut left_read, mut left_write) = tokio::io::split(left_client);
        let (mut right_read, mut right_write) = tokio::io::split(right_client);
        let (lr, lw) = tokio::io::split(left_proxy);
        let (rr, rw) = tokio::io::split(right_proxy);
        let left_payload = (0..=255_u8).collect::<Vec<_>>().repeat(8192);
        let right_payload = (0..=255_u8).rev().collect::<Vec<_>>().repeat(8192);
        let left_send = async {
            left_write.write_all(&left_payload).await.unwrap();
            left_write.shutdown().await.unwrap();
        };
        let right_send = async {
            right_write.write_all(&right_payload).await.unwrap();
            right_write.shutdown().await.unwrap();
        };
        let left_receive = async {
            let mut bytes = Vec::new();
            left_read.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, right_payload);
        };
        let right_receive = async {
            let mut bytes = Vec::new();
            right_read.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, left_payload);
        };
        let (stats, (), (), (), ()) = tokio::join!(
            copy_bidirectional_split(lr, lw, rr, rw),
            left_send,
            right_send,
            left_receive,
            right_receive,
        );
        assert_eq!(
            stats.unwrap(),
            CopyStats {
                left_to_right: left_payload.len() as u64,
                right_to_left: right_payload.len() as u64
            }
        );
    })
    .await
    .expect("full-duplex transfer deadlocked under backpressure");
}
