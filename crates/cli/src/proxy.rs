use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CopyStats {
    pub left_to_right: u64,
    pub right_to_left: u64,
}

pub async fn copy_bidirectional_split<LR, LW, RR, RW>(
    mut left_reader: LR,
    mut left_writer: LW,
    mut right_reader: RR,
    mut right_writer: RW,
) -> io::Result<CopyStats>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
{
    let left_to_right = async {
        let copied = tokio::io::copy(&mut left_reader, &mut right_writer).await?;
        right_writer.shutdown().await?;
        io::Result::Ok(copied)
    };
    let right_to_left = async {
        let copied = tokio::io::copy(&mut right_reader, &mut left_writer).await?;
        left_writer.shutdown().await?;
        io::Result::Ok(copied)
    };
    let (left_to_right, right_to_left) = tokio::try_join!(left_to_right, right_to_left)?;
    Ok(CopyStats {
        left_to_right,
        right_to_left,
    })
}

pub async fn copy_until_cancelled<LR, LW, RR, RW>(
    left_reader: LR,
    left_writer: LW,
    right_reader: RR,
    right_writer: RW,
    cancellation: CancellationToken,
) -> io::Result<CopyStats>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
{
    tokio::select! {
        result = copy_bidirectional_split(left_reader, left_writer, right_reader, right_writer) => result,
        () = cancellation.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "proxy cancelled")),
    }
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod resilience_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn copies_both_directions_and_half_closes() {
        let (left_client, left_proxy) = tokio::io::duplex(128);
        let (right_proxy, right_client) = tokio::io::duplex(128);
        let (mut left_client_reader, mut left_client_writer) = tokio::io::split(left_client);
        let (left_proxy_reader, left_proxy_writer) = tokio::io::split(left_proxy);
        let (right_proxy_reader, right_proxy_writer) = tokio::io::split(right_proxy);
        let (mut right_client_reader, mut right_client_writer) = tokio::io::split(right_client);

        let proxy = copy_bidirectional_split(
            left_proxy_reader,
            left_proxy_writer,
            right_proxy_reader,
            right_proxy_writer,
        );
        let clients = async {
            left_client_writer.write_all(b"request").await?;
            left_client_writer.shutdown().await?;
            let mut request = Vec::new();
            right_client_reader.read_to_end(&mut request).await?;
            assert_eq!(request, b"request");

            right_client_writer.write_all(b"response").await?;
            right_client_writer.shutdown().await?;
            let mut response = Vec::new();
            left_client_reader.read_to_end(&mut response).await?;
            assert_eq!(response, b"response");
            io::Result::Ok(())
        };

        let (stats, ()) = tokio::try_join!(proxy, clients).unwrap();
        assert_eq!(stats.left_to_right, 7);
        assert_eq!(stats.right_to_left, 8);
    }

    #[tokio::test]
    async fn cancellation_stops_an_idle_proxy() {
        let (_left_client, left_proxy) = tokio::io::duplex(8);
        let (right_proxy, _right_client) = tokio::io::duplex(8);
        let (left_reader, left_writer) = tokio::io::split(left_proxy);
        let (right_reader, right_writer) = tokio::io::split(right_proxy);
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = copy_until_cancelled(
            left_reader,
            left_writer,
            right_reader,
            right_writer,
            cancellation,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}
