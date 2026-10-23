//! One authenticated, fixed loopback port per QUIC connection. Each subsequent
//! bidirectional stream carries an open marker, a status byte, then raw TCP bytes.
use anyhow::{Result, bail, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{CapabilitySecret, ensure_frame_end};

pub const TCP_FORWARD_ALPN: &[u8] = b"attached-tcp/1";

/// The setup stream is finite, so extra fields (including destination addresses)
/// are rejected rather than silently accepted. ALPN versions the wire format.
pub async fn write_tcp_forward_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    capability: &CapabilitySecret,
    remote_port: u16,
) -> Result<()> {
    ensure!(remote_port != 0, "remote TCP port must be nonzero");
    writer.write_all(&capability.to_bytes()).await?;
    writer.write_u16(remote_port).await?;
    writer.shutdown().await?;
    Ok(())
}

pub async fn read_tcp_forward_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: &CapabilitySecret,
) -> Result<u16> {
    let mut supplied = [0; 32];
    reader.read_exact(&mut supplied).await?;
    ensure!(
        expected == &CapabilitySecret::from_bytes(supplied),
        "TCP forwarding authentication denied"
    );
    let port = reader.read_u16().await?;
    ensure!(port != 0, "remote TCP port must be nonzero");
    ensure_frame_end(reader, "TCP forwarding request").await?;
    Ok(port)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpForwardStatus {
    Ready,
    ConnectionFailed,
}

/// Does not end the stream: a successful data stream continues with TCP bytes.
pub async fn write_tcp_forward_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: TcpForwardStatus,
) -> Result<()> {
    writer
        .write_u8(match status {
            TcpForwardStatus::Ready => 0,
            TcpForwardStatus::ConnectionFailed => 1,
        })
        .await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_tcp_forward_status<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<TcpForwardStatus> {
    match reader.read_u8().await? {
        0 => Ok(TcpForwardStatus::Ready),
        1 => Ok(TcpForwardStatus::ConnectionFailed),
        status => bail!("unknown TCP forwarding status {status}"),
    }
}

/// QUIC streams are lazy. Sending a marker makes a new stream visible even for
/// server-first protocols whose client has no application bytes to send yet.
pub async fn write_tcp_forward_open<W: AsyncWrite + Unpin>(writer: &mut W) -> Result<()> {
    writer.write_u8(0).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_tcp_forward_open<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    ensure!(
        reader.read_u8().await? == 0,
        "invalid TCP stream open marker"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrip_and_strict_framing() {
        let capability = CapabilitySecret::from_bytes([7; 32]);
        let mut bytes = Vec::new();
        write_tcp_forward_request(&mut bytes, &capability, 4096)
            .await
            .unwrap();
        assert_eq!(bytes.len(), 34);
        assert_eq!(
            read_tcp_forward_request(&mut bytes.as_slice(), &capability)
                .await
                .unwrap(),
            4096
        );
        for length in 0..bytes.len() {
            assert!(
                read_tcp_forward_request(&mut &bytes[..length], &capability)
                    .await
                    .is_err()
            );
        }
        let wrong = CapabilitySecret::from_bytes([8; 32]);
        assert!(
            read_tcp_forward_request(&mut bytes.as_slice(), &wrong)
                .await
                .is_err()
        );
        bytes.push(0);
        assert!(
            read_tcp_forward_request(&mut bytes.as_slice(), &capability)
                .await
                .is_err()
        );
        bytes.truncate(32);
        bytes.extend_from_slice(&[0, 0]);
        assert!(
            read_tcp_forward_request(&mut bytes.as_slice(), &capability)
                .await
                .is_err()
        );
        assert!(
            write_tcp_forward_request(&mut Vec::new(), &capability, 0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn status_and_open_leave_application_bytes_untouched() {
        for status in [TcpForwardStatus::Ready, TcpForwardStatus::ConnectionFailed] {
            let mut bytes = Vec::new();
            write_tcp_forward_status(&mut bytes, status).await.unwrap();
            bytes.extend_from_slice(b"\0\xffpayload");
            let mut input = bytes.as_slice();
            assert_eq!(read_tcp_forward_status(&mut input).await.unwrap(), status);
            assert_eq!(input, b"\0\xffpayload");
        }
        assert!(read_tcp_forward_status(&mut &[2][..]).await.is_err());
        assert!(read_tcp_forward_status(&mut &[][..]).await.is_err());
        let mut bytes = Vec::new();
        write_tcp_forward_open(&mut bytes).await.unwrap();
        read_tcp_forward_open(&mut bytes.as_slice()).await.unwrap();
        assert!(read_tcp_forward_open(&mut &[1][..]).await.is_err());
        assert!(read_tcp_forward_open(&mut &[][..]).await.is_err());
    }
}
