use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// A client may half-close a request and still expect its response. Conversely,
/// Herdr closing its one-request socket must end the channel even if the SSH
/// client has not sent EOF (including a terminated event subscription).
pub(super) async fn bridge<C, S>(channel: C, socket: S) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut input, mut output) = tokio::io::split(channel);
    let (mut socket_read, mut socket_write) = tokio::io::split(socket);
    let upload = async {
        tokio::io::copy(&mut input, &mut socket_write).await?;
        socket_write.shutdown().await
    };
    let download = async {
        tokio::io::copy(&mut socket_read, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => { result?; download.await },
        result = &mut download => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn remote_eof_closes_channel_without_waiting_for_client_eof() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut client, channel) = tokio::io::duplex(128);
            let (socket, mut server) = tokio::io::duplex(128);
            let pump = tokio::spawn(bridge(channel, socket));
            server.write_all(b"response\nevent\n").await.unwrap();
            server.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"response\nevent\n");
            pump.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn client_half_close_preserves_large_response_tail() {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut client, channel) = tokio::io::duplex(128);
            let (socket, mut server) = tokio::io::duplex(128);
            let pump = tokio::spawn(bridge(channel, socket));
            let serve = tokio::spawn(async move {
                let mut request = Vec::new();
                server.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"request");
                server.write_all(&vec![7; 65536]).await.unwrap();
            });
            client.write_all(b"request").await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, vec![7; 65536]);
            serve.await.unwrap();
            pump.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}
