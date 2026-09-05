use super::*;
use std::future::Future;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn request(stream: &mut TcpStream) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
        assert!(headers.len() <= 8192);
    }
}

async fn with_response<T, F, Fut>(wire: Vec<u8>, operation: F) -> T
where
    F: FnOnce(SyncHttpClient, AccountCredentials) -> Fut,
    Fut: Future<Output = T>,
{
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let root = crate::test_support::canonical_tempdir();
        super::super::state::test_support::create_account(
            root.path(),
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .unwrap();
        let account =
            super::super::state::load_account(root.path(), ApiKeyScope::Download).unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            // Early rejection may close the socket while the fixture is writing.
            let _ = stream.write_all(&wire).await;
            let _ = stream.shutdown().await;
        };
        let (result, ()) = tokio::join!(operation(SyncHttpClient::new().unwrap(), account), server);
        result
    })
    .await
    .expect("HTTP response fixture timed out")
}

fn wire(headers: &str, body: &[u8]) -> Vec<u8> {
    let mut wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}\r\n"
    )
    .into_bytes();
    wire.extend_from_slice(body);
    wire
}

#[tokio::test]
async fn record_etags_reject_noncanonical_missing_and_overflow_revisions() {
    let body = serde_json::to_vec(&Envelope::new([0; 24], vec![0; 32]).unwrap()).unwrap();
    for (etag, valid) in [
        (None, false),
        (Some("\"1\""), true),
        (Some("\"9223372036854775807\""), true),
        (Some("\"0\""), false),
        (Some("\"01\""), false),
        (Some("W/\"1\""), false),
        (Some("1"), false),
        (Some("\"\""), false),
        (Some("\"+1\""), false),
        (Some("\"9223372036854775808\""), false),
        (Some("\"18446744073709551616\""), false),
    ] {
        let headers = format!(
            "Content-Length: {}\r\n{}",
            body.len(),
            etag.map(|value| format!("ETag: {value}\r\n"))
                .unwrap_or_default()
        );
        let result = with_response(wire(&headers, &body), |client, account| async move {
            client
                .get_record(&account, RecordId::from_bytes([1; 16]))
                .await
        })
        .await;
        assert_eq!(result.is_ok(), valid, "ETag {etag:?}");
        if valid {
            assert_eq!(
                result.unwrap().unwrap().revision,
                etag.unwrap().trim_matches('"').parse::<u64>().unwrap()
            );
        } else {
            assert!(result.err().unwrap().to_string().contains("ETag"));
        }
    }
}

#[tokio::test]
async fn truncated_fixed_length_and_chunked_bodies_are_transport_errors_not_empty_catalogs() {
    for response in [
        wire("Content-Length: 100\r\n", b"{\"records\":"),
        wire("Transfer-Encoding: chunked\r\n", b"20\r\n{\"records\":"),
    ] {
        let error = with_response(response, |client, account| async move {
            client.list_records(&account).await.unwrap_err()
        })
        .await;
        assert!(
            error
                .to_string()
                .contains("could not read synchronization response"),
            "{error:#}"
        );
    }
}

#[tokio::test]
async fn body_limits_apply_to_both_declared_length_and_streamed_chunks() {
    let body = vec![b'x'; MAX_API_BODY_BYTES + 1];
    let mut chunked = format!("{:x}\r\n", body.len()).into_bytes();
    chunked.extend_from_slice(&body);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    for response in [
        wire(&format!("Content-Length: {}\r\n", body.len()), b""),
        wire("Transfer-Encoding: chunked\r\n", &chunked),
    ] {
        let error = with_response(response, |client, account| async move {
            client.list_records(&account).await.unwrap_err()
        })
        .await;
        assert!(error.to_string().contains("exceeds"), "{error:#}");
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_service_error_bodies_are_not_disclosed() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secret = "DO-NOT-PRINT-SERVER-BODY";
    for status in ["302 Found", "503 Unavailable"] {
        let response = format!(
            "HTTP/1.1 {status}\r\nLocation: http://{}/stolen\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{secret}",
            target.local_addr().unwrap(),
            secret.len()
        );
        let error = with_response(response.into_bytes(), |client, account| async move {
            client.list_records(&account).await.unwrap_err()
        })
        .await;
        let message = format!("{error:#}");
        assert!(message.contains(&status[..3]), "{message}");
        assert!(!message.contains(secret), "{message}");
    }
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err(),
        "redirect received a credential-bearing request"
    );
}

async fn stalled_request_times_out_and_client_recovers(partial_body: bool) {
    timeout(REQUEST_TIMEOUT + Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let root = crate::test_support::canonical_tempdir();
        super::super::state::test_support::create_account(
            root.path(),
            &format!("http://{}", listener.local_addr().unwrap()),
        )
        .unwrap();
        let account =
            super::super::state::load_account(root.path(), ApiKeyScope::Download).unwrap();
        let client = SyncHttpClient::new().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            if partial_body {
                stream
                    .write_all(&wire("Content-Length: 100\r\n", b"{"))
                    .await
                    .unwrap();
            }
            // No sleep: wait until the client's production deadline closes this request.
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            let body = serde_json::to_vec(&LiveRecordIndex::new(vec![]).unwrap()).unwrap();
            stream
                .write_all(&wire(&format!("Content-Length: {}\r\n", body.len()), &body))
                .await
                .unwrap();
        };
        let requests = async {
            let error = client.list_records(&account).await.unwrap_err();
            assert!(
                error.chain().any(|source| source
                    .downcast_ref::<reqwest::Error>()
                    .is_some_and(reqwest::Error::is_timeout)),
                "{error:#}"
            );
            let recovered = client.list_records(&account).await.unwrap();
            assert!(recovered.records.is_empty());
        };
        tokio::join!(server, requests);
    })
    .await
    .expect("stalled HTTP request exceeded production timeout plus grace");
}

#[tokio::test]
async fn stalled_headers_have_a_deadline_and_do_not_poison_the_client() {
    stalled_request_times_out_and_client_recovers(false).await;
}

#[tokio::test]
async fn stalled_body_has_a_deadline_and_does_not_poison_the_client() {
    stalled_request_times_out_and_client_recovers(true).await;
}
