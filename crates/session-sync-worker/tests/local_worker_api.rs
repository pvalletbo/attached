#![forbid(unsafe_code)]

use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Read as _, Seek as _, SeekFrom},
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail, ensure};
use attached_session_sync_protocol::{
    account::{AccountId, ApiToken, RecordId},
    api::{
        CACHE_CONTROL_VALUE, CONTENT_TYPE_JSON, CreateAccountResponse, Envelope, HEADER_ETAG,
        HEADER_RETRY_AFTER, LiveRecordIndex, LiveRecordIndexEntry, STATUS_CREATED,
        STATUS_METHOD_NOT_ALLOWED, STATUS_NO_CONTENT, STATUS_NOT_FOUND, STATUS_OK,
        STATUS_PAYLOAD_TOO_LARGE, STATUS_TOO_MANY_REQUESTS, STATUS_UNAUTHORIZED,
        parse_live_record_index,
    },
    limits::{MAX_API_BODY_BYTES, MAX_LIVE_RECORDS},
};
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use rustix::process::{Pid, Signal, kill_process_group};
use tempfile::{Builder, TempDir};
use tokio::{
    process::{Child, Command},
    sync::Barrier,
    time::{self, Instant},
};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const INTEGRATION_TIMEOUT: Duration = Duration::from_secs(240);
const TERM_GRACE: Duration = Duration::from_secs(5);
const KILL_GRACE: Duration = Duration::from_secs(5);
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RELOAD_SETTLE_DELAY: Duration = Duration::from_secs(1);
const DIAGNOSTIC_SETTLE_DELAY: Duration = Duration::from_millis(250);
const DIAGNOSTIC_LIMIT: u64 = 32 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 128 * 1024;

struct ApiResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct TestAccount {
    id: AccountId,
    publish_token: ApiToken,
    download_token: ApiToken,
}

struct LocalWorker {
    client: Client,
    port: u16,
    worker_dir: PathBuf,
    state_dir: PathBuf,
    output_path: PathBuf,
    temporary_root: PathBuf,
    child: Option<Child>,
    process_group: Option<Pid>,
}

impl LocalWorker {
    fn new(
        client: Client,
        temporary: &TempDir,
        state_dir: &Path,
        output_name: &str,
    ) -> Result<Self> {
        Ok(Self {
            client,
            port: available_port()?,
            worker_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            state_dir: state_dir.to_owned(),
            output_path: temporary.path().join(output_name),
            temporary_root: temporary.path().to_owned(),
            child: None,
            process_group: None,
        })
    }

    async fn start(&mut self) -> Result<()> {
        ensure!(
            self.child.is_none(),
            "local Worker was started more than once without stopping"
        );

        let output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&self.output_path)
            .map_err(|_| anyhow!("failed to open local Worker diagnostics"))?;
        let stderr = output
            .try_clone()
            .map_err(|_| anyhow!("failed to prepare local Worker diagnostics"))?;
        let mut command = Command::new("corepack");
        command
            .args([
                "pnpm",
                "exec",
                "wrangler",
                "dev",
                "--local",
                "--ip",
                "127.0.0.1",
                "--port",
            ])
            .arg(self.port.to_string())
            .args(["--persist-to"])
            .arg(&self.state_dir)
            .current_dir(&self.worker_dir)
            .env("WRANGLER_SEND_METRICS", "false")
            .stdin(Stdio::null())
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .process_group(0);
        let child = command
            .spawn()
            .map_err(|_| anyhow!("failed to start local Worker"))?;
        let raw_pid = child
            .id()
            .ok_or_else(|| anyhow!("local Worker did not report a process ID"))?;
        let raw_pid = i32::try_from(raw_pid)
            .map_err(|_| anyhow!("local Worker process ID was outside the supported range"))?;
        let process_group =
            Pid::from_raw(raw_pid).ok_or_else(|| anyhow!("local Worker process ID was invalid"))?;
        self.child = Some(child);
        self.process_group = Some(process_group);

        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if self
                .child
                .as_mut()
                .expect("local Worker child is present after spawning")
                .try_wait()
                .map_err(|_| anyhow!("failed to poll local Worker during startup"))?
                .is_some()
            {
                bail!("local Worker exited during startup");
            }
            if let Ok(response) = self
                .request(Method::GET, "/healthz", HeaderMap::new(), None)
                .await
                && response.status == StatusCode::NO_CONTENT
            {
                // Wrangler may schedule one initial custom-build reload after first
                // opening the port. Do not begin mutations mid-reload.
                time::sleep(RELOAD_SETTLE_DELAY).await;
                if let Ok(response) = self
                    .request(Method::GET, "/healthz", HeaderMap::new(), None)
                    .await
                    && response.status == StatusCode::NO_CONTENT
                {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("local Worker did not become ready before the deadline");
            }
            time::sleep(STARTUP_POLL_INTERVAL).await;
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<ApiResponse> {
        let mut request = self
            .client
            .request(method, format!("http://127.0.0.1:{}{path}", self.port))
            .headers(headers);
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow!("local Worker request failed"))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY_BYTES as u64)
        {
            bail!("Worker response exceeded the integration-test bound");
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("failed to read local Worker response"))?
        {
            let length = body
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow!("Worker response exceeded the integration-test bound"))?;
            if length > MAX_RESPONSE_BODY_BYTES {
                bail!("Worker response exceeded the integration-test bound");
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ApiResponse {
            status,
            headers,
            body,
        })
    }

    async fn stop(&mut self) -> Result<()> {
        let Some(process_group) = self.process_group else {
            return self.reap_child().await;
        };

        signal_process_group(process_group, Signal::TERM)?;
        if self.wait_for_child_exit(TERM_GRACE).await? {
            // The group leader can exit before a TERM-resistant descendant.
            // Kill any such child before the temporary persistence directory is
            // reused by the restart check below.
            signal_process_group(process_group, Signal::KILL)?;
        } else {
            signal_process_group(process_group, Signal::KILL)?;
            if !self.wait_for_child_exit(KILL_GRACE).await? {
                bail!("local Worker did not exit after SIGKILL");
            }
        }
        self.process_group = None;
        Ok(())
    }

    async fn wait_for_child_exit(&mut self, grace: Duration) -> Result<bool> {
        let Some(child) = &mut self.child else {
            return Ok(true);
        };
        match time::timeout(grace, child.wait()).await {
            Ok(Ok(_)) => {
                self.child = None;
                Ok(true)
            }
            Ok(Err(_)) => bail!("failed to reap local Worker"),
            Err(_) => Ok(false),
        }
    }

    async fn reap_child(&mut self) -> Result<()> {
        if self.wait_for_child_exit(KILL_GRACE).await? {
            Ok(())
        } else {
            bail!("local Worker did not exit before the shutdown deadline")
        }
    }

    async fn diagnostics(&mut self) -> String {
        if self
            .child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
        {
            time::sleep(DIAGNOSTIC_SETTLE_DELAY).await;
        }
        let Ok(mut output) = File::open(&self.output_path) else {
            return String::new();
        };
        let Ok(size) = output.seek(SeekFrom::End(0)) else {
            return String::new();
        };
        if output
            .seek(SeekFrom::Start(size.saturating_sub(DIAGNOSTIC_LIMIT)))
            .is_err()
        {
            return String::new();
        }
        let mut bytes = Vec::new();
        if output.read_to_end(&mut bytes).is_err() {
            return String::new();
        }
        self.sanitize_diagnostics(&String::from_utf8_lossy(&bytes))
    }

    fn sanitize_diagnostics(&self, diagnostics: &str) -> String {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("Worker manifest has a workspace root")
            .display()
            .to_string();
        let mut sanitized = diagnostics.replace(&repository_root, "<repository>");
        for (path, replacement) in [
            (&self.temporary_root, "<temporary>"),
            (&self.state_dir, "<temporary-state>"),
        ] {
            sanitized = sanitized.replace(&path.display().to_string(), replacement);
        }
        if let Some(home) = std::env::var_os("HOME") {
            sanitized = sanitized.replace(&PathBuf::from(home).display().to_string(), "<home>");
        }
        sanitized
            .lines()
            .filter(|line| {
                let normalized = line.to_ascii_lowercase();
                !normalized.contains(".npmrc")
                    && !normalized.contains("authorization")
                    && !normalized.contains("bearer ")
                    && !normalized.contains("publish_api_token")
                    && !normalized.contains("download_api_token")
                    && !normalized.contains("ciphertext")
                    && !normalized.contains("\"nonce\"")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for LocalWorker {
    fn drop(&mut self) {
        if let Some(process_group) = self.process_group {
            let _ = kill_process_group(process_group, Signal::KILL);
        }
    }
}

fn available_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| anyhow!("failed to reserve a loopback port for the local Worker"))?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| anyhow!("failed to inspect the local Worker loopback port"))
}

fn signal_process_group(process_group: Pid, signal: Signal) -> Result<()> {
    match kill_process_group(process_group, signal) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => bail!("failed to signal local Worker process group"),
    }
}

fn client() -> Result<Client> {
    Client::builder()
        .http1_only()
        .no_proxy()
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| anyhow!("failed to create the local Worker HTTP client"))
}

fn bearer(token: &ApiToken) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("Bearer {}", token.encode()))
        .expect("a generated API token is a valid HTTP header value");
    headers.insert(AUTHORIZATION, value);
    headers
}

fn publishing_headers(token: &ApiToken) -> HeaderMap {
    bearer(token)
}

fn header<'a>(response: &'a ApiResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

fn expect_status(response: &ApiResponse, expected: u16, case: &str) -> Result<()> {
    ensure!(
        response.status.as_u16() == expected,
        "{case}: expected HTTP {expected}, received HTTP {}",
        response.status.as_u16()
    );
    ensure!(
        header(response, "cache-control") == Some(CACHE_CONTROL_VALUE),
        "{case}: response was not marked no-store"
    );
    Ok(())
}

fn expect_header(response: &ApiResponse, name: &str, expected: &str, case: &str) -> Result<()> {
    ensure!(
        header(response, name) == Some(expected),
        "{case}: unexpected {name} header"
    );
    Ok(())
}

fn envelope(nonce_byte: u8, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let envelope = Envelope::new([nonce_byte; 24], ciphertext.to_vec())
        .expect("fixed opaque test fixture is within the envelope limit");
    serde_json::to_vec(&envelope)
        .map_err(|_| anyhow!("failed to encode opaque local Worker test fixture"))
}

async fn create_account(worker: &LocalWorker) -> Result<TestAccount> {
    let response = worker
        .request(Method::POST, "/v1/accounts", HeaderMap::new(), Some(b""))
        .await?;
    expect_status(&response, STATUS_CREATED, "account creation")?;
    expect_header(
        &response,
        "content-type",
        CONTENT_TYPE_JSON,
        "account creation",
    )?;
    let response = CreateAccountResponse::parse_json(&response.body)
        .map_err(|_| anyhow!("account creation: invalid response body"))?;
    let (id, publish_token, download_token) = response.into_parts();
    ensure!(
        id.is_uuid_v7(),
        "account creation: account ID is not canonical UUIDv7"
    );
    ensure!(
        publish_token.service_hash() != download_token.service_hash(),
        "account creation: scoped API tokens are not distinct"
    );
    Ok(TestAccount {
        id,
        publish_token,
        download_token,
    })
}

async fn exercise_api(worker: &LocalWorker) -> Result<(TestAccount, RecordId)> {
    let response = worker
        .request(Method::GET, "/healthz", HeaderMap::new(), None)
        .await?;
    expect_status(&response, STATUS_NO_CONTENT, "health")?;

    let response = worker
        .request(Method::POST, "/healthz", HeaderMap::new(), None)
        .await?;
    expect_status(
        &response,
        STATUS_METHOD_NOT_ALLOWED,
        "health method rejection",
    )?;
    expect_header(&response, "allow", "GET", "health method rejection")?;

    let response = worker
        .request(Method::GET, "/v1/accounts", HeaderMap::new(), None)
        .await?;
    expect_status(
        &response,
        STATUS_METHOD_NOT_ALLOWED,
        "account method rejection",
    )?;
    expect_header(&response, "allow", "POST", "account method rejection")?;

    let account = create_account(worker).await?;
    let mut unknown_id = *account.id.as_bytes();
    unknown_id[15] ^= 0xff;
    let unknown_id = AccountId::from_bytes(unknown_id);
    let response = worker
        .request(
            Method::GET,
            &format!("/v1/accounts/{unknown_id}/records"),
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_UNAUTHORIZED, "unknown account")?;

    let records_path = format!("/v1/accounts/{}/records", account.id);
    let record_id = RecordId::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let record_path = format!("{records_path}/{record_id}");

    for path in [
        format!("{records_path}/"),
        format!("{record_path}/extra"),
        "/v1/accounts//records".to_owned(),
        "/unknown".to_owned(),
        "/".to_owned(),
    ] {
        let response = worker
            .request(Method::GET, &path, bearer(&account.download_token), None)
            .await?;
        expect_status(&response, STATUS_NOT_FOUND, "unknown route rejection")?;
    }

    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "empty index")?;
    let empty_index = parse_live_record_index(&response.body)
        .map_err(|_| anyhow!("empty index: invalid response body"))?;
    ensure!(
        empty_index == LiveRecordIndex::new(Vec::new()).expect("empty index is valid"),
        "empty index: unexpected body"
    );

    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&account.publish_token),
            None,
        )
        .await?;
    expect_status(
        &response,
        STATUS_UNAUTHORIZED,
        "publish scope read rejection",
    )?;

    let response = worker
        .request(
            Method::GET,
            &record_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_NOT_FOUND, "missing record")?;

    let first = envelope(1, b"first opaque fixture")?;
    let publish_headers = publishing_headers(&account.publish_token);
    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publish_headers.clone(),
            Some(&first),
        )
        .await?;
    expect_status(&response, STATUS_CREATED, "record creation")?;
    expect_header(&response, HEADER_ETAG, "\"1\"", "record creation")?;

    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publishing_headers(&account.download_token),
            Some(&first),
        )
        .await?;
    expect_status(
        &response,
        STATUS_UNAUTHORIZED,
        "download scope write rejection",
    )?;

    let response = worker
        .request(
            Method::GET,
            &record_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "record download")?;
    expect_header(&response, HEADER_ETAG, "\"1\"", "record download")?;
    ensure!(
        response.body == first,
        "record download: envelope or revision changed"
    );

    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publish_headers.clone(),
            Some(&first),
        )
        .await?;
    expect_status(
        &response,
        STATUS_NO_CONTENT,
        "unconditional same-value replacement",
    )?;
    expect_header(&response, HEADER_ETAG, "\"2\"", "same-value replacement")?;

    let oversized = vec![b'x'; MAX_API_BODY_BYTES + 1];
    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publishing_headers(&account.download_token),
            Some(&oversized),
        )
        .await?;
    expect_status(
        &response,
        STATUS_UNAUTHORIZED,
        "oversized download-scope write rejection",
    )?;
    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publish_headers.clone(),
            Some(&oversized),
        )
        .await?;
    expect_status(
        &response,
        STATUS_PAYLOAD_TOO_LARGE,
        "oversized record rejection",
    )?;

    let second = envelope(2, b"second opaque fixture")?;
    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publish_headers.clone(),
            Some(&second),
        )
        .await?;
    expect_status(&response, STATUS_NO_CONTENT, "record replacement")?;
    expect_header(&response, HEADER_ETAG, "\"3\"", "record replacement")?;

    let response = worker
        .request(
            Method::GET,
            &record_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "latest record download")?;
    expect_header(&response, HEADER_ETAG, "\"3\"", "latest record download")?;
    ensure!(
        response.body == second,
        "latest record download: envelope or revision changed"
    );

    let response = worker
        .request(
            Method::DELETE,
            &record_path,
            bearer(&account.publish_token),
            Some(b""),
        )
        .await?;
    expect_status(
        &response,
        STATUS_METHOD_NOT_ALLOWED,
        "record deletion rejection",
    )?;
    expect_header(&response, "allow", "GET, PUT", "record deletion rejection")?;

    let other_account = create_account(worker).await?;
    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&other_account.download_token),
            None,
        )
        .await?;
    expect_status(
        &response,
        STATUS_UNAUTHORIZED,
        "cross-account read rejection",
    )?;
    let response = worker
        .request(
            Method::PUT,
            &record_path,
            publishing_headers(&other_account.publish_token),
            Some(&first),
        )
        .await?;
    expect_status(
        &response,
        STATUS_UNAUTHORIZED,
        "cross-account write rejection",
    )?;

    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "latest index")?;
    let latest_index = parse_live_record_index(&response.body)
        .map_err(|_| anyhow!("latest index: invalid response body"))?;
    let expected_index = LiveRecordIndex::new(vec![LiveRecordIndexEntry {
        record_id,
        revision: 3,
    }])
    .expect("fixed latest index is valid");
    ensure!(
        latest_index == expected_index,
        "latest index: unexpected body"
    );

    Ok((account, record_id))
}

async fn concurrent_put(
    worker: &LocalWorker,
    barrier: Arc<Barrier>,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
) -> Result<ApiResponse> {
    time::timeout(REQUEST_TIMEOUT, barrier.wait())
        .await
        .map_err(|_| anyhow!("concurrent upserts: timed out waiting to start"))?;
    worker
        .request(Method::PUT, &path, headers, Some(&body))
        .await
}

async fn verify_concurrent_last_write_wins(worker: &LocalWorker) -> Result<()> {
    let account = create_account(worker).await?;
    let record_id = RecordId::from_bytes([0x44; 16]);
    let record_path = format!("/v1/accounts/{}/records/{record_id}", account.id);
    let headers = publishing_headers(&account.publish_token);
    let first = envelope(4, b"concurrent fixture one")?;
    let second = envelope(5, b"concurrent fixture two")?;
    let barrier = Arc::new(Barrier::new(2));

    let (first_response, second_response) = tokio::join!(
        concurrent_put(
            worker,
            Arc::clone(&barrier),
            record_path.clone(),
            headers.clone(),
            first.clone(),
        ),
        concurrent_put(
            worker,
            barrier,
            record_path.clone(),
            headers,
            second.clone()
        ),
    );
    let first_response = first_response?;
    let second_response = second_response?;
    let mut statuses = [
        first_response.status.as_u16(),
        second_response.status.as_u16(),
    ];
    statuses.sort_unstable();
    ensure!(
        statuses == [STATUS_CREATED, STATUS_NO_CONTENT],
        "concurrent upserts: unexpected status pair"
    );
    let first_revision = header(&first_response, HEADER_ETAG);
    let second_revision = header(&second_response, HEADER_ETAG);
    ensure!(
        (first_revision == Some("\"1\"") && second_revision == Some("\"2\""))
            || (first_revision == Some("\"2\"") && second_revision == Some("\"1\"")),
        "concurrent upserts: unexpected revision pair"
    );
    for response in [&first_response, &second_response] {
        ensure!(
            header(response, "cache-control") == Some(CACHE_CONTROL_VALUE),
            "concurrent upserts: response was not marked no-store"
        );
    }

    let response = worker
        .request(
            Method::GET,
            &record_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "concurrent upsert result")?;
    expect_header(&response, HEADER_ETAG, "\"2\"", "concurrent upsert result")?;
    ensure!(
        response.body == first || response.body == second,
        "concurrent upserts: latest value was not retained"
    );
    Ok(())
}

async fn verify_index_is_derived_in_record_id_order(worker: &LocalWorker) -> Result<()> {
    let account = create_account(worker).await?;
    let records_path = format!("/v1/accounts/{}/records", account.id);
    let headers = publishing_headers(&account.publish_token);
    let value = envelope(6, b"ordered index fixture")?;
    let low = RecordId::from_bytes([1; 16]);
    let high = RecordId::from_bytes([0xfe; 16]);

    for (record_id, expected_status) in [
        (high, STATUS_CREATED),
        (low, STATUS_CREATED),
        (high, STATUS_NO_CONTENT),
    ] {
        let response = worker
            .request(
                Method::PUT,
                &format!("{records_path}/{record_id}"),
                headers.clone(),
                Some(&value),
            )
            .await?;
        expect_status(&response, expected_status, "ordered index upsert")?;
    }

    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "ordered index")?;
    let index = parse_live_record_index(&response.body)
        .map_err(|_| anyhow!("ordered index: invalid response body"))?;
    let expected = LiveRecordIndex::new(vec![
        LiveRecordIndexEntry {
            record_id: low,
            revision: 1,
        },
        LiveRecordIndexEntry {
            record_id: high,
            revision: 2,
        },
    ])
    .expect("ordered index fixture is valid");
    ensure!(index == expected, "ordered index: unexpected body");
    Ok(())
}

async fn verify_live_quota(worker: &LocalWorker) -> Result<()> {
    let account = create_account(worker).await?;
    let records_path = format!("/v1/accounts/{}/records", account.id);
    let headers = publishing_headers(&account.publish_token);
    let value = envelope(6, b"quota fixture")?;

    for index in 0..MAX_LIVE_RECORDS {
        let record_id = RecordId::from_bytes((index as u128).to_be_bytes());
        let response = worker
            .request(
                Method::PUT,
                &format!("{records_path}/{record_id}"),
                headers.clone(),
                Some(&value),
            )
            .await?;
        expect_status(&response, STATUS_CREATED, "record within live quota")?;
    }

    let over_quota_id = RecordId::from_bytes([0xff; 16]);
    let response = worker
        .request(
            Method::PUT,
            &format!("{records_path}/{over_quota_id}"),
            headers.clone(),
            Some(&value),
        )
        .await?;
    expect_status(
        &response,
        STATUS_TOO_MANY_REQUESTS,
        "record beyond live quota",
    )?;
    expect_header(
        &response,
        HEADER_RETRY_AFTER,
        "60",
        "record beyond live quota",
    )?;

    let first_id = RecordId::from_bytes([0; 16]);
    let replacement = envelope(7, b"at-quota replacement")?;
    let response = worker
        .request(
            Method::PUT,
            &format!("{records_path}/{first_id}"),
            headers,
            Some(&replacement),
        )
        .await?;
    expect_status(
        &response,
        STATUS_NO_CONTENT,
        "record replacement at live quota",
    )?;
    expect_header(
        &response,
        HEADER_ETAG,
        "\"2\"",
        "record replacement at live quota",
    )?;
    Ok(())
}

async fn verify_persistence(
    worker: &LocalWorker,
    account: &TestAccount,
    record_id: RecordId,
) -> Result<()> {
    let records_path = format!("/v1/accounts/{}/records", account.id);
    let response = worker
        .request(
            Method::GET,
            &records_path,
            bearer(&account.download_token),
            None,
        )
        .await?;
    expect_status(&response, STATUS_OK, "persisted index")?;
    let index = parse_live_record_index(&response.body)
        .map_err(|_| anyhow!("persisted index: invalid response body"))?;
    let expected = LiveRecordIndex::new(vec![LiveRecordIndexEntry {
        record_id,
        revision: 3,
    }])
    .expect("fixed persisted index is valid");
    ensure!(
        index == expected,
        "persisted index: durable state did not survive restart"
    );
    Ok(())
}

async fn stop_workers(first: &mut LocalWorker, second: &mut LocalWorker) -> Result<()> {
    let first_result = first.stop().await;
    let second_result = second.stop().await;
    if first_result.is_err() || second_result.is_err() {
        bail!("failed to stop local Worker")
    }
    Ok(())
}

async fn diagnostics(first: &mut LocalWorker, second: &mut LocalWorker) -> String {
    let first = first.diagnostics().await;
    let second = second.diagnostics().await;
    [
        ("first local Worker", first),
        ("second local Worker", second),
    ]
    .into_iter()
    .filter_map(|(name, output)| (!output.is_empty()).then(|| format!("{name}:\n{output}")))
    .collect::<Vec<_>>()
    .join("\n")
}

async fn run_local_worker_api() -> Result<()> {
    let temporary = Builder::new()
        .prefix("attached-worker-test-")
        .tempdir()
        .map_err(|_| anyhow!("failed to create local Worker temporary state"))?;
    let state_dir = temporary.path().join("state");
    let client = client()?;
    let mut first = LocalWorker::new(
        client.clone(),
        &temporary,
        &state_dir,
        "first-wrangler-output.log",
    )?;
    let mut second =
        LocalWorker::new(client, &temporary, &state_dir, "second-wrangler-output.log")?;

    let result = match time::timeout(INTEGRATION_TIMEOUT, async {
        first.start().await?;
        let (account, record_id) = exercise_api(&first).await?;
        verify_concurrent_last_write_wins(&first).await?;
        verify_index_is_derived_in_record_id_order(&first).await?;
        verify_live_quota(&first).await?;
        first.stop().await?;

        second.start().await?;
        verify_persistence(&second, &account, record_id).await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "local Worker integration test exceeded its {}-second deadline",
            INTEGRATION_TIMEOUT.as_secs()
        )),
    };

    if let Err(error) = result {
        let output = diagnostics(&mut first, &mut second).await;
        let cleanup = stop_workers(&mut first, &mut second).await;
        let error = if cleanup.is_err() {
            error.context("failed to clean up local Worker after the test failure")
        } else {
            error
        };
        return if output.is_empty() {
            Err(error)
        } else {
            Err(error.context(format!("local Worker diagnostics:\n{output}")))
        };
    }

    stop_workers(&mut first, &mut second).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires worker-build, corepack, pnpm, and local workerd"]
async fn local_workerd_exercises_api() -> Result<()> {
    run_local_worker_api().await
}
