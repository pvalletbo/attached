use std::time::Duration;

use anyhow::{Result, ensure};

use crate::process::{self, Reply, strings};

pub(crate) struct Spec {
    pub args: Vec<String>,
    pub input: Option<Vec<u8>>,
    pub stream: bool,
    pub timeout: Duration,
}

impl Spec {
    pub fn new(args: &[&str]) -> Self {
        Self {
            args: strings(args),
            input: None,
            stream: false,
            timeout: Duration::from_secs(30),
        }
    }
    pub fn stream(mut self) -> Self {
        self.stream = true;
        self
    }
    pub fn seconds(mut self, seconds: u64) -> Self {
        self.timeout = Duration::from_secs(seconds);
        self
    }
    pub fn input(mut self, input: Vec<u8>) -> Self {
        self.input = Some(input);
        self
    }
}

pub(crate) trait Executor {
    async fn execute(&self, spec: Spec) -> Result<Reply>;
}

pub(crate) struct Docker;
impl Executor for Docker {
    async fn execute(&self, spec: Spec) -> Result<Reply> {
        process::run("docker", &spec.args, spec.input, spec.stream, spec.timeout).await
    }
}

pub(crate) async fn checked(executor: &impl Executor, spec: Spec) -> Result<Reply> {
    let operation = spec.args.first().cloned().unwrap_or_default();
    let result = executor.execute(spec).await?;
    // stdout may be a publish bundle or binary. Never include it in an error.
    ensure!(
        result.code == 0,
        "docker {operation} failed with exit status {}; {}",
        result.code,
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    #[derive(Default)]
    pub(crate) struct Fake {
        pub calls: Mutex<Vec<Spec>>,
        pub replies: Mutex<VecDeque<Result<Reply>>>,
        pub hang_build: bool,
        pub fail_ssh: bool,
    }
    impl Executor for Fake {
        async fn execute(&self, spec: Spec) -> Result<Reply> {
            let hang = self.hang_build && spec.args[0] == "build";
            let fail = self.fail_ssh && spec.args.iter().any(|arg| arg == "verify");
            let version = spec.args.last().is_some_and(|arg| arg == "--version");
            self.calls.lock().unwrap().push(spec);
            if hang {
                return std::future::pending().await;
            }
            if fail {
                anyhow::bail!("SSH failure");
            }
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| reply(0, if version { "attached 0.3.5\n" } else { "" }))
        }
    }
    pub fn reply(code: i32, stdout: &str) -> Result<Reply> {
        Ok(Reply {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }

    #[tokio::test]
    async fn errors_do_not_disclose_captured_bundles() {
        let fake = Fake::default();
        fake.replies
            .lock()
            .unwrap()
            .push_back(reply(1, "secret bundle"));
        let error = checked(
            &fake,
            Spec::new(&["exec", "client", "cat", "publish.bundle"]),
        )
        .await
        .err()
        .unwrap();
        assert!(!error.to_string().contains("secret bundle"));
    }
}
