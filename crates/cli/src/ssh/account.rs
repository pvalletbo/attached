//! Resolve the effective account through the OS directory service, not environment
//! variables or /etc/passwd alone. Absolute tool paths avoid PATH substitution and
//! keep this lookup compatible with the workspace's prohibition on unsafe code.
use std::{os::unix::ffi::OsStrExt, path::PathBuf, process::Command};

use anyhow::{Context, Result, ensure};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Account {
    pub uid: u32,
    pub username: String,
    pub home: PathBuf,
    pub shell: PathBuf,
}

pub(super) fn lookup(uid: u32) -> Result<Account> {
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = Command::new("/usr/bin/getent");
        command.args(["passwd", &uid.to_string()]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/dscacheutil");
        command.args(["-q", "user", "-a", "uid", &uid.to_string()]);
        command
    };
    let output = command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .context("could not run OS account lookup tool")?;
    ensure!(output.status.success(), "OS account lookup failed");
    #[cfg(target_os = "linux")]
    let account = parse_passwd(&output.stdout, uid);
    #[cfg(target_os = "macos")]
    let account = parse_directory(&output.stdout, uid);
    account.context("could not resolve publisher OS account")
}

fn account(
    uid: &[u8],
    username: &[u8],
    home: &[u8],
    shell: &[u8],
    expected: u32,
) -> Result<Account> {
    let uid: u32 = std::str::from_utf8(uid)?.parse()?;
    ensure!(uid == expected, "OS account UID mismatch");
    let username = std::str::from_utf8(username)?.to_owned();
    ensure!(
        !username.is_empty()
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
        "unsupported OS username"
    );
    ensure!(
        !home.contains(&0) && !shell.contains(&0),
        "NUL in account path"
    );
    let home = PathBuf::from(std::ffi::OsStr::from_bytes(home));
    let shell = PathBuf::from(std::ffi::OsStr::from_bytes(shell));
    ensure!(
        home.is_absolute() && shell.is_absolute(),
        "account shell and home must be absolute paths"
    );
    Ok(Account {
        uid,
        username,
        home,
        shell,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_passwd(bytes: &[u8], uid: u32) -> Result<Account> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    ensure!(!bytes.contains(&b'\n'), "ambiguous OS account lookup");
    let fields: Vec<_> = bytes.split(|b| *b == b':').collect();
    ensure!(fields.len() == 7, "invalid passwd record");
    account(fields[2], fields[0], fields[5], fields[6], uid)
}

#[cfg(any(target_os = "macos", test))]
fn parse_directory(bytes: &[u8], uid: u32) -> Result<Account> {
    let mut fields = std::collections::BTreeMap::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let separator = line
            .windows(2)
            .position(|w| w == b": ")
            .context("invalid directory record")?;
        let (key, value) = (&line[..separator], &line[separator + 2..]);
        ensure!(
            fields.insert(key, value).is_none(),
            "ambiguous directory record"
        );
    }
    let field = |key: &[u8]| {
        fields
            .get(key)
            .copied()
            .context("missing directory account field")
    };
    account(
        field(b"uid")?,
        field(b"name")?,
        field(b"dir")?,
        field(b"shell")?,
        uid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_and_macos_directory_records() {
        let expected = Account {
            uid: 501,
            username: "alice".into(),
            home: "/home/alice".into(),
            shell: "/bin/sh".into(),
        };
        assert_eq!(
            parse_passwd(b"alice:x:501:20:Alice:/home/alice:/bin/sh\n", 501).unwrap(),
            expected
        );
        assert_eq!(parse_directory(b"name: alice\npassword: ********\nuid: 501\ngid: 20\ndir: /home/alice\nshell: /bin/sh\ngecos: Alice\n\n", 501).unwrap(), expected);
    }

    #[test]
    fn rejects_missing_ambiguous_mismatched_or_invalid_accounts() {
        for record in [
            b"".as_slice(),
            b"alice:x:501:20:Alice:/home/alice:/bin/sh\nalice:x:501:20:Alice:/home/alice:/bin/sh\n",
            b"alice:x:502:20:Alice:/home/alice:/bin/sh",
            b"alice:x:501:20:Alice:relative:/bin/sh",
            b"alice:x:501:20:Alice:/home/alice:",
            b"bad name:x:501:20:Alice:/home/alice:/bin/sh",
            b"\xff:x:501:20:Alice:/home/alice:/bin/sh",
            b"alice:x:501:20:Alice:/home/\0:/bin/sh",
        ] {
            assert!(parse_passwd(record, 501).is_err());
        }
        let valid = b"name: alice\nuid: 501\ndir: /home/alice\nshell: /bin/sh\n";
        assert!(parse_directory(valid, 502).is_err());
        assert!(parse_directory(&[valid.as_slice(), valid.as_slice()].concat(), 501).is_err());
        assert!(parse_directory(b"name: alice\nuid: 501\n", 501).is_err());
        assert!(parse_directory(b"malformed", 501).is_err());
    }

    #[test]
    fn preserves_non_utf8_paths() {
        let parsed = parse_passwd(b"alice:x:501:20:Alice:/home/\xff:/bin/sh", 501).unwrap();
        assert_eq!(parsed.home.as_os_str().as_bytes(), b"/home/\xff");
        let parsed = parse_directory(
            b"name: alice\nuid: 501\ndir: /home/\xff\nshell: /bin/sh\n",
            501,
        )
        .unwrap();
        assert_eq!(parsed.home.as_os_str().as_bytes(), b"/home/\xff");
    }

    #[test]
    fn resolves_effective_account_using_system_directory() {
        let uid = rustix::process::geteuid().as_raw();
        let account = lookup(uid).unwrap();
        assert_eq!(account.uid, uid);
        assert!(!account.username.is_empty());
        assert!(account.home.is_absolute());
        assert!(account.shell.is_absolute());
    }
}
