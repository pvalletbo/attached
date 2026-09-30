//! Embedded SFTP v3, with the same filesystem authority as the publisher shell.
//! russh-sftp supplies the codecs. We own the bounded request loop rather than
//! its detached server runner, so errors and cancellation close all file handles.
use std::{
    collections::HashMap,
    io::{self, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use russh_sftp::{
    protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode,
        Version,
    },
    server::Handler,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt},
};
use tokio_util::sync::CancellationToken;

const MAX_PACKET: u32 = 256 * 1024;
const MAX_READ: u32 = 64 * 1024;
const MAX_HANDLES: usize = 128;
const DIRECTORY_BATCH: usize = 32;

pub(super) async fn serve<S>(mut stream: S, home: PathBuf, cancel: CancellationToken) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handler = Filesystem::new(home);
    let session = async {
        let mut initialized = false;
        loop {
            let mut header = [0; 4];
            if stream.read(&mut header[..1]).await? == 0 {
                return Ok(());
            }
            // Only EOF between packets is clean. A partial header/body is a
            // malformed request, not a successful transfer shutdown.
            stream.read_exact(&mut header[1..]).await?;
            let length = u32::from_be_bytes(header);
            ensure!(
                (1..=MAX_PACKET).contains(&length),
                "invalid SFTP packet length"
            );
            let mut buffer = vec![0; length as usize];
            stream.read_exact(&mut buffer).await?;
            // Reject response-only packet types before decoding their arbitrary
            // collection counts. Client requests are INIT, 3..20, and EXTENDED.
            ensure!(
                matches!(buffer[0], 1 | 3..=20 | 200),
                "invalid SFTP request type"
            );
            let mut buffer = Bytes::from(buffer);
            let request = Packet::try_from(&mut buffer).context("invalid SFTP packet")?;
            ensure!(buffer.is_empty(), "trailing SFTP request data");
            if matches!(request, Packet::Init(_)) {
                ensure!(!initialized, "duplicate SFTP initialization");
                initialized = true;
            } else {
                ensure!(initialized, "SFTP request before initialization");
            }
            let response = dispatch(&mut handler, request).await;
            // Serialization includes the four-byte packet length.
            let encoded = Bytes::try_from(response)?;
            ensure!(
                encoded.len() <= MAX_PACKET as usize + 4,
                "SFTP response too large"
            );
            stream.write_all(&encoded).await?;
            stream.flush().await?;
        }
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(()),
        result = session => result,
    }
}

macro_rules! reply {
    ($handler:expr, $request:expr, $method:ident, $($argument:ident),*) => {{
        let request = $request;
        let id = request.id;
        match $handler.$method(id, $(request.$argument),*).await {
            Ok(response) => response.into(),
            Err(code) => Packet::error(id, code),
        }
    }};
}

async fn dispatch(handler: &mut Filesystem, packet: Packet) -> Packet {
    match packet {
        Packet::Init(request) => match handler.init(request.version, request.extensions).await {
            Ok(version) => version.into(),
            Err(code) => Packet::error(0, code),
        },
        Packet::Open(r) => reply!(handler, r, open, filename, pflags, attrs),
        Packet::Close(r) => reply!(handler, r, close, handle),
        Packet::Read(r) => reply!(handler, r, read, handle, offset, len),
        Packet::Write(r) => reply!(handler, r, write, handle, offset, data),
        Packet::Lstat(r) => reply!(handler, r, lstat, path),
        Packet::Fstat(r) => reply!(handler, r, fstat, handle),
        Packet::SetStat(r) => reply!(handler, r, setstat, path, attrs),
        Packet::FSetStat(r) => reply!(handler, r, fsetstat, handle, attrs),
        Packet::OpenDir(r) => reply!(handler, r, opendir, path),
        Packet::ReadDir(r) => reply!(handler, r, readdir, handle),
        Packet::Remove(r) => reply!(handler, r, remove, filename),
        Packet::MkDir(r) => reply!(handler, r, mkdir, path, attrs),
        Packet::RmDir(r) => reply!(handler, r, rmdir, path),
        Packet::RealPath(r) => reply!(handler, r, realpath, path),
        Packet::Stat(r) => reply!(handler, r, stat, path),
        Packet::Rename(r) => reply!(handler, r, rename, oldpath, newpath),
        Packet::ReadLink(r) => reply!(handler, r, readlink, path),
        // OpenSSH's SYMLINK wire ordering reverses the original v3 draft:
        // the target comes first, then the name of the new symbolic link.
        Packet::Symlink(r) => reply!(handler, r, symlink, targetpath, linkpath),
        Packet::Extended(r) => reply!(handler, r, extended, request, data),
        other => Packet::error(other.get_request_id(), StatusCode::BadMessage),
    }
}

enum Resource {
    File(fs::File),
    Directory(fs::ReadDir),
}

struct Filesystem {
    home: PathBuf,
    handles: HashMap<String, Resource>,
    next_handle: u64,
}

impl Filesystem {
    fn new(home: PathBuf) -> Self {
        Self {
            home,
            handles: HashMap::new(),
            next_handle: 0,
        }
    }

    // This is a working directory, NOT a chroot. Absolute paths and '..' retain
    // the same meaning and OS permissions as commands executed by Attached.
    fn path(&self, path: &str) -> std::result::Result<PathBuf, StatusCode> {
        if path.contains('\0') {
            return Err(StatusCode::BadMessage);
        }
        Ok(self.home.join(if path.is_empty() { "." } else { path }))
    }

    fn capacity(&self) -> std::result::Result<(), StatusCode> {
        if self.handles.len() >= MAX_HANDLES {
            Err(StatusCode::Failure)
        } else {
            Ok(())
        }
    }

    fn insert(&mut self, id: u32, resource: Resource) -> Handle {
        self.next_handle += 1;
        let handle = self.next_handle.to_string();
        self.handles.insert(handle.clone(), resource);
        Handle { id, handle }
    }

    fn file(&mut self, handle: &str) -> std::result::Result<&mut fs::File, StatusCode> {
        match self.handles.get_mut(handle) {
            Some(Resource::File(file)) => Ok(file),
            _ => Err(StatusCode::Failure),
        }
    }
}

fn status(error: io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

fn attributes(metadata: std::fs::Metadata) -> FileAttributes {
    FileAttributes::from(&metadata)
}

// OpenSSH's REALPATH permits a missing final component. scp -r uses this
// before creating a new destination directory; existing parents still resolve
// through the OS, including symlinks, rather than through lexical guessing.
async fn canonicalize(path: PathBuf) -> std::result::Result<PathBuf, StatusCode> {
    match fs::canonicalize(&path).await {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(StatusCode::NoSuchFile)?;
            let parent = path.parent().ok_or(StatusCode::NoSuchFile)?;
            let parent = fs::canonicalize(parent).await.map_err(status)?;
            if !fs::metadata(&parent).await.map_err(status)?.is_dir() {
                return Err(StatusCode::Failure);
            }
            Ok(parent.join(name))
        }
        Err(error) => Err(status(error)),
    }
}

fn utf8(path: PathBuf) -> std::result::Result<String, StatusCode> {
    path.into_os_string()
        .into_string()
        .map_err(|_| StatusCode::Failure)
}

async fn apply_attributes(
    file: &fs::File,
    attrs: FileAttributes,
) -> std::result::Result<(), StatusCode> {
    // Borrowing the native fd avoids converting/cloning Tokio's file while it
    // has pending I/O. These metadata syscalls do not transfer file contents.
    if attrs.uid.is_some() || attrs.gid.is_some() {
        rustix::fs::fchown(
            file,
            attrs.uid.map(rustix::process::Uid::from_raw),
            attrs.gid.map(rustix::process::Gid::from_raw),
        )
        .map_err(io::Error::from)
        .map_err(status)?;
    }
    if let Some(mode) = attrs.permissions {
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
            .await
            .map_err(status)?;
    }
    if let Some(size) = attrs.size {
        file.set_len(size).await.map_err(status)?;
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        rustix::fs::futimens(file, &timestamps(&attrs))
            .map_err(io::Error::from)
            .map_err(status)?;
    }
    Ok(())
}

fn timestamps(attrs: &FileAttributes) -> rustix::fs::Timestamps {
    let timestamp = |seconds: Option<u32>| rustix::fs::Timespec {
        tv_sec: seconds.unwrap_or(0).into(),
        tv_nsec: if seconds.is_some() {
            0
        } else {
            rustix::fs::UTIME_OMIT
        },
    };
    rustix::fs::Timestamps {
        last_access: timestamp(attrs.atime),
        last_modification: timestamp(attrs.mtime),
    }
}

impl Handler for Filesystem {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _: u32,
        _: HashMap<String, String>,
    ) -> std::result::Result<Version, StatusCode> {
        let mut version = Version::new();
        version
            .extensions
            .insert("posix-rename@openssh.com".into(), "1".into());
        version
            .extensions
            .insert("expand-path@openssh.com".into(), "1".into());
        version
            .extensions
            .insert("fsync@openssh.com".into(), "1".into());
        Ok(version)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        flags: OpenFlags,
        attrs: FileAttributes,
    ) -> std::result::Result<Handle, StatusCode> {
        self.capacity()?;
        if flags.bits() & !OpenFlags::all().bits() != 0
            || !flags.intersects(OpenFlags::READ | OpenFlags::WRITE)
            || flags.intersects(OpenFlags::APPEND | OpenFlags::TRUNCATE | OpenFlags::CREATE)
                && !flags.contains(OpenFlags::WRITE)
            || flags.contains(OpenFlags::EXCLUDE) && !flags.contains(OpenFlags::CREATE)
        {
            return Err(StatusCode::BadMessage);
        }
        let mut options = fs::OpenOptions::new();
        options
            .read(flags.contains(OpenFlags::READ))
            .write(flags.contains(OpenFlags::WRITE))
            .append(flags.contains(OpenFlags::APPEND))
            .create(flags.contains(OpenFlags::CREATE))
            .create_new(flags.contains(OpenFlags::EXCLUDE))
            .truncate(flags.contains(OpenFlags::TRUNCATE))
            .mode(attrs.permissions.unwrap_or(0o666) & 0o7777)
            // Opening a FIFO must not block a runtime worker or shutdown. Reject
            // all non-regular files after opening without blocking.
            .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        let file = options.open(self.path(&filename)?).await.map_err(status)?;
        if !file.metadata().await.map_err(status)?.is_file() {
            return Err(StatusCode::Failure);
        }
        Ok(self.insert(id, Resource::File(file)))
    }

    async fn close(&mut self, id: u32, handle: String) -> std::result::Result<Status, StatusCode> {
        let resource = self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        if let Resource::File(mut file) = resource {
            file.flush().await.map_err(status)?;
        }
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> std::result::Result<Data, StatusCode> {
        let file = self.file(&handle)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(status)?;
        let mut data = vec![0; len.min(MAX_READ) as usize];
        let count = file.read(&mut data).await.map_err(status)?;
        if count == 0 && len != 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(count);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> std::result::Result<Status, StatusCode> {
        let file = self.file(&handle)?;
        file.seek(SeekFrom::Start(offset)).await.map_err(status)?;
        file.write_all(&data).await.map_err(status)?;
        // An SFTP acknowledgement reports completed I/O, not a Tokio buffer that
        // can still fail later. This does not imply a durable fsync per packet.
        file.flush().await.map_err(status)?;
        Ok(ok(id))
    }

    async fn stat(&mut self, id: u32, path: String) -> std::result::Result<Attrs, StatusCode> {
        Ok(Attrs {
            id,
            attrs: attributes(fs::metadata(self.path(&path)?).await.map_err(status)?),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> std::result::Result<Attrs, StatusCode> {
        Ok(Attrs {
            id,
            attrs: attributes(
                fs::symlink_metadata(self.path(&path)?)
                    .await
                    .map_err(status)?,
            ),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> std::result::Result<Attrs, StatusCode> {
        Ok(Attrs {
            id,
            attrs: attributes(self.file(&handle)?.metadata().await.map_err(status)?),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> std::result::Result<Status, StatusCode> {
        let path = self.path(&path)?;
        let metadata = fs::metadata(&path).await.map_err(status)?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(StatusCode::Failure);
        }
        if let Some(size) = attrs.size {
            let file = fs::OpenOptions::new()
                .write(true)
                .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                .open(&path)
                .await
                .map_err(status)?;
            if !file.metadata().await.map_err(status)?.is_file() {
                return Err(StatusCode::Failure);
            }
            file.set_len(size).await.map_err(status)?;
        }
        // chmod/chown/utime need ownership, not permission to read the file.
        // In particular a client must be able to restore permissions after
        // chmod 000, and update metadata on write-only files/directories.
        if attrs.uid.is_some() || attrs.gid.is_some() {
            rustix::fs::chownat(
                rustix::fs::CWD,
                &path,
                attrs.uid.map(rustix::process::Uid::from_raw),
                attrs.gid.map(rustix::process::Gid::from_raw),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(io::Error::from)
            .map_err(status)?;
        }
        if let Some(mode) = attrs.permissions {
            fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o7777))
                .await
                .map_err(status)?;
        }
        if attrs.atime.is_some() || attrs.mtime.is_some() {
            rustix::fs::utimensat(
                rustix::fs::CWD,
                &path,
                &timestamps(&attrs),
                rustix::fs::AtFlags::empty(),
            )
            .map_err(io::Error::from)
            .map_err(status)?;
        }
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> std::result::Result<Status, StatusCode> {
        apply_attributes(self.file(&handle)?, attrs).await?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> std::result::Result<Handle, StatusCode> {
        self.capacity()?;
        let directory = fs::read_dir(self.path(&path)?).await.map_err(status)?;
        Ok(self.insert(id, Resource::Directory(directory)))
    }

    async fn readdir(&mut self, id: u32, handle: String) -> std::result::Result<Name, StatusCode> {
        let Some(Resource::Directory(directory)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        let mut files = Vec::new();
        for _ in 0..DIRECTORY_BATCH {
            let Some(entry) = directory.next_entry().await.map_err(status)? else {
                break;
            };
            let filename = entry
                .file_name()
                .into_string()
                .map_err(|_| StatusCode::Failure)?;
            files.push(File::new(
                filename,
                attributes(entry.metadata().await.map_err(status)?),
            ));
        }
        if files.is_empty() {
            return Err(StatusCode::Eof);
        }
        Ok(Name { id, files })
    }

    async fn realpath(&mut self, id: u32, path: String) -> std::result::Result<Name, StatusCode> {
        let path = canonicalize(self.path(&path)?).await?;
        Ok(Name {
            id,
            files: vec![File::dummy(utf8(path)?)],
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> std::result::Result<Status, StatusCode> {
        let mut builder = fs::DirBuilder::new();
        builder.mode(attrs.permissions.unwrap_or(0o777) & 0o7777);
        builder.create(self.path(&path)?).await.map_err(status)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> std::result::Result<Status, StatusCode> {
        fs::remove_dir(self.path(&path)?).await.map_err(status)?;
        Ok(ok(id))
    }

    async fn remove(
        &mut self,
        id: u32,
        filename: String,
    ) -> std::result::Result<Status, StatusCode> {
        fs::remove_file(self.path(&filename)?)
            .await
            .map_err(status)?;
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> std::result::Result<Status, StatusCode> {
        let old = self.path(&oldpath)?;
        let new = self.path(&newpath)?;
        // SFTP v3 RENAME must not replace an existing destination.
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &old,
            rustix::fs::CWD,
            &new,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(io::Error::from)
        .map_err(status)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> std::result::Result<Name, StatusCode> {
        let target = fs::read_link(self.path(&path)?).await.map_err(status)?;
        Ok(Name {
            id,
            files: vec![File::dummy(utf8(target)?)],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> std::result::Result<Status, StatusCode> {
        if targetpath.contains('\0') {
            return Err(StatusCode::BadMessage);
        }
        fs::symlink(Path::new(&targetpath), self.path(&linkpath)?)
            .await
            .map_err(status)?;
        Ok(ok(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> std::result::Result<Packet, StatusCode> {
        if !matches!(
            request.as_str(),
            "fsync@openssh.com" | "expand-path@openssh.com" | "posix-rename@openssh.com"
        ) {
            return Err(StatusCode::OpUnsupported);
        }
        let mut data = data.as_slice();
        let first = extension_string(&mut data)?;
        match request.as_str() {
            "fsync@openssh.com" => {
                if !data.is_empty() {
                    return Err(StatusCode::BadMessage);
                }
                self.file(&first)?.sync_all().await.map_err(status)?;
                Ok(ok(id).into())
            }
            "expand-path@openssh.com" => {
                if !data.is_empty() {
                    return Err(StatusCode::BadMessage);
                }
                let expanded = if first == "~" {
                    self.home.clone()
                } else if let Some(relative) = first.strip_prefix("~/") {
                    self.home.join(relative)
                } else if first.starts_with('~') {
                    return Err(StatusCode::OpUnsupported);
                } else {
                    self.path(&first)?
                };
                let path = canonicalize(expanded).await?;
                Ok(Name {
                    id,
                    files: vec![File::dummy(utf8(path)?)],
                }
                .into())
            }
            "posix-rename@openssh.com" => {
                let second = extension_string(&mut data)?;
                if !data.is_empty() {
                    return Err(StatusCode::BadMessage);
                }
                fs::rename(self.path(&first)?, self.path(&second)?)
                    .await
                    .map_err(status)?;
                Ok(ok(id).into())
            }
            _ => Err(StatusCode::OpUnsupported),
        }
    }
}

fn extension_string(data: &mut &[u8]) -> std::result::Result<String, StatusCode> {
    if data.len() < 4 {
        return Err(StatusCode::BadMessage);
    }
    let length = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    *data = &data[4..];
    if length > data.len() {
        return Err(StatusCode::BadMessage);
    }
    let text = std::str::from_utf8(&data[..length])
        .map_err(|_| StatusCode::BadMessage)?
        .to_owned();
    *data = &data[length..];
    Ok(text)
}

#[cfg(test)]
#[path = "sftp_tests.rs"]
mod tests;
