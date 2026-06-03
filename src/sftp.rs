//! Filesystem-backed SFTP subsystem handler for the SSH server.
//!
//! Modern OpenSSH clients (9.0+) use the SFTP protocol for `scp` by default
//! (unless `-O` is passed to force the legacy SCP protocol). This module
//! implements a real, working SFTP server on top of [`russh_sftp`] so that
//! plain `scp` and `sftp` work against this server.
//!
//! It maps SFTP operations onto the local filesystem (relative to the process
//! working directory). Handles are random opaque strings; per-handle state
//! (open files and directory iterators) is kept in maps.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

/// One open regular file, tracked by its handle id.
struct OpenFile {
    file: std::fs::File,
}

/// One opened directory: the precomputed entries and whether we've already
/// returned them (SFTP `readdir` is called repeatedly until EOF).
struct OpenDir {
    path: PathBuf,
    entries: Vec<File>,
    done: bool,
}

/// The per-connection SFTP session handler.
pub struct SftpSession {
    version: Option<u32>,
    /// Open file handles keyed by their opaque handle string.
    files: HashMap<String, OpenFile>,
    /// Open directory handles keyed by their opaque handle string.
    dirs: HashMap<String, OpenDir>,
    /// Monotonic counter to mint unique handle strings.
    next_handle: AtomicU64,
}

impl Default for SftpSession {
    fn default() -> Self {
        Self {
            version: None,
            files: HashMap::new(),
            dirs: HashMap::new(),
            next_handle: AtomicU64::new(1),
        }
    }
}

impl SftpSession {
    fn new_handle(&self, kind: &str) -> String {
        let n = self.next_handle.fetch_add(1, Ordering::Relaxed);
        format!("{kind}-{n}")
    }
}

/// Map a std::io::Error to the closest SFTP status code.
fn io_to_status(e: &std::io::Error) -> StatusCode {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => StatusCode::NoSuchFile,
        PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

/// Build a successful `Status` reply.
fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

/// Convert an `std::fs::Metadata` into SFTP `FileAttributes`.
fn meta_to_attrs(meta: &std::fs::Metadata) -> FileAttributes {
    FileAttributes::from(meta)
}

#[allow(unused_variables)]
impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if self.version.is_some() {
            log::error!("duplicate SSH_FXP_INIT");
            return Err(StatusCode::ConnectionLost);
        }
        self.version = Some(version);
        log::info!("sftp: client version {version}");
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        // Resolve the requested path to an absolute, canonical path. The
        // OpenSSH client sends "." initially and relies on the answer to set
        // the remote working directory.
        let p = if path.is_empty() { ".".to_string() } else { path };
        let resolved = std::fs::canonicalize(&p).unwrap_or_else(|_| {
            // If it doesn't exist yet, fall back to an absolute (lexical) path.
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            if Path::new(&p).is_absolute() {
                PathBuf::from(&p)
            } else {
                cwd.join(&p)
            }
        });
        let name = path_to_string(&resolved);
        log::info!("sftp realpath: {p} -> {name}");
        Ok(Name {
            id,
            files: vec![File::dummy(name)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::metadata(&path).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: meta_to_attrs(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = std::fs::symlink_metadata(&path).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: meta_to_attrs(&meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let of = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let meta = of.file.metadata().map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: meta_to_attrs(&meta),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        // Translate SFTP open flags into std OpenOptions (the crate provides a
        // direct conversion).
        let opts: std::fs::OpenOptions = pflags.into();
        let file = opts.open(&filename).map_err(|e| {
            log::warn!("sftp open {filename} failed: {e}");
            io_to_status(&e)
        })?;
        let handle = self.new_handle("file");
        self.files.insert(handle.clone(), OpenFile { file });
        log::info!("sftp open: {filename} (flags {pflags:?}) -> {handle}");
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        use std::io::{Read, Seek, SeekFrom};
        let of = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        of.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| io_to_status(&e))?;
        let mut buf = vec![0u8; len as usize];
        let n = of.file.read(&mut buf).map_err(|e| io_to_status(&e))?;
        if n == 0 {
            // End of file: SFTP signals this with an EOF status.
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        use std::io::{Seek, SeekFrom, Write};
        let of = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        of.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| io_to_status(&e))?;
        of.file.write_all(&data).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        // Dropping the entry closes the underlying file/dir.
        let was_file = self.files.remove(&handle).is_some();
        let was_dir = self.dirs.remove(&handle).is_some();
        if was_file || was_dir {
            Ok(ok_status(id))
        } else {
            // Unknown handle: still respond OK to keep the client happy.
            Ok(ok_status(id))
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let meta = std::fs::metadata(&path).map_err(|e| io_to_status(&e))?;
        if !meta.is_dir() {
            return Err(StatusCode::NoSuchFile);
        }

        // Precompute the directory listing now, including "." and "..".
        let mut files = Vec::new();
        let dir_path = PathBuf::from(&path);

        if let Ok(m) = std::fs::metadata(&dir_path) {
            files.push(File::new(".", meta_to_attrs(&m)));
        }
        if let Some(parent) = dir_path.parent() {
            if let Ok(m) = std::fs::metadata(parent) {
                files.push(File::new("..", meta_to_attrs(&m)));
            }
        }

        match std::fs::read_dir(&dir_path) {
            Ok(rd) => {
                for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let attrs = match entry.metadata() {
                        Ok(m) => meta_to_attrs(&m),
                        Err(_) => FileAttributes::default(),
                    };
                    files.push(File::new(name, attrs));
                }
            }
            Err(e) => return Err(io_to_status(&e)),
        }

        let handle = self.new_handle("dir");
        self.dirs.insert(
            handle.clone(),
            OpenDir {
                path: dir_path,
                entries: files,
                done: false,
            },
        );
        log::info!("sftp opendir: {path} -> {handle}");
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let dir = self.dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if dir.done {
            // All entries already returned: signal EOF.
            return Err(StatusCode::Eof);
        }
        dir.done = true;
        let files = std::mem::take(&mut dir.entries);
        log::info!(
            "sftp readdir: {} -> {} entries",
            path_to_string(&dir.path),
            files.len()
        );
        Ok(Name { id, files })
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(&filename).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        std::fs::create_dir_all(&path).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(&path).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        std::fs::rename(&oldpath, &newpath).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        // Accept attribute changes (permissions/times) as a no-op so that
        // `scp` (which sends a setstat after upload) succeeds.
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(ok_status(id))
    }
}

/// Render a path as a forward-slash string. On Windows, canonicalize() yields
/// a `\\?\C:\...` extended-length path; strip the prefix and normalize slashes
/// so SFTP clients see a clean path.
fn path_to_string(p: &Path) -> String {
    let s = p.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let s = s.replace('\\', "/");
    if s.is_empty() {
        "/".to_string()
    } else {
        s
    }
}
