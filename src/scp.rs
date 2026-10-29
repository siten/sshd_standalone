//! SCP protocol implementation over an SSH channel.
//!
//! Implements both the "sink" side (server receives files: `scp -t`) and the
//! "source" side (server sends files: `scp -f`), with recursive (`-r`) support.
//!
//! The SCP wire protocol is the classic OpenSSH one:
//!   * After the channel is opened, sink/source exchange protocol messages.
//!   * A single `\0` byte means "OK". A leading `\x01`/`\x02` byte followed by
//!     text and `\n` means a (fatal) error/warning message.
//!   * Control lines:
//!     `C<mode> <size> <filename>\n`  - regular file follows
//!     `D<mode> <size> <dirname>\n`   - enter directory (size ignored)
//!     `E\n`                          - leave directory
//!     `T<mtime> 0 <atime> 0\n`       - timestamps for the next entry (-p)

use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Parsed `scp` command line coming from an `exec` request.
#[derive(Debug, Clone)]
pub struct ScpCommand {
    /// `-f` source mode (server -> client download).
    pub source: bool,
    /// `-t` sink mode (client -> server upload).
    pub sink: bool,
    /// `-r` recursive.
    pub recursive: bool,
    /// `-d` target should be a directory.
    #[allow(dead_code)]
    pub directory: bool,
    /// The path operand.
    pub path: PathBuf,
}

/// Try to parse a command line into an `ScpCommand`.
///
/// Returns `None` if the command is not an `scp` invocation.
pub fn parse_scp_command(command: &str) -> Option<ScpCommand> {
    let args = shell_words::split(command).ok()?;
    let mut iter = args.iter();
    let first = iter.next()?;
    // Accept "scp" or any path ending in "scp".
    let base = Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first.as_str());
    if base != "scp" {
        return None;
    }

    let mut source = false;
    let mut sink = false;
    let mut recursive = false;
    let mut directory = false;
    let mut path: Option<PathBuf> = None;

    for arg in iter {
        if arg == "--" {
            continue;
        }
        if let Some(flags) = arg.strip_prefix('-') {
            // A bundle of single-char flags, e.g. "-rt", "-f", "-pr".
            for c in flags.chars() {
                match c {
                    'f' => source = true,
                    't' => sink = true,
                    'r' => recursive = true,
                    'd' => directory = true,
                    // Silently ignore the other transfer-tuning flags that the
                    // OpenSSH client may pass (-p, -v, -q, -B, etc.).
                    _ => {}
                }
            }
        } else {
            // Last non-flag operand is the path.
            path = Some(PathBuf::from(arg));
        }
    }

    Some(ScpCommand {
        source,
        sink,
        recursive,
        directory,
        path: path.unwrap_or_else(|| PathBuf::from(".")),
    })
}

const OK: u8 = 0;
const WARN: u8 = 1;
const ERR: u8 = 2;

/// Send a single OK (`\0`) byte.
async fn send_ok<W: AsyncWrite + Unpin>(w: &mut W) -> std::io::Result<()> {
    w.write_all(&[OK]).await?;
    w.flush().await
}

/// Send an SCP error message. `fatal = true` uses code `\x02`.
async fn send_error<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &str,
    fatal: bool,
) -> std::io::Result<()> {
    let code = if fatal { ERR } else { WARN };
    let mut buf = Vec::with_capacity(msg.len() + 2);
    buf.push(code);
    buf.extend_from_slice(msg.as_bytes());
    buf.push(b'\n');
    w.write_all(&buf).await?;
    w.flush().await
}

/// Read the client's status reply (`\0` = OK, otherwise an error message).
async fn read_reply<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<()> {
    let mut code = [0u8; 1];
    r.read_exact(&mut code).await?;
    match code[0] {
        OK => Ok(()),
        WARN | ERR => {
            let msg = read_line(r).await?;
            Err(std::io::Error::other(format!("scp client reported: {msg}")))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected scp reply byte: {other}"),
        )),
    }
}

/// Read a `\n`-terminated line (the `\n` is consumed and dropped).
async fn read_line<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ---------------------------------------------------------------------------
// Sink: client uploads to the server (`scp -t <path>` / `scp -rt <path>`).
// ---------------------------------------------------------------------------

/// Run the SCP sink protocol. `stream` is the bidirectional channel stream.
pub async fn run_sink<S>(stream: &mut S, cmd: &ScpCommand) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // The target path the client gave us. Whether it is a directory or a file
    // name is resolved per incoming entry.
    let target = cmd.path.clone();

    // Tell the client we are ready.
    send_ok(stream).await?;

    // Stack of directories we have descended into (for `D`/`E`).
    let mut dir_stack: Vec<PathBuf> = Vec::new();
    // Pending modification time set by a `T` line (currently parsed but unused
    // beyond acknowledging; could be applied with filetime crate).
    let mut _pending_time = false;

    loop {
        // Read the next control byte.
        let mut first = [0u8; 1];
        let n = stream.read(&mut first).await?;
        if n == 0 {
            break; // EOF: client finished.
        }

        match first[0] {
            b'C' | b'D' => {
                let line = read_line(stream).await?;
                // line is like "0644 1234 filename"
                let entry = match parse_cd_line(&line) {
                    Some(e) => e,
                    None => {
                        send_error(stream, "bad C/D line", true).await?;
                        return Err(io_err("malformed scp control line"));
                    }
                };

                // Compute destination path for this entry.
                let dest = current_dest(&target, &dir_stack, &entry.name);

                if first[0] == b'D' {
                    // Enter directory.
                    if let Err(e) = tokio::fs::create_dir_all(&dest).await {
                        send_error(stream, &format!("mkdir failed: {e}"), false).await?;
                    }
                    dir_stack.push(dest);
                    send_ok(stream).await?;
                } else {
                    // Regular file: ack header, then read `size` bytes.
                    send_ok(stream).await?;
                    receive_file(stream, &dest, entry.size).await?;
                    _pending_time = false;
                }
            }
            b'E' => {
                // Leave the current directory.
                let _ = read_line(stream).await?; // consume the rest (just "\n")
                dir_stack.pop();
                send_ok(stream).await?;
            }
            b'T' => {
                // Timestamp line: "T<mtime> 0 <atime> 0". We acknowledge it.
                let _ = read_line(stream).await?;
                _pending_time = true;
                send_ok(stream).await?;
            }
            0 => {
                // A stray OK from the client; ignore.
            }
            other => {
                send_error(
                    stream,
                    &format!("unexpected scp byte: 0x{other:02x}"),
                    true,
                )
                .await?;
                return Err(io_err("unexpected scp control byte"));
            }
        }
    }

    Ok(())
}

struct CdEntry {
    #[allow(dead_code)]
    mode: u32,
    size: u64,
    name: String,
}

fn parse_cd_line(line: &str) -> Option<CdEntry> {
    // Format: "<octal-mode> <size> <name>", e.g. "0644 1234 hello.txt".
    let mut parts = line.splitn(3, ' ');
    let mode_str = parts.next()?;
    let size_str = parts.next()?;
    let name = parts.next()?.to_string();
    let mode = u32::from_str_radix(mode_str, 8).unwrap_or(0o644);
    let size = size_str.parse::<u64>().ok()?;
    Some(CdEntry { mode, size, name })
}

/// Decide where to write `name` given the original target and current dir stack.
fn current_dest(target: &Path, dir_stack: &[PathBuf], name: &str) -> PathBuf {
    if let Some(top) = dir_stack.last() {
        // Inside a directory we created: always join the name.
        top.join(name)
    } else if target_is_existing_dir(target) {
        target.join(name)
    } else {
        // Target does not exist or is a file: use the target path as-is for a
        // single file upload, or join for directory mode.
        target.to_path_buf()
    }
}

fn target_is_existing_dir(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// Read exactly `size` bytes of file content, then the trailing status byte,
/// write the content to `dest`, and ack.
async fn receive_file<S>(stream: &mut S, dest: &Path, size: u64) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
    }

    let mut file = match tokio::fs::File::create(dest).await {
        Ok(f) => f,
        Err(e) => {
            // Still drain the bytes so the protocol stays in sync.
            drain(stream, size).await?;
            // consume trailing status byte
            let mut b = [0u8; 1];
            let _ = stream.read_exact(&mut b).await;
            send_error(stream, &format!("create failed: {e}"), false).await?;
            return Ok(());
        }
    };

    let mut remaining = size;
    let mut buf = vec![0u8; 32 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = stream.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(io_err("unexpected EOF while reading file body"));
        }
        file.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    file.flush().await?;

    // Read the trailing status byte sent by the client after the file body.
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    if status[0] != OK {
        let msg = read_line(stream).await?;
        send_error(stream, &format!("transfer error: {msg}"), false).await?;
        return Ok(());
    }

    // Acknowledge successful receipt.
    send_ok(stream).await
}

async fn drain<R: AsyncRead + Unpin>(r: &mut R, mut n: u64) -> std::io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    while n > 0 {
        let want = n.min(buf.len() as u64) as usize;
        let got = r.read(&mut buf[..want]).await?;
        if got == 0 {
            break;
        }
        n -= got as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Source: server sends files to the client (`scp -f <path>` / `scp -rf`).
// ---------------------------------------------------------------------------

/// Run the SCP source protocol, sending the requested path to the client.
pub async fn run_source<S>(stream: &mut S, cmd: &ScpCommand) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Wait for the client's initial OK.
    read_reply(stream).await?;

    let meta = match tokio::fs::metadata(&cmd.path).await {
        Ok(m) => m,
        Err(e) => {
            send_error(
                stream,
                &format!("{}: {}", cmd.path.display(), e),
                false,
            )
            .await?;
            return Ok(());
        }
    };

    if meta.is_dir() {
        if !cmd.recursive {
            send_error(
                stream,
                &format!("{}: not a regular file", cmd.path.display()),
                false,
            )
            .await?;
            return Ok(());
        }
        send_dir(stream, &cmd.path).await?;
    } else {
        let name = cmd
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_string();
        send_file(stream, &cmd.path, &name, meta.len()).await?;
    }

    Ok(())
}

/// Recursively send a directory.
fn send_dir<'a, S>(
    stream: &'a mut S,
    dir: &'a Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    Box::pin(async move {
        let dir_name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("dir")
            .to_string();

        // D<mode> 0 <name>
        let header = format!("D0755 0 {dir_name}\n");
        stream.write_all(header.as_bytes()).await?;
        stream.flush().await?;
        read_reply(stream).await?;

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let meta = entry.metadata().await?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                send_dir(stream, &path).await?;
            } else if meta.is_file() {
                send_file(stream, &path, &name, meta.len()).await?;
            }
        }

        // E
        stream.write_all(b"E\n").await?;
        stream.flush().await?;
        read_reply(stream).await?;
        Ok(())
    })
}

/// Send a single regular file.
async fn send_file<S>(
    stream: &mut S,
    path: &Path,
    name: &str,
    size: u64,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            send_error(stream, &format!("{}: {}", path.display(), e), false).await?;
            return Ok(());
        }
    };

    // C<mode> <size> <name>
    let header = format!("C0644 {size} {name}\n");
    stream.write_all(header.as_bytes()).await?;
    stream.flush().await?;
    read_reply(stream).await?;

    // File body.
    let mut remaining = size;
    let mut buf = vec![0u8; 32 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want]).await?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    stream.flush().await?;

    // Trailing OK byte to signal end of file body.
    send_ok(stream).await?;
    // Read the client's acknowledgement.
    read_reply(stream).await?;
    Ok(())
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}
