//! Session regressions. Each test starts its own server on an ephemeral port
//! with a throwaway host key, so nothing is written next to the executable.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::client::Handle;
use russh::ChannelMsg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use super::AppConfig;
use super::AppServer;

/// Capacity of the server channel queue under test. The interactive shell must
/// discard that copy of each keystroke; otherwise the session blocks here.
const CHANNEL_QUEUE_CAPACITY: usize = 100;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

type ClientHandle = Handle<AcceptAll>;
type ClientChannel = russh::Channel<russh::client::Msg>;

struct AcceptAll;

impl russh::client::Handler for AcceptAll {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Running {
    addr: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn client_config() -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(120)),
        nodelay: true,
        ..Default::default()
    })
}

async fn start_server() -> Result<Running> {
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(120)),
        auth_rejection_time: Duration::from_millis(20),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        channel_buffer_size: CHANNEL_QUEUE_CAPACITY,
        nodelay: true,
        keys: vec![key],
        ..Default::default()
    });
    let mut server = AppServer {
        config: Arc::new(AppConfig {
            username: "admin".into(),
            password: "password".into(),
        }),
    };
    let task = tokio::spawn(async move {
        use russh::server::Server as _;
        let _ = server.run_on_socket(config, &listener).await;
    });
    Ok(Running { addr, task })
}

async fn handshake(addr: std::net::SocketAddr) -> Result<ClientHandle> {
    let mut last_error = None;
    for _ in 0..50 {
        match russh::client::connect(client_config(), addr, AcceptAll).await {
            Ok(session) => return Ok(session),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    let error = last_error.expect("connect was retried");
    bail!("connecting to the test server: {error}")
}

async fn connect(addr: std::net::SocketAddr) -> Result<ClientHandle> {
    let mut session = handshake(addr).await?;
    let auth = session.authenticate_password("admin", "password").await?;
    if !auth.success() {
        bail!("password authentication failed");
    }
    Ok(session)
}

/// ConPTY sessions are unhappy in parallel. Exec tests do not take this.
fn shell_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Mutex::new(()))
}

struct CommandOutput {
    stdout: String,
    stderr: String,
    code: u32,
}

impl CommandOutput {
    fn summary(&self) -> String {
        format!(
            "exit {} stdout {:?} stderr {:?}",
            self.code, self.stdout, self.stderr
        )
    }
}

async fn exec(session: &ClientHandle, command: &str) -> Result<CommandOutput> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command.as_bytes()).await?;
    finish_exec(&mut channel, COMMAND_TIMEOUT).await
}

async fn exec_with_stdin(
    session: &ClientHandle,
    command: &str,
    stdin: &[u8],
) -> Result<CommandOutput> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command.as_bytes()).await?;
    channel.data_bytes(stdin.to_vec()).await?;
    channel.eof().await?;
    finish_exec(&mut channel, COMMAND_TIMEOUT).await
}

async fn finish_exec(channel: &mut ClientChannel, timeout: Duration) -> Result<CommandOutput> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => stdout.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExtendedData { data, .. })) => stderr.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                return Ok(CommandOutput {
                    stdout: String::from_utf8_lossy(&stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&stderr).into_owned(),
                    code: exit_status,
                });
            }
            Ok(Some(ChannelMsg::Close)) | Ok(None) => {
                bail!(
                    "channel closed without an exit status; stdout {:?} stderr {:?}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
            }
            Ok(Some(_)) => {}
            Err(_) => break,
        }
    }
    bail!(
        "timed out waiting for exit status; stdout {:?} stderr {:?}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
}

/// File name contains a space, so a cmd redirect that splits on whitespace
/// never creates it. russh drops a client channel on close, so these tests
/// watch the file instead of the exit status.
const HEARTBEAT_NAME: &str = "beat file.txt";

/// Rewrites `path` about once a second until the channel closes.
///
/// A `"` inside the `cmd /C` argument becomes `\"` after Rust quotes it, and
/// cmd then rejects the redirect. A caret keeps the next character, including
/// spaces, as part of the path.
fn heartbeat_command(path: &Path) -> String {
    let path = path.display().to_string();
    if cfg!(windows) {
        format!(
            "for /L %i in (1,1,30) do @echo %i>{} & ping -n 2 127.0.0.1 >nul",
            cmd_escape(&path)
        )
    } else {
        format!(
            "i=0; while [ \"$i\" -lt 30 ]; do i=$((i+1)); echo \"$i\" > '{path}'; sleep 1; done"
        )
    }
}

/// Escape a cmd metacharacter so it stays inside the redirection target.
///
/// Kept on every target: `if cfg!(windows)` still type-checks the Windows
/// branch when cross-compiling, so this function must exist there too.
fn cmd_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, ' ' | '&' | '(' | ')' | '^' | '<' | '>' | '|') {
            escaped.push('^');
        }
        escaped.push(c);
    }
    escaped
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("command did not start writing {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_until_rewritten(path: &Path, previous: &[u8], timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if !bytes.is_empty() && bytes != previous {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "command stopped writing before close: {:?}",
                String::from_utf8_lossy(previous)
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn assert_writes_stopped(path: &Path) -> Result<()> {
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mid = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if mid != after {
        bail!(
            "command kept writing after the channel closed: {:?} -> {:?}",
            String::from_utf8_lossy(&mid),
            String::from_utf8_lossy(&after)
        );
    }
    Ok(())
}

fn newline() -> &'static str {
    if cfg!(windows) {
        "\r\n"
    } else {
        "\n"
    }
}

fn cwd_command() -> &'static str {
    if cfg!(windows) {
        "cd"
    } else {
        "pwd"
    }
}

fn term_command() -> &'static str {
    if cfg!(windows) {
        "echo %TERM%"
    } else {
        r#"printf '%s\n' "$TERM""#
    }
}

struct Shell {
    input: Option<mpsc::UnboundedSender<Vec<u8>>>,
    output: mpsc::UnboundedReceiver<Vec<u8>>,
    exit: Option<oneshot::Receiver<Option<u32>>>,
    buffered: Vec<u8>,
    sent: Arc<AtomicUsize>,
}

impl Shell {
    async fn open(session: &ClientHandle, term: &str) -> Result<Self> {
        let mut channel = session.channel_open_session().await?;
        channel
            .request_pty(true, term, 80, 24, 0, 0, &[] as &[(russh::Pty, u32)])
            .await?;
        channel.request_shell(true).await?;

        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (output_tx, output_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (exit_tx, exit_rx) = oneshot::channel();
        let sent = Arc::new(AtomicUsize::new(0));
        let sent_task = Arc::clone(&sent);

        tokio::spawn(async move {
            let mut exit_tx = Some(exit_tx);
            let mut tail = Vec::new();
            let mut input_open = true;
            loop {
                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data })
                            | Some(ChannelMsg::ExtendedData { data, .. }) => {
                                if take_cursor_query(&mut tail, &data) {
                                    let _ = channel.data_bytes(b"\x1b[1;1R".to_vec()).await;
                                }
                                if output_tx.send(data.to_vec()).is_err() {
                                    break;
                                }
                            }
                            Some(ChannelMsg::ExitStatus { exit_status }) => {
                                if let Some(tx) = exit_tx.take() {
                                    let _ = tx.send(Some(exit_status));
                                }
                            }
                            Some(ChannelMsg::Eof) => {}
                            Some(ChannelMsg::Close) | None => break,
                            Some(_) => {}
                        }
                    }
                    incoming = input_rx.recv(), if input_open => {
                        match incoming {
                            Some(bytes) => {
                                if channel.data_bytes(bytes).await.is_err() {
                                    break;
                                }
                                sent_task.fetch_add(1, Ordering::Relaxed);
                            }
                            None => {
                                input_open = false;
                                if channel.close().await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if let Some(tx) = exit_tx {
                let _ = tx.send(None);
            }
        });

        Ok(Self {
            input: Some(input_tx),
            output: output_rx,
            exit: Some(exit_rx),
            buffered: Vec::new(),
            sent,
        })
    }

    fn send(&self, bytes: impl Into<Vec<u8>>) {
        if let Some(input) = &self.input {
            let _ = input.send(bytes.into());
        }
    }

    fn send_line(&self, line: &str) {
        self.send(format!("{line}{}", newline()));
    }

    fn drain(&mut self) {
        while let Ok(chunk) = self.output.try_recv() {
            self.buffered.extend_from_slice(&chunk);
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.buffered).into_owned()
    }

    async fn wait_for_output(&mut self, timeout: Duration) -> bool {
        if !self.buffered.is_empty() {
            return true;
        }
        match tokio::time::timeout(timeout, self.output.recv()).await {
            Ok(Some(chunk)) => {
                self.buffered.extend_from_slice(&chunk);
                !self.buffered.is_empty()
            }
            _ => false,
        }
    }

    /// `Ok` means an exit was already reported. The status is consumed.
    fn exited(&mut self) -> bool {
        let Some(exit) = self.exit.as_mut() else {
            return true;
        };
        match exit.try_recv() {
            Ok(_) => true,
            Err(oneshot::error::TryRecvError::Empty) => false,
            Err(oneshot::error::TryRecvError::Closed) => true,
        }
    }

    async fn read_until(&mut self, needle: &str, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let needle_bytes = needle.as_bytes();
        loop {
            if !needle_bytes.is_empty()
                && self
                    .buffered
                    .windows(needle_bytes.len())
                    .any(|window| window == needle_bytes)
            {
                return Ok(self.text());
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                bail!("timed out waiting for {needle:?} in {:?}", self.text());
            }
            match tokio::time::timeout(left, self.output.recv()).await {
                Ok(Some(chunk)) => self.buffered.extend_from_slice(&chunk),
                Ok(None) => bail!("shell output ended before {needle:?} in {:?}", self.text()),
                Err(_) => bail!("timed out waiting for {needle:?} in {:?}", self.text()),
            }
        }
    }

    async fn wait_until_sent(&self, count: usize, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.sent.load(Ordering::Relaxed) >= count {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "sent {} of {count} shell inputs before the channel stalled",
                    self.sent.load(Ordering::Relaxed)
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_exit(mut self, timeout: Duration) -> Result<(String, u32)> {
        let exit = self.exit.take().expect("shell exit receiver");
        let waited = tokio::time::timeout(timeout, exit).await;
        self.drain();
        let text = self.text();
        match waited {
            Ok(Ok(Some(code))) => Ok((text, code)),
            Ok(Ok(None)) => bail!("shell channel closed without an exit status; output: {text}"),
            Ok(Err(_)) => bail!("shell driver ended before an exit status; output: {text}"),
            Err(_) => bail!("timed out waiting for shell exit status; output: {text}"),
        }
    }

    fn request_close(&mut self) {
        self.input.take();
    }
}

/// ConPTY asks for the cursor with ESC [ 6 n. The four bytes may be split, so
/// the last three stay in `tail` for the next chunk.
fn take_cursor_query(tail: &mut Vec<u8>, chunk: &[u8]) -> bool {
    tail.extend_from_slice(chunk);
    let saw = tail.windows(4).any(|window| window == b"\x1b[6n");
    let extra = tail.len().saturating_sub(3);
    if extra > 0 {
        tail.drain(..extra).for_each(drop);
    }
    saw
}

fn dir_needle(path: &Path) -> String {
    let mut text = path.display().to_string();
    if text.len() > 3 {
        while text.ends_with('\\') || text.ends_with('/') {
            text.pop();
        }
    }
    text
}

fn same_directory(printed: &str, cwd: &Path) -> bool {
    let line = printed.lines().next().unwrap_or(printed).trim();
    if line.is_empty() {
        return false;
    }
    let printed_path = Path::new(line);
    if printed_path == cwd {
        return true;
    }
    if let (Ok(left), Ok(right)) = (printed_path.canonicalize(), cwd.canonicalize()) {
        if left == right {
            return true;
        }
    }
    dir_needle(printed_path).eq_ignore_ascii_case(&dir_needle(cwd))
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("sshd-standalone-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scp_command(flags: &str, path: &Path) -> String {
    let text = path.to_string_lossy();
    format!("scp {flags} {}", shell_words::quote(text.as_ref()))
}

async fn open_scp(
    session: &ClientHandle,
    flags: &str,
    path: &Path,
) -> Result<impl AsyncRead + AsyncWrite + Unpin> {
    let channel = session.channel_open_session().await?;
    channel.exec(true, scp_command(flags, path)).await?;
    Ok(channel.into_stream())
}

async fn read_ok<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;
    if byte[0] == 0 {
        return Ok(());
    }
    let line = read_line(stream).await?;
    bail!("scp server error: {line}")
}

async fn read_line<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn scp_upload_bytes(
    session: &ClientHandle,
    remote_path: &Path,
    name: &str,
    content: &[u8],
) -> Result<()> {
    let mut stream = open_scp(session, "-t", remote_path).await?;
    read_ok(&mut stream).await?;
    upload_scp_file(&mut stream, name, content).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn upload_scp_file<S>(stream: &mut S, name: &str, content: &[u8]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header = format!("C0644 {} {name}\n", content.len());
    stream.write_all(header.as_bytes()).await?;
    stream.flush().await?;
    read_ok(stream).await?;
    stream.write_all(content).await?;
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    read_ok(stream).await
}

async fn scp_upload_tree(session: &ClientHandle, remote_dir: &Path) -> Result<()> {
    let mut stream = open_scp(session, "-rt", remote_dir).await?;
    read_ok(&mut stream).await?;
    stream.write_all(b"D0755 0 mydir\n").await?;
    stream.flush().await?;
    read_ok(&mut stream).await?;
    upload_scp_file(&mut stream, "a.txt", b"alpha\n").await?;
    stream.write_all(b"D0755 0 sub\n").await?;
    stream.flush().await?;
    read_ok(&mut stream).await?;
    upload_scp_file(&mut stream, "b.txt", b"beta beta\n").await?;
    stream.write_all(b"E\n").await?;
    stream.flush().await?;
    read_ok(&mut stream).await?;
    stream.write_all(b"E\n").await?;
    stream.flush().await?;
    read_ok(&mut stream).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn scp_download_file(
    session: &ClientHandle,
    remote_path: &Path,
) -> Result<(String, Vec<u8>)> {
    let mut stream = open_scp(session, "-f", remote_path).await?;
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    let line = read_line(&mut stream).await?;
    if !line.starts_with('C') {
        bail!("expected scp C line, got {line:?}");
    }
    let mut parts = line[1..].splitn(3, ' ');
    let _mode = parts.next().unwrap_or("");
    let size: u64 = parts
        .next()
        .unwrap_or("0")
        .parse()
        .context("scp file size")?;
    let name = parts.next().unwrap_or("").to_string();
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    let mut body = vec![0u8; size as usize];
    stream.read_exact(&mut body).await?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    if status[0] != 0 {
        bail!("scp source status {}", status[0]);
    }
    stream.write_all(&[0]).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok((name, body))
}

async fn finish_shell_line(
    mut shell: Shell,
    needle: &str,
    timeout: Duration,
) -> Result<(String, u32)> {
    shell.read_until(needle, timeout).await?;
    shell.wait_exit(Duration::from_secs(10)).await
}

#[tokio::test]
async fn password_auth_accepts_the_configured_user() -> Result<()> {
    let server = start_server().await?;
    let mut session = handshake(server.addr).await?;
    let rejected = session.authenticate_password("admin", "wrong").await?;
    assert!(!rejected.success());
    let accepted = session.authenticate_password("admin", "password").await?;
    assert!(accepted.success());
    Ok(())
}

#[tokio::test]
async fn remote_exec_returns_stdout() -> Result<()> {
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let output = exec(&session, "echo hello-from-server").await?;
    assert_eq!(output.code, 0, "{}", output.summary());
    assert!(
        output.stdout.contains("hello-from-server"),
        "{}",
        output.summary()
    );
    Ok(())
}

#[tokio::test]
async fn remote_exec_reports_exit_code() -> Result<()> {
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let output = exec(&session, "exit 42").await?;
    assert_eq!(output.code, 42, "{}", output.summary());
    #[cfg(unix)]
    {
        let output = exec(&session, "kill -9 $$").await?;
        assert_eq!(output.code, 137, "{}", output.summary());
    }
    Ok(())
}

#[tokio::test]
async fn remote_exec_reads_stdin_until_eof() -> Result<()> {
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let command = if cfg!(windows) {
        "findstr stdin"
    } else {
        "cat"
    };
    let output = exec_with_stdin(&session, command, b"hello-stdin\n").await?;
    assert_eq!(output.code, 0, "{}", output.summary());
    assert!(
        output.stdout.contains("hello-stdin"),
        "{}",
        output.summary()
    );
    Ok(())
}

#[tokio::test]
async fn remote_exec_close_kills_the_child() -> Result<()> {
    let dir = TempDir::new();
    let beat = dir.path().join(HEARTBEAT_NAME);
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let channel = session.channel_open_session().await?;
    channel.exec(true, heartbeat_command(&beat)).await?;
    let first = wait_for_file(&beat, Duration::from_secs(8)).await?;
    wait_until_rewritten(&beat, &first, Duration::from_secs(4)).await?;
    channel.close().await?;
    assert_writes_stopped(&beat).await?;
    Ok(())
}

#[tokio::test]
async fn legacy_scp_round_trip() -> Result<()> {
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let dir = TempDir::new();
    let file_path = dir.path().join("uploaded.txt");
    let content = b"scp upload works\n";

    scp_upload_bytes(&session, &file_path, "uploaded.txt", content).await?;
    assert_eq!(
        std::fs::read(&file_path).with_context(|| format!("read {}", file_path.display()))?,
        content
    );

    let (name, downloaded) = scp_download_file(&session, &file_path).await?;
    assert_eq!(name, "uploaded.txt");
    assert_eq!(downloaded, content);

    scp_upload_tree(&session, dir.path()).await?;
    let alpha = dir.path().join("mydir").join("a.txt");
    let beta = dir.path().join("mydir").join("sub").join("b.txt");
    assert_eq!(
        std::fs::read(&alpha).with_context(|| format!("read {}", alpha.display()))?,
        b"alpha\n"
    );
    assert_eq!(
        std::fs::read(&beta).with_context(|| format!("read {}", beta.display()))?,
        b"beta beta\n"
    );
    Ok(())
}

#[tokio::test]
async fn shell_prints_client_term_or_the_safe_default() -> Result<()> {
    let _guard = shell_gate().lock().await;
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    assert_shell_term(&session, "tmux-256color", "tmux-256color").await?;
    assert_shell_term(&session, "a/b", "xterm-256color").await?;
    Ok(())
}

async fn assert_shell_term(session: &ClientHandle, requested: &str, expected: &str) -> Result<()> {
    let mut shell = Shell::open(session, requested).await?;
    let _ = shell.wait_for_output(Duration::from_secs(3)).await;
    shell.send_line(term_command());
    shell.send_line("exit");
    let (text, code) = finish_shell_line(shell, expected, Duration::from_secs(10)).await?;
    assert!(text.contains(expected), "term output {text:?}");
    assert_eq!(code, 0, "{text}");
    Ok(())
}

#[tokio::test]
async fn shell_and_exec_start_in_session_cwd() -> Result<()> {
    let cwd = super::session_cwd();
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let output = exec(&session, cwd_command()).await?;
    assert_eq!(output.code, 0, "{}", output.summary());
    assert!(
        same_directory(&output.stdout, &cwd),
        "exec started in {:?} instead of {}; {}",
        output.stdout,
        cwd.display(),
        output.summary()
    );

    let _guard = shell_gate().lock().await;
    let mut shell = Shell::open(&session, "xterm-256color").await?;
    let _ = shell.wait_for_output(Duration::from_secs(3)).await;
    shell.send_line(cwd_command());
    shell.send_line("exit");
    let (text, code) = finish_shell_line(shell, &dir_needle(&cwd), Duration::from_secs(10)).await?;
    assert_eq!(code, 0, "{text}");
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn unix_exec_receives_assembled_path() -> Result<()> {
    let expected = super::unix_path();
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let output = exec(&session, r#"printf %s "$PATH""#).await?;
    assert_eq!(output.code, 0, "{}", output.summary());
    assert_eq!(output.stdout, expected, "{}", output.summary());
    Ok(())
}

#[tokio::test]
async fn shell_exit_reports_status() -> Result<()> {
    let _guard = shell_gate().lock().await;
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let mut shell = Shell::open(&session, "xterm").await?;
    let _ = shell.wait_for_output(Duration::from_secs(3)).await;
    shell.send_line("echo shell-says-hi");
    shell.send_line("exit");
    let (text, code) = finish_shell_line(shell, "shell-says-hi", Duration::from_secs(10)).await?;
    assert!(text.contains("shell-says-hi"), "{text:?}");
    assert_eq!(code, 0, "{text}");
    Ok(())
}

/// Closing the channel must kill the live shell. Polling the finished channel
/// task again panics; Tokio reports that through the panic hook.
#[tokio::test]
async fn shell_channel_close_finishes_without_hanging() -> Result<()> {
    let _guard = shell_gate().lock().await;
    let panics = PanicWatch::arm();
    let dir = TempDir::new();
    let beat = dir.path().join(HEARTBEAT_NAME);
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let mut shell = Shell::open(&session, "xterm-256color").await?;
    let _ = shell.wait_for_output(Duration::from_secs(3)).await;
    shell.send_line(&heartbeat_command(&beat));
    let first = wait_for_file(&beat, Duration::from_secs(10)).await?;
    wait_until_rewritten(&beat, &first, Duration::from_secs(4)).await?;
    if shell.exited() {
        bail!("shell exited before the channel was closed");
    }
    shell.request_close();
    assert_writes_stopped(&beat).await?;
    panics.check()?;
    Ok(())
}

/// Unlike Shell, this client deliberately does not answer ESC[6n. Old conhost
/// must be able to start and exit without a cursor report from the SSH client.
#[cfg(windows)]
#[tokio::test]
async fn shell_starts_without_a_cursor_report_and_server_keeps_accepting() -> Result<()> {
    let _guard = shell_gate().lock().await;
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    for _ in 0..3 {
        let mut channel = session.channel_open_session().await?;
        channel
            .request_pty(true, "xterm", 200, 50, 0, 0, &[])
            .await?;
        channel.request_shell(true).await?;
        channel
            .data_bytes(b"echo NO_CURSOR_REPORT_OK\r\nexit 23\r\n".to_vec())
            .await?;
        let output = finish_exec(&mut channel, COMMAND_TIMEOUT).await?;
        assert_eq!(output.code, 23, "{}", output.summary());
        assert!(
            output.stdout.contains("NO_CURSOR_REPORT_OK"),
            "{}",
            output.summary()
        );
        let fresh = tokio::time::timeout(COMMAND_TIMEOUT, connect(server.addr)).await??;
        assert_eq!(exec(&fresh, "exit 0").await?.code, 0);
    }
    Ok(())
}

/// Keep the SSH output window small and stop consuming it while cmd floods
/// output. A four-thread blocking pool makes leaked readers visible quickly.
#[cfg(windows)]
#[test]
fn backpressured_shell_close_does_not_exhaust_the_blocking_pool() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()?
        .block_on(async {
            let _guard = shell_gate().lock().await;
            let server = start_server().await?;
            let config = Arc::new(russh::client::Config {
                inactivity_timeout: Some(Duration::from_secs(120)),
                nodelay: true,
                window_size: 4096,
                ..Default::default()
            });
            let mut session = russh::client::connect(config, server.addr, AcceptAll).await?;
            assert!(session.authenticate_password("admin", "password").await?.success());
            for _ in 0..12 {
                let cleanups = super::WINDOWS_PTY_CLEANUPS.load(Ordering::SeqCst);
                let mut channel = session.channel_open_session().await?;
                channel.request_pty(true, "xterm", 200, 50, 0, 0, &[]).await?;
                channel.request_shell(true).await?;
                channel.data_bytes(b"for /L %i in (1,1,1000000) do @echo 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n".to_vec()).await?;
                // Read once to establish that the shell started, then leave
                // output unread so SSH forwarding and the PTY pump back up.
                let _ = tokio::time::timeout(COMMAND_TIMEOUT, channel.wait()).await?;
                tokio::time::sleep(Duration::from_millis(300)).await;
                channel.close().await?;
                drop(channel);
                let deadline = tokio::time::Instant::now() + COMMAND_TIMEOUT;
                while super::WINDOWS_PTY_CLEANUPS.load(Ordering::SeqCst) == cleanups {
                    if tokio::time::Instant::now() >= deadline {
                        bail!("Windows PTY cleanup did not complete after backpressured channel close");
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let fresh = tokio::time::timeout(COMMAND_TIMEOUT, connect(server.addr)).await??;
                let output = tokio::time::timeout(COMMAND_TIMEOUT, exec(&fresh, "echo POOL_STILL_ALIVE")).await??;
                assert_eq!(output.code, 0, "{}", output.summary());
                assert!(output.stdout.contains("POOL_STILL_ALIVE"), "{}", output.summary());
            }
            Ok(())
        })
}

/// Records a panic from the shell task. The default Tokio runtime does not
/// fail a test when a spawned task panics.
struct PanicWatch {
    flag: Arc<AtomicBool>,
}

impl PanicWatch {
    fn arm() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_hook = Arc::clone(&flag);
        std::panic::set_hook(Box::new(move |info| {
            flag_hook.store(true, Ordering::SeqCst);
            eprintln!("task panic: {info}");
        }));
        Self { flag }
    }

    fn check(&self) -> Result<()> {
        if self.flag.load(Ordering::SeqCst) {
            bail!("a task panicked while closing the shell");
        }
        Ok(())
    }
}

impl Drop for PanicWatch {
    fn drop(&mut self) {
        // `take_hook` puts the default hook back.
        let _ = std::panic::take_hook();
    }
}

/// More separate data messages than the channel queue, then one marker after
/// the PTY has drained its own 32-slot queue. A session that stops draining
/// never runs the marker.
#[tokio::test]
async fn shell_accepts_more_keystrokes_than_the_channel_queue() -> Result<()> {
    let _guard = shell_gate().lock().await;
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let mut shell = Shell::open(&session, "xterm-256color").await?;
    if !shell.wait_for_output(Duration::from_secs(3)).await {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let burst = CHANNEL_QUEUE_CAPACITY + 50;
    for _ in 0..burst {
        shell.send(vec![b' ']);
    }
    shell
        .wait_until_sent(burst, Duration::from_secs(10))
        .await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    shell.send(newline().as_bytes().to_vec());
    shell.send_line("echo SHELL_STRESS_OK");
    shell.send_line("exit 0");
    let (text, code) = finish_shell_line(shell, "SHELL_STRESS_OK", Duration::from_secs(20)).await?;
    assert!(text.contains("SHELL_STRESS_OK"), "{text:?}");
    assert_eq!(code, 0, "{text}");
    Ok(())
}

#[tokio::test]
async fn sftp_canonicalize_and_another_session_works() -> Result<()> {
    let server = start_server().await?;
    let session = connect(server.addr).await?;
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;
    let path = sftp.canonicalize(".").await?;
    assert!(!path.is_empty(), "realpath returned an empty path");
    drop(sftp);
    let output = exec(&session, "echo hello-from-server").await?;
    assert_eq!(output.code, 0, "{}", output.summary());
    assert!(
        output.stdout.contains("hello-from-server"),
        "{}",
        output.summary()
    );
    Ok(())
}
