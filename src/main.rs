//! A small SSH server built on [`russh`] (0.61) that supports:
//!   * password authentication,
//!   * interactive shell (`ssh user@host`),
//!   * remote command execution (`ssh user@host -p 2222 <command>`),
//!   * SCP upload/download including recursive (`scp`, `scp -r`).
//!
//! Usage:
//!   cargo run -- [--port 2222] [--user admin] [--password secret]
//!
//! Defaults: 0.0.0.0:2222, user "admin", password "password".

mod scp;
mod sftp;

use std::collections::HashMap;
use std::sync::Arc;

use russh::server::{Auth, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh::Pty;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

/// Shared, immutable server configuration (credentials etc.).
#[derive(Clone)]
struct AppConfig {
    username: String,
    password: String,
}

/// The top-level server. Produces a fresh `ClientHandler` per connection.
#[derive(Clone)]
struct AppServer {
    config: Arc<AppConfig>,
}

impl russh::server::Server for AppServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> ClientHandler {
        if let Some(addr) = peer {
            log::info!("New connection from {addr}");
        }
        ClientHandler {
            config: self.config.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
            shell_stdin: Arc::new(Mutex::new(HashMap::new())),
            pty_size: Arc::new(Mutex::new(HashMap::new())),
            pty_master: Arc::new(Mutex::new(HashMap::new())),
            authed_user: None,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        log::warn!("Session error: {error:?}");
    }
}

/// Per-connection handler.
struct ClientHandler {
    config: Arc<AppConfig>,
    /// Open session channels, so `exec_request` can take ownership of the
    /// `Channel` to drive command/SCP IO in a spawned task.
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    /// For interactive shell channels: a sender that forwards client keystrokes
    /// (delivered via `data`) into the PTY master.
    shell_stdin: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// The requested PTY size per channel (set by `pty_request`).
    pty_size: Arc<Mutex<HashMap<ChannelId, PtySize>>>,
    /// The PTY master per shell channel, used to apply window resizes.
    pty_master: Arc<Mutex<HashMap<ChannelId, Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>>>>,
    authed_user: Option<String>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.config.username && password == self.config.password {
            log::info!("User '{user}' authenticated via password");
            self.authed_user = Some(user.to_string());
            Ok(Auth::Accept)
        } else {
            log::warn!("Failed password auth for user '{user}'");
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    /// Advertise that only password auth is offered.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::from(&[russh::MethodKind::Password][..])),
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Closing stdin lets the shell see EOF and exit on its own.
        self.shell_stdin.lock().await.remove(&channel);
        self.channels.lock().await.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_stdin.lock().await.remove(&channel);
        self.pty_size.lock().await.remove(&channel);
        self.pty_master.lock().await.remove(&channel);
        self.channels.lock().await.remove(&channel);
        Ok(())
    }

    /// Client keystrokes / piped stdin arrive here. For an interactive shell we
    /// forward them to the PTY master (which echoes and feeds the shell).
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.shell_stdin.lock().await.get(&channel) {
            // Ignore send errors: the shell may have already exited.
            let _ = tx.send(data.to_vec());
        }
        Ok(())
    }

    /// Record the requested PTY size; the PTY itself is opened in `shell_request`.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        };
        self.pty_size.lock().await.insert(channel, size);
        session.channel_success(channel)?;
        Ok(())
    }

    /// Resize the PTY when the client's terminal window changes.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let size = PtySize {
            rows: if row_height == 0 { 24 } else { row_height as u16 },
            cols: if col_width == 0 { 80 } else { col_width as u16 },
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        };
        if let Some(master) = self.pty_master.lock().await.get(&channel) {
            let master = master.clone();
            // resize is a quick blocking ioctl; run it on a blocking thread.
            let _ = tokio::task::spawn_blocking(move || {
                if let Ok(m) = master.lock() {
                    let _ = m.resize(size);
                }
            })
            .await;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        log::info!("exec request on {channel_id:?}: {command}");

        // Take ownership of the channel so we can run IO in a background task.
        let channel = match self.channels.lock().await.remove(&channel_id) {
            Some(c) => c,
            None => {
                session.channel_failure(channel_id)?;
                return Ok(());
            }
        };

        // Tell the client the exec request itself succeeded.
        session.channel_success(channel_id)?;

        let handle = session.handle();

        tokio::spawn(async move {
            let exit_code = if let Some(scp_cmd) = scp::parse_scp_command(&command) {
                run_scp(channel, scp_cmd).await
            } else {
                run_command(channel, &command).await
            };

            // Report exit status and close the channel.
            let _ = handle.exit_status_request(channel_id, exit_code).await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;
        });

        Ok(())
    }

    /// Handle a subsystem request. Modern OpenSSH clients use the `sftp`
    /// subsystem for `scp` (unless `-O` forces the legacy SCP protocol), so we
    /// run a real SFTP server here. Without this, plain `scp`/`sftp` hang.
    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::info!("subsystem request on {channel_id:?}: {name}");

        if name == "sftp" {
            let channel = match self.channels.lock().await.remove(&channel_id) {
                Some(c) => c,
                None => {
                    session.channel_failure(channel_id)?;
                    return Ok(());
                }
            };

            // Acknowledge the subsystem request, then hand the channel's byte
            // stream to the SFTP server. `russh_sftp::server::run` spawns its
            // own task that owns the stream and runs until the client sends
            // EOF; it must NOT be followed by closing the channel here (doing
            // so would tear down the session right after SSH_FXP_INIT).
            session.channel_success(channel_id)?;

            let sftp = sftp::SftpSession::default();
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            log::warn!("unsupported subsystem: {name}");
            session.channel_failure(channel_id)?;
        }

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Take ownership of the channel for the interactive session.
        let channel = match self.channels.lock().await.remove(&channel_id) {
            Some(c) => c,
            None => {
                session.channel_failure(channel_id)?;
                return Ok(());
            }
        };

        // Use the size requested via pty_request, or a sane default.
        let mut size = self
            .pty_size
            .lock()
            .await
            .get(&channel_id)
            .copied()
            .unwrap_or(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            });
        // A 0x0 size is invalid for ConPTY and some Unix PTYs; clamp it.
        if size.rows == 0 {
            size.rows = 24;
        }
        if size.cols == 0 {
            size.cols = 80;
        }

        // Open a real PTY and spawn the shell on its slave end.
        let pty_pair = match native_pty_system().openpty(size) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("failed to open PTY: {e}");
                let _ = session.channel_failure(channel_id);
                return Ok(());
            }
        };

        let mut cmd = build_shell_command();
        let child = match pty_pair.slave.spawn_command(cmd_take(&mut cmd)) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("failed to spawn shell: {e}");
                let _ = session.channel_failure(channel_id);
                return Ok(());
            }
        };
        // The slave handle is no longer needed in this process once the child
        // owns it; dropping it avoids holding an extra fd.
        drop(pty_pair.slave);

        let master = Arc::new(std::sync::Mutex::new(pty_pair.master));
        self.pty_master
            .lock()
            .await
            .insert(channel_id, master.clone());

        session.channel_success(channel_id)?;

        // Channel to forward client keystrokes into the PTY master.
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.shell_stdin.lock().await.insert(channel_id, tx);

        let handle = session.handle();
        let shell_stdin = self.shell_stdin.clone();
        let pty_master = self.pty_master.clone();

        tokio::spawn(async move {
            let exit_code = run_pty_shell(channel, rx, master, child).await;
            shell_stdin.lock().await.remove(&channel_id);
            pty_master.lock().await.remove(&channel_id);
            let _ = handle.exit_status_request(channel_id, exit_code).await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;
        });

        Ok(())
    }
}

/// Build the shell `CommandBuilder` for the current platform.
fn build_shell_command() -> CommandBuilder {
    #[cfg(windows)]
    {
        CommandBuilder::new("cmd.exe")
    }
    #[cfg(not(windows))]
    {
        // Prefer the Android system shell location, falling back to `sh` on PATH.
        let shell = if std::path::Path::new("/system/bin/sh").exists() {
            "/system/bin/sh"
        } else {
            "sh"
        };
        let mut cmd = CommandBuilder::new(shell);
        cmd.arg("-i");
        // Make interactive tools behave.
        cmd.env("TERM", "xterm-256color");
        cmd
    }
}

/// `spawn_command` consumes the builder by value; this helper moves it out of a
/// `&mut` binding (CommandBuilder is Clone, so we just clone it).
fn cmd_take(cmd: &mut CommandBuilder) -> CommandBuilder {
    cmd.clone()
}

/// Run an interactive shell over a real PTY, bridging the SSH channel.
///
/// * client keystrokes (via `stdin_rx`) -> PTY master writer
/// * PTY master reader -> SSH channel data
async fn run_pty_shell(
    channel: Channel<Msg>,
    mut stdin_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    master: Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>,
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
) -> u32 {
    use tokio::io::AsyncWriteExt;
    use std::io::{Read, Write};

    // Obtain a blocking reader and writer from the PTY master.
    let reader = match master.lock().ok().and_then(|m| m.try_clone_reader().ok()) {
        Some(r) => r,
        None => {
            let _ = channel
                .data_bytes(b"failed to obtain PTY reader\r\n".to_vec())
                .await;
            return 1;
        }
    };
    let writer = match master.lock().ok().and_then(|m| m.take_writer().ok()) {
        Some(w) => w,
        None => {
            let _ = channel
                .data_bytes(b"failed to obtain PTY writer\r\n".to_vec())
                .await;
            return 1;
        }
    };

    // Bridge PTY output -> SSH channel via a bounded async hand-off.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader_thread = std::thread::spawn(move || {
        let mut reader = reader;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task: forward PTY output to the SSH channel.
    let mut ch_writer = channel.make_writer();
    let out_task = tokio::spawn(async move {
        while let Some(chunk) = out_rx.recv().await {
            if ch_writer.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = ch_writer.flush().await;
        }
    });

    // Bridge SSH input -> PTY writer on a blocking thread.
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writer_thread = std::thread::spawn(move || {
        let mut writer = writer;
        while let Ok(bytes) = in_rx.recv() {
            if writer.write_all(&bytes).is_err() {
                break;
            }
            let _ = writer.flush();
        }
        // Dropping the writer sends EOF to the shell.
    });

    // Task: pull keystrokes off the async mpsc and push to the blocking writer.
    let in_task = tokio::spawn(async move {
        while let Some(bytes) = stdin_rx.recv().await {
            if in_tx.send(bytes).is_err() {
                break;
            }
        }
        // Closing in_tx ends writer_thread.
    });

    // Wait for the child to exit on a blocking thread.
    let exit = tokio::task::spawn_blocking(move || {
        let status = child.wait();
        status.map(|s| s.exit_code()).unwrap_or(1)
    })
    .await
    .unwrap_or(1);

    // The child has exited: stop stdin forwarding first so PTY writer drops.
    // On some PTY backends, waiting for output before dropping input can hang
    // channel teardown after typing `exit`.
    in_task.abort();
    let _ = in_task.await;
    let _ = writer_thread.join();

    // Drain any final PTY output, but never block indefinitely.
    match tokio::time::timeout(std::time::Duration::from_millis(500), out_task).await {
        Ok(joined) => {
            let _ = joined;
        }
        Err(_) => {
            // Reader may be stuck in a backend-specific blocking read; detaching
            // avoids wedging SSH channel close.
        }
    }

    // Do not join `reader_thread`: if backend read blocks forever, joining here
    // would deadlock `shell_request` completion and the client would hang.
    drop(reader_thread);

    exit
}

/// Run the SCP protocol over the channel. Returns an exit code.
async fn run_scp(channel: Channel<Msg>, cmd: scp::ScpCommand) -> u32 {
    let mut stream = channel.into_stream();
    let result = if cmd.source {
        scp::run_source(&mut stream, &cmd).await
    } else if cmd.sink {
        scp::run_sink(&mut stream, &cmd).await
    } else {
        // Neither -f nor -t: nothing sensible to do.
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "scp invoked without -f or -t",
        ))
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            log::warn!("scp error: {e}");
            1
        }
    }
}

/// Execute a shell command and stream stdout/stderr to the client.
/// Returns the process exit code.
async fn run_command(channel: Channel<Msg>, command: &str) -> u32 {
    use tokio::process::Command;

    // Spawn the command through the platform shell.
    #[cfg(windows)]
    let spawned = Command::new("cmd")
        .arg("/C")
        .arg(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    #[cfg(not(windows))]
    let spawned = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let _ = channel
                .data_bytes(format!("failed to spawn command: {e}\r\n").into_bytes())
                .await;
            return 127;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let writer = channel.make_writer();
    let writer_err = channel.make_writer_ext(Some(1)); // ext code 1 = stderr

    // Pump stdout -> channel data, stderr -> channel extended data.
    let out_task = tokio::spawn(pump(stdout, writer));
    let err_task = tokio::spawn(pump(stderr, writer_err));

    let status = child.wait().await;
    let _ = out_task.await;
    let _ = err_task.await;

    match status {
        Ok(s) => s.code().unwrap_or(0) as u32,
        Err(_) => 1,
    }
}

/// Copy all bytes from an optional async reader into an async writer.
async fn pump<R, W>(reader: Option<R>, mut writer: W)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Some(mut reader) = reader {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = writer.flush().await;
        let _ = writer.shutdown().await;
    }
}

fn parse_args() -> (String, u16, String, String, String) {
    let mut host = "0.0.0.0".to_string();
    let mut port: u16 = 2222;
    let mut user = "admin".to_string();
    let mut password = "password".to_string();
    let mut host_key = "host_key".to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = args.next().unwrap_or(host),
            "--port" => port = args.next().and_then(|s| s.parse().ok()).unwrap_or(port),
            "--user" => user = args.next().unwrap_or(user),
            "--password" => password = args.next().unwrap_or(password),
            "--host-key" => host_key = args.next().unwrap_or(host_key),
            "-h" | "--help" => {
                println!(
                    "Usage: sshd_simple [--host 0.0.0.0] [--port 2222] [--user admin] [--password password] [--host-key host_key]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
            }
        }
    }
    (host, port, user, password, host_key)
}

/// Load the server's host key from `path`, or generate and persist a new
/// Ed25519 key there if the file does not exist yet. Persisting the key keeps
/// the server's identity stable across restarts so clients don't get the
/// "REMOTE HOST IDENTIFICATION HAS CHANGED" warning.
fn load_or_create_host_key(path: &str) -> anyhow::Result<russh::keys::PrivateKey> {
    use russh::keys::ssh_key::LineEnding;

    if std::path::Path::new(path).exists() {
        let key = russh::keys::load_secret_key(path, None)
            .map_err(|e| anyhow::anyhow!("failed to load host key '{path}': {e}"))?;
        log::info!("Loaded host key from {path}");
        Ok(key)
    } else {
        let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
        key.write_openssh_file(std::path::Path::new(path), LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("failed to write host key '{path}': {e}"))?;
        // Best-effort: tighten permissions on Unix (ignored on Windows).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        log::info!("Generated new host key and saved to {path}");
        Ok(key)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (host, port, username, password, host_key_path) = parse_args();

    // Load a persistent host key (generate + save on first run).
    let host_key = load_or_create_host_key(&host_key_path)?;

    let russh_config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(2),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    };

    let mut server = AppServer {
        config: Arc::new(AppConfig { username, password }),
    };

    let listener = TcpListener::bind((host.as_str(), port)).await?;
    log::info!("SSH server listening on {host}:{port}");
    log::info!(
        "Login with: ssh {}@{} -p {}",
        server.config.username,
        if host == "0.0.0.0" { "127.0.0.1" } else { &host },
        port
    );

    server
        .run_on_socket(Arc::new(russh_config), &listener)
        .await?;
    Ok(())
}
