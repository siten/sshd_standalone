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

/// Shared PTY master handle for a shell channel.
type PtyMasterHandle = Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>;

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
            requested_pty: Arc::new(Mutex::new(HashMap::new())),
            pty_master: Arc::new(Mutex::new(HashMap::new())),
            authed_user: None,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        log::warn!("Session error: {error:?}");
    }
}

/// `pty-req` parameters. The PTY is opened later, in `shell_request`.
#[derive(Clone)]
struct RequestedPty {
    size: PtySize,
    term: String,
}

/// Per-connection handler.
struct ClientHandler {
    config: Arc<AppConfig>,
    /// Open session channels, so `exec_request` can take ownership of the
    /// `Channel` to drive command/SCP IO in a spawned task.
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    /// Interactive keystrokes. Bounded so `data` can use `try_send` and never
    /// block the session loop.
    shell_stdin: Arc<Mutex<HashMap<ChannelId, mpsc::Sender<Vec<u8>>>>>,
    /// Client terminal name and window size from `pty-req`.
    requested_pty: Arc<Mutex<HashMap<ChannelId, RequestedPty>>>,
    /// The PTY master per shell channel, used to apply window resizes.
    pty_master: Arc<Mutex<HashMap<ChannelId, PtyMasterHandle>>>,
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
        self.requested_pty.lock().await.remove(&channel);
        self.pty_master.lock().await.remove(&channel);
        self.channels.lock().await.remove(&channel);
        Ok(())
    }

    /// Interactive keystrokes. russh also queues the same bytes on the channel;
    /// the shell task discards that copy. `try_send` drops a chunk when the PTY
    /// is not reading, so this handler does not stall the session loop.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let tx = self.shell_stdin.lock().await.get(&channel).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(data.to_vec());
        }
        Ok(())
    }

    /// Record the client terminal name and size. The PTY is opened in `shell_request`.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.requested_pty.lock().await.insert(
            channel,
            RequestedPty {
                size: PtySize {
                    rows: row_height as u16,
                    cols: col_width as u16,
                    pixel_width: pix_width as u16,
                    pixel_height: pix_height as u16,
                },
                term: term.to_string(),
            },
        );
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
        let size = clamp_pty_size(PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        });
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

            // Acknowledge the subsystem request, then hand the channel stream
            // to the SFTP server. It runs in its own task; the wrapper maps
            // SSH disconnect errors to EOF so that task exits instead of
            // retrying a reset stream indefinitely.
            session.channel_success(channel_id)?;

            let sftp = sftp::SftpSession::default();
            sftp::run(channel.into_stream(), sftp).await;
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

        let requested = self.requested_pty.lock().await.get(&channel_id).cloned();
        let size = clamp_pty_size(requested.as_ref().map(|pty| pty.size).unwrap_or(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        }));
        let term = requested.map(|pty| pty.term).unwrap_or_default();

        // Open a real PTY and spawn the shell on its slave end.
        let pty_pair = match native_pty_system().openpty(size) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("failed to open PTY: {e}");
                let _ = session.channel_failure(channel_id);
                return Ok(());
            }
        };

        let child = match pty_pair.slave.spawn_command(build_shell_command(&term)) {
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

        let (tx, rx) = mpsc::channel::<Vec<u8>>(IO_CHUNKS);
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

/// ConPTY and some Unix PTYs reject a 0x0 size.
fn clamp_pty_size(mut size: PtySize) -> PtySize {
    if size.rows == 0 {
        size.rows = 24;
    }
    if size.cols == 0 {
        size.cols = 80;
    }
    size
}

trait CommandEnv {
    fn set_env(&mut self, key: &str, value: &str);
    fn set_cwd(&mut self, dir: &std::path::Path);
}

impl CommandEnv for CommandBuilder {
    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn set_cwd(&mut self, dir: &std::path::Path) {
        self.cwd(dir);
    }
}

impl CommandEnv for tokio::process::Command {
    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn set_cwd(&mut self, dir: &std::path::Path) {
        self.current_dir(dir);
    }
}

/// Use the client terminal name when it is a plain terminfo name.
fn shell_term(requested: &str) -> &str {
    let safe = !requested.is_empty()
        && requested.len() <= 128
        && requested
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'));
    if safe {
        requested
    } else {
        "xterm-256color"
    }
}

fn shell_program() -> &'static str {
    #[cfg(windows)]
    {
        "cmd.exe"
    }
    #[cfg(not(windows))]
    {
        unix_shell_path()
    }
}

/// Environment shared by the interactive shell and remote commands.
/// `term` is set only for a PTY shell. `PATH` and `SHELL` are Unix-only.
/// Both start in `session_cwd()`, which does not look up the SSH login name.
fn apply_session_env(cmd: &mut impl CommandEnv, term: Option<&str>) {
    if let Some(term) = term {
        cmd.set_env("TERM", shell_term(term));
    }
    #[cfg(not(windows))]
    {
        cmd.set_env("PATH", &unix_path());
        cmd.set_env("SHELL", unix_shell_path());
    }
    cmd.set_cwd(&session_cwd());
}

/// Directory for a new session. The SSH username may not exist on the target,
/// so this uses the process home when that directory is present, then a
/// directory that does not depend on a user account.
fn session_cwd() -> std::path::PathBuf {
    fn existing_var(name: &str) -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(std::env::var_os(name)?);
        path.is_dir().then_some(path)
    }

    #[cfg(windows)]
    if let Some(path) = existing_var("USERPROFILE") {
        return path;
    }
    if let Some(path) = existing_var("HOME") {
        return path;
    }
    first_existing_dir(session_cwd_fallbacks())
}

fn session_cwd_fallbacks() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &[r"C:\"]
    }
    #[cfg(not(windows))]
    {
        &["/"]
    }
}

/// First candidate that can be opened as a directory. The login name is not
/// consulted; a missing or inaccessible path is skipped.
fn first_existing_dir(candidates: &[&str]) -> std::path::PathBuf {
    for dir in candidates {
        let path = std::path::PathBuf::from(dir);
        if path.is_dir() {
            return path;
        }
    }
    std::path::PathBuf::from(candidates.last().copied().unwrap_or("."))
}

/// Build the interactive shell for the current platform.
fn build_shell_command(term: &str) -> CommandBuilder {
    let mut cmd = CommandBuilder::new(shell_program());
    #[cfg(not(windows))]
    cmd.arg("-i");
    apply_session_env(&mut cmd, Some(term));
    cmd
}

/// Rootless Procursus and Android prefixes. A directory is added only when it
/// can be opened and the inherited PATH does not already name it.
#[cfg(not(windows))]
const PLATFORM_PATH_DIRS: &[&str] = &[
    "/var/jb/usr/local/sbin",
    "/var/jb/usr/local/bin",
    "/var/jb/usr/sbin",
    "/var/jb/usr/bin",
    "/var/jb/sbin",
    "/var/jb/bin",
    "/system/bin",
    "/system/xbin",
];

/// login(1) directories. Each one is appended when it can be opened, including
/// when the daemon already has a PATH, so a partial PATH still finds them.
/// Inaccessible entries are left out, so this does not depend on the uid.
#[cfg(not(windows))]
const FALLBACK_PATH_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// A non-login shell does not read `/etc/profile`, so the daemon supplies PATH.
/// Order: platform prefixes → inherited dirs → fallback dirs (all deduplicated).
#[cfg(not(windows))]
fn assemble_path<'a, F>(
    inherited: Option<&'a str>,
    platform: &[&'a str],
    fallback: &[&'a str],
    mut accessible: F,
) -> String
where
    F: FnMut(&str) -> bool,
{
    let inherited_dirs: Vec<&str> = inherited
        .into_iter()
        .flat_map(|path| path.split(':'))
        .filter(|dir| !dir.is_empty())
        .collect();

    let mut dirs: Vec<&str> = Vec::new();
    let mut push = |dir: &'a str| {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    };

    for dir in platform {
        if !inherited_dirs.contains(dir) && accessible(dir) {
            push(dir);
        }
    }
    for dir in inherited_dirs {
        push(dir);
    }
    // Always append fallback dirs so partially-inherited PATHs stay complete.
    for dir in fallback {
        if accessible(dir) {
            push(dir);
        }
    }
    dirs.join(":")
}

#[cfg(not(windows))]
fn unix_path() -> String {
    let inherited = std::env::var("PATH").ok().filter(|path| !path.is_empty());
    assemble_path(
        inherited.as_deref(),
        PLATFORM_PATH_DIRS,
        FALLBACK_PATH_DIRS,
        |dir| std::path::Path::new(dir).is_dir(),
    )
}

/// Find a shell. Missing files and access errors are skipped.
/// Full-featured shells come first. Minimal `sh` is only a last resort.
#[cfg(not(windows))]
fn unix_shell_path() -> &'static str {
    [
        // zsh: rootless iOS login shell, and the usual shell on macOS.
        "/var/jb/usr/bin/zsh",
        "/bin/zsh",
        "/usr/bin/zsh",
        "/usr/local/bin/zsh",
        // bash: usual full shell on Linux and rootful jailbreaks.
        "/var/jb/usr/bin/bash",
        "/bin/bash",
        "/usr/bin/bash",
        "/usr/local/bin/bash",
        // Android's own shell (mksh). Absent on the other platforms.
        "/system/bin/sh",
        // POSIX sh, including rootless dash. Enough to run a command.
        "/var/jb/bin/sh",
        "/var/jb/usr/bin/sh",
        "/bin/sh",
        "/usr/bin/sh",
        "/usr/local/bin/sh",
    ]
    .into_iter()
    .find(|path| std::path::Path::new(path).is_file())
    .unwrap_or("sh")
}

/// Chunks queued between the SSH channel and a pipe. Further input is dropped
/// so a client that keeps sending cannot stall the session loop.
const IO_CHUNKS: usize = 32;

/// Interactive shell on a PTY.
///
/// Keystrokes arrive on `stdin_rx`. Channel EOF drops that sender, the PTY
/// writer is dropped, and the shell sees EOF. Channel Close kills the child.
/// The channel receiver is drained until then so russh can keep reading.
async fn run_pty_shell(
    mut channel: Channel<Msg>,
    stdin_rx: mpsc::Receiver<Vec<u8>>,
    master: Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>,
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
) -> u32 {
    use std::io::Read;
    use tokio::io::AsyncWriteExt;

    let reader = match master.lock().ok().and_then(|m| m.try_clone_reader().ok()) {
        Some(reader) => reader,
        None => {
            let _ = channel
                .data_bytes(b"failed to obtain PTY reader\r\n".to_vec())
                .await;
            release_pty_child(child).await;
            return 1;
        }
    };
    let writer = match master.lock().ok().and_then(|m| m.take_writer().ok()) {
        Some(writer) => writer,
        None => {
            let _ = channel
                .data_bytes(b"failed to obtain PTY writer\r\n".to_vec())
                .await;
            release_pty_child(child).await;
            return 1;
        }
    };

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(IO_CHUNKS);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut reader = reader;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut ch_writer = channel.make_writer();
    let mut channel_task = tokio::spawn(async move {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    });
    let output_task = tokio::spawn(async move {
        while let Some(chunk) = out_rx.recv().await {
            if ch_writer.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = ch_writer.flush().await;
        }
    });
    let input_task = tokio::spawn(write_pty_input(stdin_rx, writer));

    let mut killer = child.clone_killer();
    let mut child_wait = tokio::task::spawn_blocking(move || {
        child.wait().map(|status| status.exit_code()).unwrap_or(1)
    });
    let exit = tokio::select! {
        biased;
        result = &mut child_wait => result.unwrap_or(1),
        _ = &mut channel_task => {
            let _ = killer.kill();
            child_wait.await.unwrap_or(1)
        }
    };

    // Drop the PTY writer before waiting on output. Some backends hang if the
    // writer is still open while output is drained after the shell exits.
    input_task.abort();
    let _ = input_task.await;
    // Close already completed this task inside `select`. Polling the same
    // JoinHandle again panics. When the child exits first, abort drops the
    // channel receiver so later client input cannot stall the session loop.
    if !channel_task.is_finished() {
        channel_task.abort();
        let _ = channel_task.await;
    }
    finish_pump(output_task).await;
    // A read stuck in the kernel is not cancelled. Stop waiting after a moment.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), reader_task).await;
    exit
}

async fn write_pty_input(
    mut stdin_rx: mpsc::Receiver<Vec<u8>>,
    mut writer: Box<dyn std::io::Write + Send>,
) {
    use std::io::Write;
    while let Some(bytes) = stdin_rx.recv().await {
        let written = tokio::task::spawn_blocking(move || {
            let ok = writer.write_all(&bytes).is_ok() && writer.flush().is_ok();
            (writer, ok)
        })
        .await;
        match written {
            Ok((restored, true)) => writer = restored,
            Ok((restored, false)) => {
                let _ = tokio::task::spawn_blocking(move || drop(restored)).await;
                return;
            }
            Err(_) => return,
        }
    }
    // Drop sends EOF to the shell. Do that off the runtime.
    let _ = tokio::task::spawn_blocking(move || drop(writer)).await;
}

async fn release_pty_child(mut child: Box<dyn portable_pty::Child + Send + Sync>) {
    let mut killer = child.clone_killer();
    let _ = killer.kill();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = child.wait();
    })
    .await;
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

/// Run one remote command. Stdin is the SSH channel. EOF closes that pipe.
/// Close kills the child. Stdout and stderr are separate tasks.
async fn run_command(mut channel: Channel<Msg>, command: &str) -> u32 {
    use tokio::process::Command;

    let mut cmd = Command::new(shell_program());
    #[cfg(windows)]
    cmd.arg("/C");
    #[cfg(not(windows))]
    cmd.arg("-c");
    cmd.arg(command);
    apply_session_env(&mut cmd, None);
    let spawned = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _ = channel
                .data_bytes(format!("failed to spawn command: {error}\r\n").into_bytes())
                .await;
            return 127;
        }
    };

    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_task = tokio::spawn(pump(stdout, channel.make_writer()));
    let err_task = tokio::spawn(pump(stderr, channel.make_writer_ext(Some(1))));
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(IO_CHUNKS);
    let mut stdin_tx = Some(stdin_tx);
    let stdin_task = tokio::spawn(write_command_stdin(stdin_rx, stdin));

    let exit_code = loop {
        tokio::select! {
            biased;
            status = child.wait() => {
                break match status {
                    Ok(status) => process_exit_code(status),
                    Err(_) => 1,
                };
            }
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        // `try_send` never waits. A full queue drops the chunk
                        // so this arm cannot hide Close behind a blocked write.
                        if let Some(tx) = stdin_tx.as_ref() {
                            let _ = tx.try_send(data.to_vec());
                        }
                    }
                    Some(russh::ChannelMsg::Eof) => {
                        stdin_tx.take();
                    }
                    Some(russh::ChannelMsg::Close) | None => {
                        stdin_tx.take();
                        let _ = child.start_kill();
                        break match child.wait().await {
                            Ok(status) => process_exit_code(status),
                            Err(_) => 1,
                        };
                    }
                    Some(_) => {}
                }
            }
        }
    };

    drop(stdin_tx);
    drop(channel);
    stdin_task.abort();
    let _ = stdin_task.await;
    finish_pump(out_task).await;
    finish_pump(err_task).await;
    exit_code
}

async fn write_command_stdin(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    mut stdin: Option<tokio::process::ChildStdin>,
) {
    use tokio::io::AsyncWriteExt;
    while let Some(data) = inbound.recv().await {
        let failed = match stdin.as_mut() {
            Some(writer) => writer.write_all(&data).await.is_err() || writer.flush().await.is_err(),
            None => false,
        };
        if failed {
            stdin = None;
        }
    }
    if let Some(mut writer) = stdin {
        let _ = writer.shutdown().await;
    }
}

fn process_exit_code(status: std::process::ExitStatus) -> u32 {
    if let Some(code) = status.code() {
        return u32::try_from(code).unwrap_or(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return u32::try_from(signal).map_or(1, |s| 128u32.saturating_add(s));
        }
    }
    1
}

async fn finish_pump(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(std::time::Duration::from_millis(500), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
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

fn parse_args() -> (String, u16, String, String, Option<String>) {
    let mut host = "0.0.0.0".to_string();
    let mut port: u16 = 2222;
    let mut user = "admin".to_string();
    let mut password = "password".to_string();
    let mut host_key = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = args.next().unwrap_or(host),
            "--port" => port = args.next().and_then(|s| s.parse().ok()).unwrap_or(port),
            "--user" => user = args.next().unwrap_or(user),
            "--password" => password = args.next().unwrap_or(password),
            "--host-key" => host_key = args.next(),
            "-h" | "--help" => {
                println!(
                    "Usage: sshd_standalone [--host 0.0.0.0] [--port 2222] [--user admin] [--password password] [--host-key PATH]"
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

/// Load or create a persistent Ed25519 host key. Try the requested path first,
/// then the executable's directory. If neither can be used, keep the key only
/// in memory for this run.
fn load_or_create_host_key(
    explicit_path: Option<&str>,
) -> anyhow::Result<(russh::keys::PrivateKey, Option<std::path::PathBuf>)> {
    let mut candidates = Vec::new();
    if let Some(path) = explicit_path {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Some(path) = executable_host_key_path() {
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }

    for path in candidates {
        if path.exists() {
            match russh::keys::load_secret_key(&path, None) {
                Ok(key) => return Ok((key, Some(displayable_path(&path)))),
                Err(error) => log::warn!(
                    "could not load host key '{}', trying fallback: {error}",
                    path.display()
                ),
            }
            continue;
        }

        match create_host_key_at(&path) {
            Ok(()) => match russh::keys::load_secret_key(&path, None) {
                Ok(key) => return Ok((key, Some(displayable_path(&path)))),
                Err(error) => log::warn!(
                    "could not load newly-created host key '{}': {error}",
                    path.display()
                ),
            },
            Err(error) => log::warn!(
                "cannot persist host key at '{}', trying fallback: {error}",
                path.display()
            ),
        }
    }

    log::warn!("host key is not persistent; using a new in-memory key for this run");
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    Ok((key, None))
}

fn create_host_key_at(path: &std::path::Path) -> anyhow::Result<()> {
    use russh::keys::ssh_key::LineEnding;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }

    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    key.write_openssh_file(path, LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("failed to write host key '{}': {e}", path.display()))?;

    // Best-effort: tighten permissions on Unix (ignored on Windows).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn displayable_path(path: &std::path::Path) -> std::path::PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(path)
        }
    })
}

fn executable_host_key_path() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|directory| directory.join("host_key"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let (host, port, username, password, host_key_override) = parse_args();

    // Reuse or create a persistent host key, falling back to memory only when
    // none of the default locations can be used.
    let (host_key, host_key_path) = load_or_create_host_key(host_key_override.as_deref())?;
    if let Some(path) = host_key_path {
        println!("SSH host key file: {}", path.display());
    } else {
        println!(
            "SSH host key: ephemeral (not persisted; clients will see a new key after restart)"
        );
        log::warn!("using ephemeral SSH host key; host identity changes after restart");
    }

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

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use super::{assemble_path, shell_term, FALLBACK_PATH_DIRS, PLATFORM_PATH_DIRS};
    #[cfg(windows)]
    use super::shell_term;

    #[test]
    fn term_uses_client_name_or_default() {
        assert_eq!(shell_term("xterm-256color"), "xterm-256color");
        assert_eq!(shell_term("tmux-256color"), "tmux-256color");
        assert_eq!(shell_term(""), "xterm-256color");
        assert_eq!(shell_term("xterm\nEVIL=1"), "xterm-256color");
        assert_eq!(shell_term("a/b"), "xterm-256color");
        assert_eq!(shell_term(&"x".repeat(129)), "xterm-256color");
    }

    #[test]
    #[cfg(not(windows))]
    fn path_keeps_inherited_order_and_appends_fallback() {
        let inherited = "/product/bin:/system/bin:/vendor/bin:";
        let accessible =
            |dir: &str| matches!(dir, "/var/jb/usr/bin" | "/system/bin" | "/bin" | "/usr/bin");
        assert_eq!(
            assemble_path(
                Some(inherited),
                PLATFORM_PATH_DIRS,
                FALLBACK_PATH_DIRS,
                accessible
            ),
            "/var/jb/usr/bin:/product/bin:/system/bin:/vendor/bin:/usr/bin:/bin"
        );
    }

    #[test]
    fn cwd_skips_a_home_that_does_not_exist() {
        let fallback = if cfg!(windows) { r"C:\" } else { "/" };
        let chosen = super::first_existing_dir(&["/no/such/admin/home", fallback]);
        assert_eq!(chosen, std::path::PathBuf::from(fallback));
        assert!(chosen.is_dir());
    }

    #[test]
    fn session_cwd_is_an_existing_directory() {
        assert!(super::session_cwd().is_dir());
    }

    #[test]
    #[cfg(not(windows))]
    fn empty_path_uses_accessible_fallback_dirs() {
        let accessible = |dir: &str| matches!(dir, "/usr/bin" | "/bin" | "/system/bin");
        let expected = "/system/bin:/usr/bin:/bin";
        assert_eq!(
            assemble_path(None, PLATFORM_PATH_DIRS, FALLBACK_PATH_DIRS, accessible),
            expected
        );
        assert_eq!(
            assemble_path(Some(""), PLATFORM_PATH_DIRS, FALLBACK_PATH_DIRS, accessible),
            expected
        );
    }
}
