//! Session runtime: environment setup, interactive PTY shells, remote command
//! execution, and legacy SCP dispatch.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use russh::server::Msg;
use russh::Channel;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::scp;

/// Shared PTY master handle for a shell channel.
pub type PtyMasterHandle = Arc<std::sync::Mutex<Box<dyn MasterPty + Send>>>;

/// A newly opened PTY master paired with its spawned shell process.
pub struct SpawnedPtyShell {
    pub master: PtyMasterHandle,
    pub child: Box<dyn portable_pty::Child + Send + Sync>,
}

/// Chunks queued between the SSH channel and a pipe. Further input is dropped
/// so a client that keeps sending cannot stall the session loop.
pub const IO_CHUNKS: usize = 32;
pub const DEFAULT_PTY_SIZE: PtySize = PtySize {
    rows: 24,
    cols: 80,
    pixel_width: 0,
    pixel_height: 0,
};

#[cfg(all(windows, test))]
pub static WINDOWS_PTY_CLEANUPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Environment, working directory, and shell resolution
// ---------------------------------------------------------------------------

/// ConPTY and some Unix PTYs reject a 0x0 size.
pub fn clamp_pty_size(mut size: PtySize) -> PtySize {
    if size.rows == 0 {
        size.rows = DEFAULT_PTY_SIZE.rows;
    }
    if size.cols == 0 {
        size.cols = DEFAULT_PTY_SIZE.cols;
    }
    size
}

trait CommandEnv {
    fn set_env(&mut self, key: &str, value: &str);
    fn set_cwd(&mut self, dir: &Path);
}

impl CommandEnv for CommandBuilder {
    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn set_cwd(&mut self, dir: &Path) {
        self.cwd(dir);
    }
}

impl CommandEnv for tokio::process::Command {
    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }

    fn set_cwd(&mut self, dir: &Path) {
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

/// Build a Unix shell PATH in one place so its precedence is easy to audit.
///
/// Order is platform directories, inherited PATH entries, then standard
/// fallback directories. Inaccessible platform/fallback directories are
/// skipped; inherited entries are preserved. Duplicates and empty entries are
/// removed while preserving the first occurrence.
#[cfg(not(windows))]
fn assemble_path<F>(inherited: Option<&str>, mut is_accessible: F) -> String
where
    F: FnMut(&str) -> bool,
{
    // Rootless Procursus and Android-specific directories have precedence
    // over inherited PATH entries when they are available.
    const PLATFORM_DIRS: &[&str] = &[
        "/var/jb/usr/local/sbin",
        "/var/jb/usr/local/bin",
        "/var/jb/usr/sbin",
        "/var/jb/usr/bin",
        "/var/jb/sbin",
        "/var/jb/bin",
        "/system/bin",
        "/system/xbin",
    ];

    // Complete partial daemon PATHs with the usual login-shell directories.
    const FALLBACK_DIRS: &[&str] = &[
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ];

    let inherited_dirs: Vec<&str> = inherited
        .into_iter()
        .flat_map(|path| path.split(':'))
        .filter(|dir| !dir.is_empty())
        .collect();

    let mut dirs: Vec<&str> = Vec::new();

    // 1. Platform-specific directories, but don't move an inherited entry.
    for &dir in PLATFORM_DIRS {
        if !inherited_dirs.contains(&dir) && is_accessible(dir) && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }

    // 2. Keep inherited entries in their original order.
    for dir in inherited_dirs {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }

    // 3. Append accessible standard directories to complete partial PATHs.
    for &dir in FALLBACK_DIRS {
        if is_accessible(dir) && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }

    dirs.join(":")
}

#[cfg(not(windows))]
pub fn unix_path() -> String {
    let inherited = std::env::var("PATH").ok().filter(|path| !path.is_empty());
    assemble_path(inherited.as_deref(), |dir| Path::new(dir).is_dir())
}

/// Resolve the process environment once for a new child. Keeping these related
/// defaults together makes interactive shells and remote commands use the same
/// executable, working directory, and Unix PATH/SHELL settings.
struct SessionEnvironment {
    shell_program: &'static str,
    working_directory: PathBuf,
    #[cfg(not(windows))]
    path: String,
}

impl SessionEnvironment {
    fn current() -> Self {
        let shell_program = selected_shell_program();
        let working_directory = session_cwd();
        #[cfg(not(windows))]
        let path = unix_path();

        Self {
            shell_program,
            working_directory,
            #[cfg(not(windows))]
            path,
        }
    }

    fn apply_to(&self, command: &mut impl CommandEnv, term: Option<&str>) {
        if let Some(term) = term {
            command.set_env("TERM", shell_term(term));
        }
        #[cfg(not(windows))]
        {
            command.set_env("PATH", &self.path);
            command.set_env("SHELL", self.shell_program);
        }
        command.set_cwd(&self.working_directory);
    }
}

/// Select the shell using the platform's documented preference order.
fn selected_shell_program() -> &'static str {
    #[cfg(windows)]
    {
        "cmd.exe"
    }
    #[cfg(not(windows))]
    {
        // zsh: rootless iOS login shell, and the usual shell on macOS.
        // bash: usual full shell on Linux and rootful jailbreaks.
        // sh: Android's shell and the portable final fallback.
        const SHELL_CANDIDATES: &[&str] = &[
            "/var/jb/usr/bin/zsh",
            "/bin/zsh",
            "/usr/bin/zsh",
            "/usr/local/bin/zsh",
            "/var/jb/usr/bin/bash",
            "/bin/bash",
            "/usr/bin/bash",
            "/usr/local/bin/bash",
            "/system/bin/sh",
            "/var/jb/bin/sh",
            "/var/jb/usr/bin/sh",
            "/bin/sh",
            "/usr/bin/sh",
            "/usr/local/bin/sh",
        ];

        SHELL_CANDIDATES
            .iter()
            .copied()
            .find(|path| Path::new(path).is_file())
            .unwrap_or("sh")
    }
}

/// First candidate that can be opened as a directory. The login name is not
/// consulted; a missing or inaccessible path is skipped.
fn first_existing_dir(candidates: &[PathBuf], fallback: &Path) -> PathBuf {
    candidates
        .iter()
        .find(|path| path.is_dir())
        .cloned()
        .unwrap_or_else(|| fallback.to_path_buf())
}

/// Directory for a new session. The SSH username may not exist on the target,
/// so prefer the process home, then a platform root that does not depend on an
/// account.
pub fn session_cwd() -> PathBuf {
    let mut candidates = Vec::new();
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("USERPROFILE") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(path));
    }

    #[cfg(windows)]
    let fallback = PathBuf::from(r"C:\");
    #[cfg(not(windows))]
    let fallback = PathBuf::from("/");

    first_existing_dir(&candidates, &fallback)
}

/// Environment shared by the interactive shell and remote commands.
/// `term` is set only for a PTY shell.
fn build_shell_command(environment: &SessionEnvironment, term: &str) -> CommandBuilder {
    let mut command = CommandBuilder::new(environment.shell_program);
    #[cfg(not(windows))]
    command.arg("-i");
    environment.apply_to(&mut command, Some(term));
    command
}

// ---------------------------------------------------------------------------
// Shared stream and PTY cleanup helpers
// ---------------------------------------------------------------------------

async fn finish_pump(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(Duration::from_millis(500), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(windows)]
async fn finish_windows_pty(master: &PtyMasterHandle) -> bool {
    use portable_pty::win::conpty::ConPtyMasterPty;

    let shutdown = master.lock().ok().and_then(|master| {
        let master: &dyn MasterPty = master.as_ref();
        master
            .downcast_ref::<ConPtyMasterPty>()
            .map(ConPtyMasterPty::shutdown)
    });
    let Some(shutdown) = shutdown else {
        log::error!("failed to obtain Windows PTY shutdown handle");
        return false;
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match shutdown.try_wait() {
            Ok(Some(status)) => {
                log::debug!("Windows PTY cleanup completed: {status:?}");
                return true;
            }
            Err(error) => {
                log::error!(
                    "Windows PTY cleanup failed: {error}; {:?}",
                    shutdown.status()
                );
                return false;
            }
            Ok(None) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            log::error!("Windows PTY cleanup timed out: {:?}", shutdown.status());
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn release_pty_child(mut child: Box<dyn portable_pty::Child + Send + Sync>) {
    let mut killer = child.clone_killer();
    let _ = killer.kill();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = child.wait();
    })
    .await;
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

// ---------------------------------------------------------------------------
// Interactive PTY shell
// ---------------------------------------------------------------------------

/// Open a real PTY and spawn the platform's interactive shell on its slave end.
pub async fn spawn_pty_shell(size: PtySize, term: &str) -> Result<SpawnedPtyShell, ()> {
    let pty_pair = match native_pty_system().openpty(size) {
        Ok(pair) => pair,
        Err(error) => {
            log::warn!("failed to open PTY: {error}");
            return Err(());
        }
    };

    let environment = SessionEnvironment::current();
    let child = match pty_pair
        .slave
        .spawn_command(build_shell_command(&environment, term))
    {
        Ok(child) => child,
        Err(error) => {
            log::warn!("failed to spawn shell: {error}");
            #[cfg(windows)]
            {
                drop(pty_pair.slave);
                let master = Arc::new(std::sync::Mutex::new(pty_pair.master));
                finish_windows_pty(&master).await;
            }
            return Err(());
        }
    };

    // The slave handle is no longer needed once the child owns it; dropping it
    // avoids holding an extra fd.
    drop(pty_pair.slave);

    Ok(SpawnedPtyShell {
        master: Arc::new(std::sync::Mutex::new(pty_pair.master)),
        child,
    })
}

/// Interactive shell on a PTY.
///
/// Keystrokes arrive on `stdin_rx`. Channel EOF drops that sender, the PTY
/// writer is dropped, and the shell sees EOF. Channel Close kills the child.
/// The channel receiver is drained until then so russh can keep reading.
pub async fn run_pty_shell(
    mut channel: Channel<Msg>,
    stdin_rx: mpsc::Receiver<Vec<u8>>,
    master: PtyMasterHandle,
    mut child: Box<dyn portable_pty::Child + Send + Sync>,
) -> u32 {
    use std::io::Read;

    let reader = match master.lock().ok().and_then(|m| m.try_clone_reader().ok()) {
        Some(reader) => reader,
        None => {
            let _ = channel
                .data_bytes(b"failed to obtain PTY reader\r\n".to_vec())
                .await;
            release_pty_child(child).await;
            #[cfg(windows)]
            finish_windows_pty(&master).await;
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
            #[cfg(windows)]
            finish_windows_pty(&master).await;
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
    #[cfg(windows)]
    {
        // The output receiver is gone, so a reader blocked on forwarding can
        // exit. Shutdown cancels forwarding I/O, then drains the reserved output
        // pipe concurrently with ClosePseudoConsole and joins both workers.
        let closed = finish_windows_pty(&master).await;
        let mut reader_task = reader_task;
        let reader_finished = matches!(
            tokio::time::timeout(Duration::from_secs(2), &mut reader_task).await,
            Ok(Ok(()))
        );
        if !reader_finished {
            reader_task.abort();
            log::error!("PTY reader task did not finish after Windows pipe shutdown");
        }
        if closed && reader_finished {
            #[cfg(test)]
            WINDOWS_PTY_CLEANUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            log::debug!("PTY shutdown complete: output drained, pipes closed, ClosePseudoConsole returned, cleanup workers joined, reader task joined");
            exit
        } else {
            1
        }
    }
    #[cfg(not(windows))]
    {
        // Preserve the existing Unix backend behavior.
        let _ = tokio::time::timeout(Duration::from_millis(500), reader_task).await;
        exit
    }
}

// ---------------------------------------------------------------------------
// Remote command execution and legacy SCP
// ---------------------------------------------------------------------------

async fn write_command_stdin(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    mut stdin: Option<tokio::process::ChildStdin>,
) {
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

/// Copy all bytes from an optional async reader into an async writer.
async fn pump<R, W>(reader: Option<R>, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
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

/// Run the SCP protocol over the channel. Returns an exit code.
pub async fn run_scp(channel: Channel<Msg>, cmd: scp::ScpCommand) -> u32 {
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
        Err(error) => {
            log::warn!("scp error: {error}");
            1
        }
    }
}

/// Run one remote command. Stdin is the SSH channel. EOF closes that pipe.
/// Close kills the child. Stdout and stderr are separate tasks.
pub async fn run_command(mut channel: Channel<Msg>, command: &str) -> u32 {
    use tokio::process::Command;

    let environment = SessionEnvironment::current();
    let mut cmd = Command::new(environment.shell_program);
    #[cfg(windows)]
    cmd.arg("/C");
    #[cfg(not(windows))]
    cmd.arg("-c");
    cmd.arg(command);
    environment.apply_to(&mut cmd, None);
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

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::shell_term;
    #[cfg(not(windows))]
    use super::{assemble_path, shell_term};

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
            assemble_path(Some(inherited), accessible),
            "/var/jb/usr/bin:/product/bin:/system/bin:/vendor/bin:/usr/bin:/bin"
        );
    }

    #[test]
    fn cwd_skips_a_home_that_does_not_exist() {
        let fallback = if cfg!(windows) { r"C:\" } else { "/" };
        let candidates = [std::path::PathBuf::from("/no/such/admin/home")];
        let fallback = std::path::PathBuf::from(fallback);
        let chosen = super::first_existing_dir(&candidates, &fallback);
        assert_eq!(chosen, fallback);
        assert!(chosen.is_dir());
    }

    #[test]
    fn session_cwd_is_an_existing_directory() {
        assert!(super::session_cwd().is_dir());
    }

    #[test]
    fn process_exit_code_uses_the_status_code() {
        let mut command =
            std::process::Command::new(super::SessionEnvironment::current().shell_program);
        if cfg!(windows) {
            command.args(["/C", "exit 42"]);
        } else {
            command.args(["-c", "exit 42"]);
        }
        let status = command.status().expect("spawn exit 42");
        assert_eq!(super::process_exit_code(status), 42);
    }

    /// A signal death has no status code. Report the conventional 128+signal
    /// value instead of collapsing every signal to 1.
    #[test]
    #[cfg(unix)]
    fn signal_death_is_reported_as_128_plus_signal() {
        let status = std::process::Command::new(super::SessionEnvironment::current().shell_program)
            .args(["-c", "kill -9 $$"])
            .status()
            .expect("spawn kill");
        assert_eq!(super::process_exit_code(status), 137);
    }

    #[test]
    #[cfg(not(windows))]
    fn empty_path_uses_accessible_fallback_dirs() {
        let accessible = |dir: &str| matches!(dir, "/usr/bin" | "/bin" | "/system/bin");
        assert_eq!(assemble_path(None, accessible), "/system/bin:/usr/bin:/bin");
    }
}
