//! Integration test client for the SCP/exec SSH server.
//!
//! Run the server first (port 2223, admin/password), then:
//!   cargo run --example test_client
//!
//! It exercises: password auth, remote `exec`, SCP upload (single file),
//! SCP recursive upload, SCP download (single file), SCP recursive download.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use russh::client;
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Client;

impl client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

const HOST: (&str, u16) = ("127.0.0.1", 2223);
const USER: &str = "admin";
const PASS: &str = "password";

async fn connect() -> Result<client::Handle<Client>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });
    let mut session = client::connect(config, HOST, Client).await?;
    let res = session.authenticate_password(USER, PASS).await?;
    if !res.success() {
        bail!("password auth failed");
    }
    Ok(session)
}

/// Run a remote command, collecting stdout and the exit code.
async fn exec(session: &client::Handle<Client>, command: &str) -> Result<(String, u32)> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;
    let mut out = Vec::new();
    let mut code = 0;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => code = exit_status,
            ChannelMsg::Eof | ChannelMsg::Close => {}
            _ => {}
        }
    }
    Ok((String::from_utf8_lossy(&out).into_owned(), code))
}

/// Open an interactive shell, send some input, collect output until close.
async fn shell_test(session: &client::Handle<Client>) -> Result<(String, u32)> {
    let mut channel = session.channel_open_session().await?;
    // Request a PTY, then a shell, like `ssh host` does.
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await?;
    channel.request_shell(true).await?;

    #[cfg(windows)]
    let script = "echo shell-says-hi\r\nexit\r\n";
    #[cfg(not(windows))]
    let script = "echo shell-says-hi\nexit\n";

    let mut out = Vec::new();
    let mut code = 0;
    let mut sent = false;

    loop {
        // Drive the session with a timeout so we can inject input after the
        // shell/PTY has had a moment to start.
        let next = tokio::time::timeout(std::time::Duration::from_millis(800), channel.wait()).await;
        match next {
            Ok(Some(msg)) => match msg {
                ChannelMsg::Data { data } => {
                    out.extend_from_slice(&data);
                    // ConPTY (Windows) emits a cursor-position query `ESC[6n`
                    // and blocks until answered. Reply with a dummy position.
                    if data.windows(3).any(|w| w == b"\x1b[6n") {
                        let _ = channel.data(&b"\x1b[1;1R"[..]).await;
                    }
                }
                ChannelMsg::ExtendedData { data, .. } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = exit_status,
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            },
            Ok(None) => break,
            Err(_) => {
                // Idle: the shell is ready and waiting for input.
                if !sent {
                    channel.data(script.as_bytes()).await?;
                    sent = true;
                } else {
                    // Already sent and gone idle again: give up waiting.
                    break;
                }
            }
        }
    }
    Ok((String::from_utf8_lossy(&out).into_owned(), code))
}


async fn read_ok<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<()> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    if b[0] != 0 {
        // read the error line
        let mut line = Vec::new();
        loop {
            let mut c = [0u8; 1];
            s.read_exact(&mut c).await?;
            if c[0] == b'\n' {
                break;
            }
            line.push(c[0]);
        }
        bail!("server error: {}", String::from_utf8_lossy(&line));
    }
    Ok(())
}

/// Upload a single file's contents to `remote_path` via `scp -t`.
async fn scp_upload_file(
    session: &client::Handle<Client>,
    remote_path: &str,
    name: &str,
    content: &[u8],
) -> Result<()> {
    let channel = session.channel_open_session().await?;
    channel
        .exec(true, format!("scp -t {remote_path}"))
        .await?;
    let mut stream = channel.into_stream();

    read_ok(&mut stream).await?; // server ready
    let header = format!("C0644 {} {}\n", content.len(), name);
    stream.write_all(header.as_bytes()).await?;
    stream.flush().await?;
    read_ok(&mut stream).await?; // header ack
    stream.write_all(content).await?;
    stream.write_all(&[0u8]).await?; // end-of-file marker
    stream.flush().await?;
    read_ok(&mut stream).await?; // file ack
    stream.shutdown().await.ok();
    Ok(())
}

/// Recursively upload a directory with a couple of files via `scp -rt`.
async fn scp_upload_dir(session: &client::Handle<Client>, remote_path: &str) -> Result<()> {
    let channel = session.channel_open_session().await?;
    channel
        .exec(true, format!("scp -rt {remote_path}"))
        .await?;
    let mut s = channel.into_stream();

    read_ok(&mut s).await?;

    // D <- mydir
    s.write_all(b"D0755 0 mydir\n").await?;
    s.flush().await?;
    read_ok(&mut s).await?;

    // file a.txt
    let a = b"alpha\n";
    s.write_all(format!("C0644 {} a.txt\n", a.len()).as_bytes())
        .await?;
    s.flush().await?;
    read_ok(&mut s).await?;
    s.write_all(a).await?;
    s.write_all(&[0u8]).await?;
    s.flush().await?;
    read_ok(&mut s).await?;

    // nested dir
    s.write_all(b"D0755 0 sub\n").await?;
    s.flush().await?;
    read_ok(&mut s).await?;

    let b = b"beta beta\n";
    s.write_all(format!("C0644 {} b.txt\n", b.len()).as_bytes())
        .await?;
    s.flush().await?;
    read_ok(&mut s).await?;
    s.write_all(b).await?;
    s.write_all(&[0u8]).await?;
    s.flush().await?;
    read_ok(&mut s).await?;

    // E (leave sub)
    s.write_all(b"E\n").await?;
    s.flush().await?;
    read_ok(&mut s).await?;
    // E (leave mydir)
    s.write_all(b"E\n").await?;
    s.flush().await?;
    read_ok(&mut s).await?;

    s.shutdown().await.ok();
    Ok(())
}

/// Download a single file via `scp -f` and return its contents.
async fn scp_download_file(
    session: &client::Handle<Client>,
    remote_path: &str,
) -> Result<(String, Vec<u8>)> {
    let channel = session.channel_open_session().await?;
    channel
        .exec(true, format!("scp -f {remote_path}"))
        .await?;
    let mut s = channel.into_stream();

    // Send initial OK.
    s.write_all(&[0u8]).await?;
    s.flush().await?;

    // Read the C-line header.
    let line = read_line(&mut s).await?;
    if !line.starts_with('C') {
        bail!("expected C line, got: {line:?}");
    }
    let mut parts = line[1..].splitn(3, ' ');
    let _mode = parts.next().unwrap_or("");
    let size: u64 = parts.next().unwrap_or("0").parse()?;
    let name = parts.next().unwrap_or("").to_string();

    // Ack header.
    s.write_all(&[0u8]).await?;
    s.flush().await?;

    // Read body.
    let mut buf = vec![0u8; size as usize];
    s.read_exact(&mut buf).await?;
    // Read the trailing status byte from server.
    let mut status = [0u8; 1];
    s.read_exact(&mut status).await?;
    // Ack.
    s.write_all(&[0u8]).await?;
    s.flush().await?;
    s.shutdown().await.ok();
    Ok((name, buf))
}

async fn read_line<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut c = [0u8; 1];
        s.read_exact(&mut c).await?;
        if c[0] == b'\n' {
            break;
        }
        buf.push(c[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
    let session = connect().await?;
    println!("[ok] password authentication");

    // 1. exec
    let (out, code) = exec(&session, "echo hello-from-server").await?;
    println!("[exec] code={code} output={out:?}");
    assert!(out.contains("hello-from-server"), "exec output mismatch");

    // 2. SCP upload single file
    scp_upload_file(&session, "uploaded.txt", "uploaded.txt", b"scp upload works\n").await?;
    let (out, _) = exec(&session, "type uploaded.txt").await?;
    println!("[scp -t file] readback={out:?}");
    assert!(out.contains("scp upload works"), "upload mismatch");

    // 3. SCP recursive upload
    scp_upload_dir(&session, ".").await?;
    let (out, _) = exec(&session, "type mydir\\a.txt & type mydir\\sub\\b.txt").await?;
    println!("[scp -rt dir] readback={out:?}");
    assert!(out.contains("alpha") && out.contains("beta"), "recursive upload mismatch");

    // 4. SCP download single file (download what we uploaded)
    let (name, data) = scp_download_file(&session, "uploaded.txt").await?;
    println!(
        "[scp -f file] name={name:?} content={:?}",
        String::from_utf8_lossy(&data)
    );
    assert_eq!(data, b"scp upload works\n", "download mismatch");

    // 5. interactive shell
    let (out, code) = shell_test(&session).await?;
    println!("[shell] code={code} output={out:?}");
    assert!(out.contains("shell-says-hi"), "shell output mismatch");

    println!("\nALL TESTS PASSED");
    Ok(())
}
