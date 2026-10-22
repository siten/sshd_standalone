//! Regression check for the interactive-shell channel receive queue.
//!
//! Forward a local port to the Android SSH server first, then run this example:
//!   adb forward tcp:2223 tcp:2222
//!   cargo run --example shell_stress

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use russh::client;
use russh::ChannelMsg;
use tokio::sync::mpsc;

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

#[tokio::main]
async fn main() -> Result<()> {
    let mut session = client::connect(
        Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(20)),
            ..Default::default()
        }),
        ("127.0.0.1", 2223),
        Client,
    )
    .await?;

    let auth = session.authenticate_password("admin", "password").await?;
    if !auth.success() {
        bail!("password authentication failed");
    }

    let channel = session.channel_open_session().await?;
    channel
        .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
        .await?;
    channel.request_shell(true).await?;
    let (mut reader, writer) = channel.split();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(async move {
        while let Some(message) = reader.wait().await {
            match message {
                ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                    if output_tx.send(data.to_vec()).is_err() {
                        break;
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    });

    // Each byte is a separate SSH channel data message. Repeating a short,
    // harmless command exceeds russh's default channel receiver capacity
    // without relying on a long canonical-mode input line.
    for _ in 0..128 {
        for byte in b"true\n" {
            writer.data_bytes(vec![*byte]).await?;
        }
    }
    writer
        .data_bytes(b"\x03echo SHELL_STRESS_OK\nexit\n".to_vec())
        .await?;

    let output = tokio::time::timeout(Duration::from_secs(15), async {
        let mut output = Vec::new();
        while let Some(chunk) = output_rx.recv().await {
            output.extend_from_slice(&chunk);
            if output
                .windows(b"SHELL_STRESS_OK".len())
                .any(|window| window == b"SHELL_STRESS_OK")
            {
                return output;
            }
        }
        output
    })
    .await?;

    let output = String::from_utf8_lossy(&output);
    if !output.contains("SHELL_STRESS_OK") {
        bail!("shell did not complete the stress command; output: {output:?}");
    }

    println!("PASS: 128 individual shell inputs completed; marker received");
    Ok(())
}
