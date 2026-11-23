//! SSH server and per-connection protocol handler (`russh`).

use std::collections::HashMap;
use std::sync::Arc;

use portable_pty::PtySize;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::{mpsc, Mutex};

use crate::scp;
use crate::server_config::ServerConfig;
use crate::session::{
    self, clamp_pty_size, PtyMasterHandle, SpawnedPtyShell, DEFAULT_PTY_SIZE, IO_CHUNKS,
};
use crate::sftp;

/// `pty-req` parameters. The PTY is opened later, in `shell_request`.
#[derive(Clone)]
struct RequestedPty {
    size: PtySize,
    term: String,
}

/// Per-connection SSH handler: authentication, channel tracking, and request dispatch.
pub struct ClientHandler {
    config: Arc<ServerConfig>,
    /// Session channels opened by the client and awaiting exec/sftp/shell.
    pending_channels: HashMap<ChannelId, Channel<Msg>>,
    /// Client terminal name and window size from `pty-req`.
    requested_ptys: HashMap<ChannelId, RequestedPty>,
    /// Interactive keystrokes. Bounded so `data` can use `try_send` and never
    /// block the session loop.
    shell_inputs: Arc<Mutex<HashMap<ChannelId, mpsc::Sender<Vec<u8>>>>>,
    /// Active PTY masters keyed by channel, used to apply window resizes.
    pty_masters: Arc<Mutex<HashMap<ChannelId, PtyMasterHandle>>>,
    pty_allowed: bool,
}

impl ClientHandler {
    fn take_channel(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<Option<Channel<Msg>>, russh::Error> {
        match self.pending_channels.remove(&channel_id) {
            Some(channel) => Ok(Some(channel)),
            None => {
                session.channel_failure(channel_id)?;
                Ok(None)
            }
        }
    }
}

fn reject_auth() -> Auth {
    Auth::Reject {
        proceed_with_methods: None,
        partial_success: false,
    }
}

async fn finish_session_channel(
    handle: russh::server::Handle,
    channel_id: ChannelId,
    exit_code: u32,
) {
    let _ = handle.exit_status_request(channel_id, exit_code).await;
    let _ = handle.eof(channel_id).await;
    let _ = handle.close(channel_id).await;
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if self.config.accepts_password(user, password) {
            log::info!("User {user:?} authenticated via password");
            self.pty_allowed = true;
            Ok(Auth::Accept)
        } else {
            log::warn!("Failed password auth for user {user:?}");
            Ok(reject_auth())
        }
    }

    /// Tell the client which configured methods it may try.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: Some(self.config.method_set()),
            partial_success: false,
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        // A certificate probe only carries the certified key, not the CA.
        // When certificate login is enabled, the offer has to proceed so the
        // signed request can reach `auth_openssh_certificate`.
        if self.config.accepts_public_key(offer.public_key) || self.config.allows_certificate() {
            Ok(Auth::Accept)
        } else {
            Ok(reject_auth())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if self.config.accepts_public_key(key.public_key) {
            log::info!("User {user:?} authenticated via public key");
            self.pty_allowed = true;
            Ok(Auth::Accept)
        } else {
            log::warn!("Failed public key auth for user {user:?}");
            Ok(reject_auth())
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> Result<Auth, Self::Error> {
        match self.config.reject_certificate_reason(user, certificate) {
            None => {
                log::info!(
                    "User {user:?} authenticated via certificate key ID {:?}",
                    certificate.key_id()
                );
                self.pty_allowed = self.config.certificate_allows_pty(certificate);
                Ok(Auth::Accept)
            }
            Some(reason) => {
                log::warn!("Failed certificate auth for user {user:?}: {reason}");
                Ok(reject_auth())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pending_channels.insert(channel.id(), channel);
        // Dropping the handle rejects the channel.
        reply.accept().await;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Closing stdin lets the shell see EOF and exit on its own.
        self.shell_inputs.lock().await.remove(&channel);
        self.pending_channels.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.shell_inputs.lock().await.remove(&channel);
        self.pty_masters.lock().await.remove(&channel);
        self.requested_ptys.remove(&channel);
        self.pending_channels.remove(&channel);
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
        let tx = self.shell_inputs.lock().await.get(&channel).cloned();
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
        if !self.pty_allowed {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.requested_ptys.insert(
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
        if let Some(master) = self.pty_masters.lock().await.get(&channel) {
            let master = Arc::clone(master);
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
        let Some(channel) = self.take_channel(channel_id, session)? else {
            return Ok(());
        };

        let command = String::from_utf8_lossy(data).into_owned();
        let scp_cmd = scp::parse_scp_command(&command);
        if scp_cmd.is_some() {
            log::info!("exec request on {channel_id:?}: scp");
        } else {
            log::info!(
                "exec request on {channel_id:?}: command ({} bytes)",
                command.len()
            );
        }

        // Tell the client the exec request itself succeeded.
        session.channel_success(channel_id)?;

        let handle = session.handle();
        tokio::spawn(async move {
            let exit_code = match scp_cmd {
                Some(scp_cmd) => session::run_scp(channel, scp_cmd).await,
                None => session::run_command(channel, &command).await,
            };
            finish_session_channel(handle, channel_id, exit_code).await;
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
            let Some(channel) = self.take_channel(channel_id, session)? else {
                return Ok(());
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
        if !self.pty_allowed {
            self.pending_channels.remove(&channel_id);
            session.channel_failure(channel_id)?;
            return Ok(());
        }
        let Some(channel) = self.take_channel(channel_id, session)? else {
            return Ok(());
        };

        let requested = self.requested_ptys.remove(&channel_id);
        let size = clamp_pty_size(
            requested
                .as_ref()
                .map(|pty| pty.size)
                .unwrap_or(DEFAULT_PTY_SIZE),
        );
        let term = requested.map(|pty| pty.term).unwrap_or_default();

        let SpawnedPtyShell { master, child } = match session::spawn_pty_shell(size, &term).await {
            Ok(spawned) => spawned,
            Err(()) => {
                let _ = session.channel_failure(channel_id);
                return Ok(());
            }
        };

        self.pty_masters
            .lock()
            .await
            .insert(channel_id, Arc::clone(&master));

        session.channel_success(channel_id)?;

        let (tx, rx) = mpsc::channel::<Vec<u8>>(IO_CHUNKS);
        self.shell_inputs.lock().await.insert(channel_id, tx);

        let handle = session.handle();
        let shell_inputs = Arc::clone(&self.shell_inputs);
        let pty_masters = Arc::clone(&self.pty_masters);

        tokio::spawn(async move {
            let exit_code = session::run_pty_shell(channel, rx, master, child).await;
            shell_inputs.lock().await.remove(&channel_id);
            pty_masters.lock().await.remove(&channel_id);
            finish_session_channel(handle, channel_id, exit_code).await;
        });

        Ok(())
    }
}

/// Top-level SSH server. Produces a fresh [`ClientHandler`] per connection.
#[derive(Clone)]
pub struct SshServer {
    pub config: Arc<ServerConfig>,
}

impl russh::server::Server for SshServer {
    type Handler = ClientHandler;

    fn new_client(&mut self, peer: Option<std::net::SocketAddr>) -> ClientHandler {
        if let Some(addr) = peer {
            log::info!("New connection from {addr}");
        }
        ClientHandler {
            config: Arc::clone(&self.config),
            pending_channels: HashMap::new(),
            requested_ptys: HashMap::new(),
            shell_inputs: Arc::new(Mutex::new(HashMap::new())),
            pty_masters: Arc::new(Mutex::new(HashMap::new())),
            pty_allowed: false,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        log::warn!("Session error: {error:?}");
    }
}
