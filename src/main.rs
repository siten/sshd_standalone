//! A small SSH server built on [`russh`] (0.65) that supports:
//!   * password, public key, and OpenSSH user-certificate authentication,
//!   * interactive shell (`ssh user@host`),
//!   * remote command execution (`ssh user@host -p 2222 <command>`),
//!   * SCP upload/download including recursive (`scp`, `scp -r`).
//!
//! Usage:
//!   cargo run -- [--port 2222] [--user admin] [--password admpass] [--config server.conf]
//!
//! Without `--config`, only password login is enabled. Defaults: 0.0.0.0:2222,
//! user "admin", password "admpass". With `--config`, each of `[public_keys]`,
//! `[certificates]`, and `[passwords]` enables that method when it contains a
//! valid entry. The command-line password is not used. `host`, `port`, and
//! `host-key` before any section override those defaults. The same command-line
//! flags override the file.

mod host_key;
mod scp;
mod server_config;
mod session;
mod sftp;
mod ssh;

#[cfg(test)]
mod session_tests;

use std::sync::Arc;
use std::time::Duration;

use russh::server::Server as _;
use server_config::{
    parse_cli, resolve_startup, CliCommand, ServerConfig, DEFAULT_LISTEN_HOST, HELP,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_cli(args.iter().map(String::as_str)) {
        Ok(CliCommand::Help) => {
            println!("{HELP}");
            return Ok(());
        }
        Ok(CliCommand::Run(cli)) => cli,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    let file = match cli.config.as_deref() {
        Some(path) => Some(ServerConfig::from_file(path)?),
        None => None,
    };
    let (listen, auth) = resolve_startup(&cli, file);

    let (host_key, host_key_path) = host_key::load_or_create_host_key(listen.host_key.as_deref())?;
    if let Some(path) = host_key_path {
        println!("SSH host key file: {}", path.display());
    } else {
        println!(
            "SSH host key: ephemeral (not persisted; clients will see a new key after restart)"
        );
        log::warn!("using ephemeral SSH host key; host identity changes after restart");
    }

    let russh_config = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(2),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    };

    let mut server = ssh::SshServer {
        config: Arc::new(auth),
    };

    let listener = TcpListener::bind((listen.host.as_str(), listen.port)).await?;
    let display_host = if listen.host == DEFAULT_LISTEN_HOST {
        "127.0.0.1"
    } else {
        listen.host.as_str()
    };
    log::info!("SSH server listening on {}:{}", listen.host, listen.port);
    log::info!("Login methods: {}", server.config.describe());
    for user in server.config.password_users() {
        log::info!(
            "Password login: ssh {user}@{display_host} -p {}",
            listen.port
        );
    }

    server
        .run_on_socket(Arc::new(russh_config), &listener)
        .await?;
    Ok(())
}
