//! A small SSH server built on [`russh`] (0.65) that supports:
//!   * password, public key, and OpenSSH user-certificate authentication,
//!   * interactive shell (`ssh user@host`),
//!   * remote command execution (`ssh user@host -p 2222 <command>`),
//!   * SCP upload/download including recursive (`scp`, `scp -r`).
//!
//! Usage:
//!   cargo run -- [--port 2222] [--user admin] [--password admpass] [--config server.conf]
//!
//! Without `--config`, a `server.conf` beside the executable is loaded when
//! present. Otherwise the server uses password login and defaults to
//! 0.0.0.0:2222, user "admin", password "admpass". A loaded config file
//! overrides listen fields it sets; omitted listen fields fall back to CLI and
//! then defaults. Authentication is file-only, so `--user` and `--password` are
//! ignored whenever a config is loaded. `--config` explicitly selects the file.

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
    load_startup_config, parse_cli, resolve_startup, CliCommand, DEFAULT_LISTEN_HOST, HELP,
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

    let file = load_startup_config(cli.config.as_deref())?;
    let (listen, auth) = match resolve_startup(&cli, file) {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

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
