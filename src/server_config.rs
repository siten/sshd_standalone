//! Server listen settings and login methods.
//!
//! Outside a section the file accepts `host`, `port`, and `host-key`.
//! `[public_keys]`, `[certificates]`, and `[passwords]` each stay active until
//! the next section header. A section enables its login method only when it
//! contains a valid entry.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use russh::keys::ssh_key::Fingerprint;
use russh::keys::{Certificate, HashAlg, PublicKey};
use russh::{MethodKind, MethodSet};
use subtle::ConstantTimeEq;

pub const DEFAULT_LISTEN_HOST: &str = "0.0.0.0";
pub const DEFAULT_LISTEN_PORT: u16 = 2222;
pub const DEFAULT_USER: &str = "admin";
pub const DEFAULT_PASSWORD: &str = "admpass";
const CONFIG_FILE_NAME: &str = "server.conf";

struct PasswordLogin {
    user: String,
    password: String,
}

/// Credentials the server will accept. Each list is independent.
pub struct ServerConfig {
    passwords: Vec<PasswordLogin>,
    public_keys: Vec<PublicKey>,
    ca_fingerprints: Vec<Fingerprint>,
    host: Option<String>,
    port: Option<u16>,
    host_key: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    PublicKeys,
    Certificates,
    Passwords,
}

// ---------------------------------------------------------------------------
// Config file parser (bottom-up: value/line helpers -> section/file parser)
// ---------------------------------------------------------------------------

fn resolve_path(base: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn parse_value(raw: &str) -> Result<String> {
    let starts_quoted = raw.starts_with('"');
    let ends_quoted = raw.ends_with('"');
    match (starts_quoted, ends_quoted) {
        (true, true) if raw.len() >= 2 => {
            let mut value = String::new();
            let mut chars = raw[1..raw.len() - 1].chars();
            while let Some(ch) = chars.next() {
                match ch {
                    '"' => bail!("unescaped quote"),
                    '\\' => match chars.next() {
                        Some('"') => value.push('"'),
                        Some('\\') => value.push('\\'),
                        Some(next) => {
                            value.push('\\');
                            value.push(next);
                        }
                        None => bail!("trailing escape"),
                    },
                    _ => value.push(ch),
                }
            }
            Ok(value)
        }
        (true, _) | (_, true) => bail!("unmatched quote"),
        _ if raw.contains('"') => bail!("unmatched quote"),
        _ => Ok(raw.to_string()),
    }
}

fn section_name(line: &str) -> Option<&str> {
    let line = line.strip_prefix('[')?.strip_suffix(']')?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

fn parse_password(line: &str) -> Result<(String, String)> {
    let Some((user, raw)) = line.split_once('=') else {
        bail!("password line must be user = \"password\"");
    };
    let user = user.trim();
    if user.is_empty() {
        bail!("password line is missing a user");
    }
    let password = parse_value(raw.trim())?;
    if password.is_empty() {
        bail!("password is empty");
    }
    Ok((user.to_string(), password))
}

fn apply_listen_setting(
    config: &mut ServerConfig,
    base: &Path,
    path: &Path,
    line_number: usize,
    line: &str,
) -> Result<()> {
    let Some((key, raw)) = line.split_once('=') else {
        bail!(
            "{}:{line_number}: line is outside a section",
            path.display()
        );
    };
    let key = key.trim();
    if !matches!(key, "host" | "port" | "host-key") {
        bail!(
            "{}:{line_number}: line is outside a section",
            path.display()
        );
    }
    let value = parse_value(raw.trim()).with_context(|| {
        format!(
            "{}:{line_number}: invalid quoted value for {key}",
            path.display()
        )
    })?;
    if value.is_empty() {
        bail!("{}:{line_number}: {key} is empty", path.display());
    }
    match key {
        "host" => {
            if let Some(previous) = &config.host {
                bail!(
                    "{}:{line_number}: duplicate host \"{previous}\" and \"{value}\"",
                    path.display()
                );
            }
            config.host = Some(value);
        }
        "port" => {
            if let Some(previous) = config.port {
                bail!(
                    "{}:{line_number}: duplicate port {previous} and \"{value}\"",
                    path.display()
                );
            }
            config.port = Some(
                value
                    .parse::<u16>()
                    .with_context(|| format!("{}:{line_number}: invalid port", path.display()))?,
            );
        }
        "host-key" => {
            if let Some(previous) = &config.host_key {
                bail!(
                    "{}:{line_number}: duplicate host-key \"{}\" and \"{value}\"",
                    path.display(),
                    previous.display()
                );
            }
            config.host_key = Some(resolve_path(base, &value));
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn parse_config(text: &str, path: &Path) -> Result<ServerConfig> {
    let mut config = ServerConfig {
        passwords: Vec::new(),
        public_keys: Vec::new(),
        ca_fingerprints: Vec::new(),
        host: None,
        port: None,
        host_key: None,
    };
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut section: Option<Section> = None;
    let mut seen = [false; 3];
    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = section_name(line) {
            let next = match name {
                "public_keys" => Section::PublicKeys,
                "certificates" => Section::Certificates,
                "passwords" => Section::Passwords,
                other => bail!(
                    "{}:{line_number}: unknown section [{other}]",
                    path.display()
                ),
            };
            if seen[next as usize] {
                bail!(
                    "{}:{line_number}: duplicate section [{name}]",
                    path.display()
                );
            }
            seen[next as usize] = true;
            section = Some(next);
            continue;
        }
        match section {
            None => apply_listen_setting(&mut config, base, path, line_number, line)?,
            Some(Section::PublicKeys) => {
                let key = PublicKey::from_openssh(line).with_context(|| {
                    format!(
                        "{}:{line_number}: invalid OpenSSH public key",
                        path.display()
                    )
                })?;
                config.public_keys.push(key);
            }
            Some(Section::Certificates) => {
                let key = PublicKey::from_openssh(line).with_context(|| {
                    format!("{}:{line_number}: invalid OpenSSH CA key", path.display())
                })?;
                config
                    .ca_fingerprints
                    .push(key.fingerprint(HashAlg::Sha256));
            }
            Some(Section::Passwords) => {
                let (user, password) = parse_password(line).with_context(|| {
                    format!("{}:{line_number}: invalid password entry", path.display())
                })?;
                if config.passwords.iter().any(|login| login.user == user) {
                    bail!(
                        "{}:{line_number}: duplicate password user \"{user}\"",
                        path.display()
                    );
                }
                config.passwords.push(PasswordLogin { user, password });
            }
        }
    }
    Ok(config)
}

impl ServerConfig {
    pub fn with_password(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            passwords: vec![PasswordLogin {
                user: user.into(),
                password: password.into(),
            }],
            public_keys: Vec::new(),
            ca_fingerprints: Vec::new(),
            host: None,
            port: None,
            host_key: None,
        }
    }

    #[cfg(test)]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    #[cfg(test)]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    #[cfg(test)]
    pub fn host_key(&self) -> Option<&Path> {
        self.host_key.as_deref()
    }

    pub fn allows_password(&self) -> bool {
        !self.passwords.is_empty()
    }

    pub fn allows_public_key(&self) -> bool {
        !self.public_keys.is_empty()
    }

    pub fn allows_certificate(&self) -> bool {
        !self.ca_fingerprints.is_empty()
    }

    fn any_method(&self) -> bool {
        self.allows_password() || self.allows_public_key() || self.allows_certificate()
    }

    /// Load `path`. A method is enabled only by a valid entry of that kind.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read server config '{}'", path.display()))?;
        let config = parse_config(&text, path)?;
        if !config.any_method() {
            bail!("server config '{}' enables no login method", path.display());
        }
        Ok(config)
    }

    /// `publickey` covers both raw keys and OpenSSH user certificates.
    pub fn method_set(&self) -> MethodSet {
        let mut methods = Vec::new();
        if self.allows_password() {
            methods.push(MethodKind::Password);
        }
        if self.allows_public_key() || self.allows_certificate() {
            methods.push(MethodKind::PublicKey);
        }
        MethodSet::from(methods.as_slice())
    }

    pub fn password_users(&self) -> impl Iterator<Item = &str> {
        self.passwords.iter().map(|login| login.user.as_str())
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.allows_password() {
            let users: Vec<_> = self.password_users().collect();
            parts.push(format!("password ({})", users.join(", ")));
        }
        if self.allows_public_key() {
            parts.push(format!("public key ({} keys)", self.public_keys.len()));
        }
        if self.allows_certificate() {
            parts.push(format!("certificate ({} CAs)", self.ca_fingerprints.len()));
        }
        parts.join(", ")
    }

    pub fn accepts_password(&self, user: &str, password: &str) -> bool {
        self.passwords.iter().any(|login| {
            login.user == user && bool::from(login.password.as_bytes().ct_eq(password.as_bytes()))
        })
    }

    pub fn accepts_public_key(&self, key: &PublicKey) -> bool {
        self.public_keys
            .iter()
            .any(|allowed| allowed.key_data() == key.key_data())
    }

    /// `None` means the certificate may log in as `user`.
    pub fn reject_certificate_reason(
        &self,
        user: &str,
        certificate: &Certificate,
    ) -> Option<&'static str> {
        if !certificate.cert_type().is_user() {
            return Some("not a user certificate");
        }
        if !certificate.critical_options().is_empty() {
            return Some("critical options are not supported");
        }
        let principals = certificate.valid_principals();
        if principals.is_empty() || !principals.iter().any(|principal| principal == user) {
            return Some("principal does not match the user");
        }
        if certificate.validate(self.ca_fingerprints.iter()).is_err() {
            return Some("CA is not trusted or the certificate is outside its validity window");
        }
        None
    }

    /// OpenSSH certificate extensions grant capabilities. This server's shell
    /// implementation always allocates a PTY, so only certificates explicitly
    /// carrying the empty `permit-pty` extension may request a shell.
    pub fn certificate_allows_pty(&self, certificate: &Certificate) -> bool {
        certificate
            .extensions()
            .get("permit-pty")
            .is_some_and(String::is_empty)
    }
}

fn adjacent_config_path(executable_path: &Path) -> Option<PathBuf> {
    executable_path
        .parent()
        .map(|directory| directory.join(CONFIG_FILE_NAME))
}

fn load_config_from_paths(
    explicit_path: Option<&Path>,
    adjacent_path: Option<&Path>,
) -> Result<Option<ServerConfig>> {
    let path = match explicit_path {
        Some(path) => Some(path),
        None => adjacent_path.filter(|path| path.is_file()),
    };
    path.map(ServerConfig::from_file).transpose()
}

/// Load an explicitly selected config, or automatically use `server.conf`
/// beside the executable when present. An absent adjacent file means defaults.
pub fn load_startup_config(explicit_path: Option<&Path>) -> Result<Option<ServerConfig>> {
    let adjacent_path = std::env::current_exe()
        .ok()
        .and_then(|path| adjacent_config_path(&path));
    load_config_from_paths(explicit_path, adjacent_path.as_deref())
}

// ---------------------------------------------------------------------------
// CLI parsing and startup resolution
// ---------------------------------------------------------------------------

/// Effective listener settings selected after config-file discovery.
pub struct Listen {
    pub host: String,
    pub port: u16,
    pub host_key: Option<PathBuf>,
}

/// Flags exactly as written. Absent flags stay `None` so defaults are applied later.
#[derive(Default)]
pub struct Cli {
    pub host: Option<String>,
    /// Kept as text until we know whether a config file makes this value inert.
    pub port: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host_key: Option<PathBuf>,
    pub config: Option<PathBuf>,
}

pub enum CliCommand {
    Help,
    Run(Cli),
}

pub const HELP: &str = r#"Usage: sshd_standalone [--host 0.0.0.0] [--port 2222] [--user admin] [--password admpass] [--host-key PATH] [--config PATH]

--config selects a config file explicitly. Without it, a server.conf beside the
executable is loaded when present. With a config file, its host, port, host-key,
and login settings are used. Configured listen fields override matching flags;
omitted listen fields fall back to command-line values and then defaults.
Authentication is file-only when a config is loaded; --user and --password are
ignored.
Without a config file, command-line values override built-in defaults. The
server listens on 0.0.0.0:2222 and uses admin/admpass for password login.

  host = "0.0.0.0"
  port = 2222
  host-key = "host_key"

  [public_keys]
  ssh-ed25519 AAAA... comment

  [certificates]
  ssh-ed25519 AAAA... comment

  [passwords]
  alice = "secret"

Write host, port, and host-key before any section. Inside [passwords] those
words are user names. Public keys and CA keys are OpenSSH one-line entries.
A listed public key may log in as any user name. A user certificate may log
in when it is signed by a listed CA, names that user as a principal, and
carries no critical options. Shell sessions also require the empty `permit-pty`
certificate extension; commands and SFTP do not. A relative host-key path in
the file is resolved from the file's directory. See examples/server.conf."#;

fn take_value<S>(flag: &str, args: &mut impl Iterator<Item = S>) -> Result<String>
where
    S: AsRef<str>,
{
    let Some(value) = args.next() else {
        bail!("{flag} requires a value");
    };
    let value = value.as_ref();
    if value.is_empty() || value.starts_with("--") {
        bail!("{flag} requires a value");
    }
    Ok(value.to_string())
}

fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<()> {
    if slot.is_some() {
        bail!("duplicate {flag}");
    }
    *slot = Some(value);
    Ok(())
}

pub fn parse_cli<I, S>(args: I) -> Result<CliCommand>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cli = Cli::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "-h" | "--help" => return Ok(CliCommand::Help),
            "--host" => {
                let value = take_value("--host", &mut args)?;
                set_once(&mut cli.host, "--host", value)?;
            }
            "--port" => {
                let value = take_value("--port", &mut args)?;
                set_once(&mut cli.port, "--port", value)?;
            }
            "--user" => {
                let value = take_value("--user", &mut args)?;
                set_once(&mut cli.user, "--user", value)?;
            }
            "--password" => {
                let value = take_value("--password", &mut args)?;
                set_once(&mut cli.password, "--password", value)?;
            }
            "--host-key" => {
                let value = take_value("--host-key", &mut args)?;
                set_once(&mut cli.host_key, "--host-key", PathBuf::from(value))?;
            }
            "--config" => {
                let value = take_value("--config", &mut args)?;
                set_once(&mut cli.config, "--config", PathBuf::from(value))?;
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    Ok(CliCommand::Run(cli))
}

fn parse_cli_port(value: Option<&str>) -> Result<Option<u16>> {
    value
        .map(|value| {
            value
                .parse::<u16>()
                .with_context(|| "--port requires a number from 0 to 65535".to_string())
        })
        .transpose()
}

pub fn resolve_startup(cli: &Cli, file: Option<ServerConfig>) -> Result<(Listen, ServerConfig)> {
    let file_host = file.as_ref().and_then(|config| config.host.as_deref());
    let file_port = file.as_ref().and_then(|config| config.port);
    let file_host_key = file.as_ref().and_then(|config| config.host_key.as_deref());

    let host = file_host
        .or(cli.host.as_deref())
        .unwrap_or(DEFAULT_LISTEN_HOST)
        .to_string();
    let port = match file_port {
        Some(port) => port,
        None => parse_cli_port(cli.port.as_deref())?.unwrap_or(DEFAULT_LISTEN_PORT),
    };
    let host_key = file_host_key
        .or(cli.host_key.as_deref())
        .map(Path::to_path_buf);

    // Authentication is owned exclusively by the config file when one is loaded.
    let auth = file.unwrap_or_else(|| {
        ServerConfig::with_password(
            cli.user.as_deref().unwrap_or(DEFAULT_USER),
            cli.password.as_deref().unwrap_or(DEFAULT_PASSWORD),
        )
    });

    Ok((
        Listen {
            host,
            port,
            host_key,
        },
        auth,
    ))
}

#[cfg(test)]
mod tests {
    use super::{HashAlg, PublicKey, Section, *};
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::Algorithm;
    use russh::keys::PrivateKey;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sshd-auth-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_config(body: &str) -> (TempDir, PathBuf) {
        let dir = TempDir(temp_dir());
        let path = dir.0.join("server.conf");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn config_error(body: &str) -> String {
        let (_dir, path) = write_config(body);
        match ServerConfig::from_file(&path) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("expected {body:?} to fail"),
        }
    }

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    fn openssh(key: &PrivateKey) -> String {
        key.public_key().to_openssh().unwrap().trim().to_string()
    }

    fn user_cert_validity(
        subject: &PrivateKey,
        ca: &PrivateKey,
        principal: Option<&str>,
        critical: bool,
        host: bool,
        valid_after: u64,
        valid_before: u64,
    ) -> Certificate {
        let mut builder = Builder::new_with_random_nonce(
            &mut rand::rng(),
            subject.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();
        builder
            .cert_type(if host { CertType::Host } else { CertType::User })
            .unwrap();
        builder.key_id("test").unwrap();
        if let Some(principal) = principal {
            builder.valid_principal(principal).unwrap();
        } else {
            builder.all_principals_valid().unwrap();
        }
        if critical {
            builder.critical_option("force-command", "true").unwrap();
        }
        builder.sign(ca).unwrap()
    }

    fn user_cert(
        subject: &PrivateKey,
        ca: &PrivateKey,
        principal: Option<&str>,
        critical: bool,
        host: bool,
    ) -> Certificate {
        user_cert_validity(subject, ca, principal, critical, host, 0, u64::MAX)
    }

    /// Entries the test supplies when `examples/server.conf` has deleted a section.
    /// A section that is still in the file is loaded from that file, including
    /// commented lines that the parser skips.
    struct LoginFallback {
        public_key: PrivateKey,
        ca: PrivateKey,
    }

    fn section_present(text: &str, name: &str) -> bool {
        text.lines().any(|raw| {
            let line = raw.trim();
            !line.is_empty() && !line.starts_with('#') && section_name(line) == Some(name)
        })
    }

    fn strip_section(text: &str, name: &str) -> String {
        let mut out = String::new();
        let mut skipping = false;
        for raw in text.lines() {
            let line = raw.trim();
            let header = if line.is_empty() || line.starts_with('#') {
                None
            } else {
                section_name(line)
            };
            if header == Some(name) {
                skipping = true;
                continue;
            }
            if skipping {
                if header.is_some() {
                    skipping = false;
                } else {
                    continue;
                }
            }
            out.push_str(raw);
            out.push('\n');
        }
        out
    }

    fn with_missing_sections(text: &str, fallback: &LoginFallback) -> String {
        let mut text = text.to_string();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if !section_present(&text, "public_keys") {
            text.push_str("[public_keys]\n");
            text.push_str(&openssh(&fallback.public_key));
            text.push('\n');
        }
        if !section_present(&text, "certificates") {
            text.push_str("[certificates]\n");
            text.push_str(&openssh(&fallback.ca));
            text.push('\n');
        }
        if !section_present(&text, "passwords") {
            text.push_str("[passwords]\nalice = \"example-password\"\n");
        }
        text
    }

    struct ScannedLogin {
        passwords: Vec<(String, String)>,
        public_keys: Vec<PublicKey>,
        cas: Vec<PublicKey>,
    }

    /// Count the same lines the parser keeps: a section stays active until the
    /// next header, and blank lines and `#` comments are ignored.
    fn scan_login(text: &str) -> ScannedLogin {
        let mut section: Option<Section> = None;
        let mut scanned = ScannedLogin {
            passwords: Vec::new(),
            public_keys: Vec::new(),
            cas: Vec::new(),
        };
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = section_name(line) {
                section = match name {
                    "public_keys" => Some(Section::PublicKeys),
                    "certificates" => Some(Section::Certificates),
                    "passwords" => Some(Section::Passwords),
                    _ => None,
                };
                continue;
            }
            match section {
                Some(Section::PublicKeys) => {
                    scanned
                        .public_keys
                        .push(PublicKey::from_openssh(line).unwrap());
                }
                Some(Section::Certificates) => {
                    scanned.cas.push(PublicKey::from_openssh(line).unwrap());
                }
                Some(Section::Passwords) => {
                    scanned.passwords.push(parse_password(line).unwrap());
                }
                None => {}
            }
        }
        scanned
    }

    fn describe_scanned(scanned: &ScannedLogin) -> String {
        let mut parts = Vec::new();
        if !scanned.passwords.is_empty() {
            let users: Vec<_> = scanned
                .passwords
                .iter()
                .map(|(user, _)| user.as_str())
                .collect();
            parts.push(format!("password ({})", users.join(", ")));
        }
        if !scanned.public_keys.is_empty() {
            parts.push(format!("public key ({} keys)", scanned.public_keys.len()));
        }
        if !scanned.cas.is_empty() {
            parts.push(format!("certificate ({} CAs)", scanned.cas.len()));
        }
        parts.join(", ")
    }

    fn assert_loaded_login(original: &str, path: &Path, fallback: &LoginFallback) {
        let text = with_missing_sections(original, fallback);
        let config = parse_config(&text, path).unwrap();
        assert!(config.any_method());
        let scanned = scan_login(&text);

        assert_eq!(config.passwords.len(), scanned.passwords.len());
        for (user, password) in &scanned.passwords {
            assert!(config.accepts_password(user, password));
        }
        assert_eq!(config.public_keys.len(), scanned.public_keys.len());
        for key in &scanned.public_keys {
            assert!(config.accepts_public_key(key));
        }
        assert_eq!(config.ca_fingerprints.len(), scanned.cas.len());
        for ca in &scanned.cas {
            let fingerprint = ca.fingerprint(HashAlg::Sha256);
            assert!(config.ca_fingerprints.contains(&fingerprint));
        }
        assert_eq!(config.describe(), describe_scanned(&scanned));

        if !section_present(original, "public_keys") {
            assert!(config.accepts_public_key(fallback.public_key.public_key()));
        }
        if !section_present(original, "certificates") {
            let fingerprint = fallback.ca.public_key().fingerprint(HashAlg::Sha256);
            assert!(config.ca_fingerprints.contains(&fingerprint));
        }
        if !section_present(original, "passwords") {
            assert!(config.accepts_password("alice", "example-password"));
        }

        assert_eq!(config.host(), Some("0.0.0.0"));
        assert_eq!(config.port(), Some(2222));
        assert_eq!(config.host_key(), None);
    }

    #[test]
    fn file_enables_only_valid_entries_and_keeps_them_independent() {
        let alice = ed25519();
        let ca = ed25519();
        let cert = user_cert(&alice, &ca, Some("alice"), false, false);
        let body = format!(
            "[public_keys]\n{}\n\n[certificates]\n{}\n\n[passwords]\nbob = \"secret with spaces\"\n",
            openssh(&alice),
            openssh(&ca)
        );
        let (_dir, path) = write_config(&body);
        let config = ServerConfig::from_file(&path).unwrap();
        assert!(config.accepts_password("bob", "secret with spaces"));
        assert!(!config.accepts_password("admin", "admpass"));
        assert!(config.accepts_public_key(alice.public_key()));
        assert!(!config.accepts_public_key(ed25519().public_key()));
        assert!(config.reject_certificate_reason("alice", &cert).is_none());
        assert!(config.reject_certificate_reason("bob", &cert).is_some());
        let another = user_cert(&ed25519(), &ca, Some("alice"), false, false);
        assert!(config
            .reject_certificate_reason("alice", &another)
            .is_none());
        let other_ca = ed25519();
        assert!(config
            .reject_certificate_reason(
                "alice",
                &user_cert(&alice, &other_ca, Some("alice"), false, false)
            )
            .is_some());
        assert!(config
            .reject_certificate_reason("alice", &user_cert(&alice, &ca, None, false, false))
            .is_some());
        assert!(config
            .reject_certificate_reason("alice", &user_cert(&alice, &ca, Some("alice"), true, false))
            .is_some());
        assert!(config
            .reject_certificate_reason("alice", &user_cert(&alice, &ca, Some("alice"), false, true))
            .is_some());
        assert!(config
            .reject_certificate_reason(
                "alice",
                &user_cert_validity(&alice, &ca, Some("alice"), false, false, 0, 1)
            )
            .is_some());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(config
            .reject_certificate_reason(
                "alice",
                &user_cert_validity(
                    &alice,
                    &ca,
                    Some("alice"),
                    false,
                    false,
                    now + 3600,
                    u64::MAX
                )
            )
            .is_some());
        assert!(!config.certificate_allows_pty(&cert));
        let mut pty_builder =
            Builder::new_with_random_nonce(&mut rand::rng(), alice.public_key(), 0, u64::MAX)
                .unwrap();
        pty_builder
            .cert_type(CertType::User)
            .unwrap()
            .key_id("pty-cert")
            .unwrap()
            .valid_principal("alice")
            .unwrap()
            .extension("permit-pty", "")
            .unwrap();
        let pty_cert = pty_builder.sign(&ca).unwrap();
        assert!(config.certificate_allows_pty(&pty_cert));
        assert_eq!(
            &*config.method_set(),
            &[MethodKind::Password, MethodKind::PublicKey]
        );
    }

    #[test]
    fn sections_may_be_empty_commented_or_omitted() {
        let kept = ed25519();
        let skipped = ed25519();
        let ca = ed25519();
        let body = format!(
            "[public_keys]\n#{}\n{}\n\n[certificates]\n{}\n\n[passwords]\nalice = \"example-password\"\n",
            openssh(&skipped),
            openssh(&kept),
            openssh(&ca)
        );
        let (_dir, path) = write_config(&body);
        let config = ServerConfig::from_file(&path).unwrap();
        assert!(config.accepts_public_key(kept.public_key()));
        assert!(!config.accepts_public_key(skipped.public_key()));

        let (_dir, path) = write_config(&format!(
            "[public_keys]\n\n[certificates]\n{}\n\n[passwords]\nalice = \"example-password\"\n",
            openssh(&ca)
        ));
        let config = ServerConfig::from_file(&path).unwrap();
        assert!(!config.allows_public_key());
        assert!(config.allows_certificate());
        assert!(config.accepts_password("alice", "example-password"));

        let (_dir, path) = write_config(&format!(
            "[public_keys]\n{}\n\n[passwords]\nalice = \"example-password\"\n",
            openssh(&kept)
        ));
        let config = ServerConfig::from_file(&path).unwrap();
        assert!(!config.allows_certificate());
        assert!(config.accepts_public_key(kept.public_key()));
    }

    #[test]
    fn each_login_section_advertises_only_its_method() {
        let key = ed25519();
        let ca = ed25519();
        let (_dir, path) = write_config(&format!("[public_keys]\n{}\n", openssh(&key)));
        assert_eq!(
            &*ServerConfig::from_file(&path).unwrap().method_set(),
            &[MethodKind::PublicKey]
        );

        let (_dir, path) = write_config(&format!("[certificates]\n{}\n", openssh(&ca)));
        assert_eq!(
            &*ServerConfig::from_file(&path).unwrap().method_set(),
            &[MethodKind::PublicKey]
        );

        assert_eq!(
            &*ServerConfig::with_password("alice", "secret").method_set(),
            &[MethodKind::Password]
        );
    }

    #[test]
    fn malformed_lines_and_empty_file_fail() {
        let (_dir, path) = write_config("[public_keys]\nnot-a-key\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let (_dir, path) = write_config("# nothing\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let (_dir, path) = write_config("Example 1\n[passwords]\nalice = \"secret\"\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let (_dir, path) = write_config("[trusted_user_ca_keys]\nssh-ed25519 AAAA\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let error = config_error("[passwords]\nalice = \"secret\"\n[passwords]\n");
        assert!(error.contains("duplicate section [passwords]"), "{error}");
        assert!(parse_value("\"secret\"suffix\"").is_err());
        assert_eq!(parse_value("\"secret\"").unwrap(), "secret");
        assert_eq!(
            parse_value(r#""C:\keys\host_key""#).unwrap(),
            r"C:\keys\host_key"
        );
    }

    #[test]
    fn startup_config_uses_explicit_path_or_existing_adjacent_file() {
        let root = TempDir(temp_dir());
        let executable = root.0.join("bin").join("sshd_standalone.exe");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        let adjacent = adjacent_config_path(&executable).unwrap();
        std::fs::write(&adjacent, "[passwords]\nadjacent = secret\n").unwrap();

        let explicit = root.0.join("custom.conf");
        std::fs::write(&explicit, "[passwords]\nexplicit = secret\n").unwrap();

        let selected = load_config_from_paths(Some(&explicit), Some(&adjacent))
            .unwrap()
            .expect("explicit config should load");
        assert!(selected.accepts_password("explicit", "secret"));
        assert!(!selected.accepts_password("adjacent", "secret"));

        let selected = load_config_from_paths(None, Some(&adjacent))
            .unwrap()
            .expect("adjacent config should load");
        assert!(selected.accepts_password("adjacent", "secret"));

        let missing = root.0.join("missing.conf");
        assert!(load_config_from_paths(None, Some(&missing))
            .unwrap()
            .is_none());
        assert!(load_config_from_paths(Some(&missing), Some(&adjacent)).is_err());
    }

    #[test]
    fn server_settings_are_optional_and_paths_are_relative_to_the_config() {
        let (dir, path) = write_config(
            "port = \"2200\"\nhost = 127.0.0.1\nhost-key = \"keys/host_key\"\n\n[passwords]\nalice = \"secret\"\n",
        );
        let config = ServerConfig::from_file(&path).unwrap();
        assert_eq!(config.host(), Some("127.0.0.1"));
        assert_eq!(config.port(), Some(2200));
        assert_eq!(
            config.host_key(),
            Some(dir.0.join("keys").join("host_key").as_path())
        );

        let (_dir, path) = write_config("[passwords]\nalice = \"secret\"\n");
        let config = ServerConfig::from_file(&path).unwrap();
        assert_eq!(config.host(), None);
        assert_eq!(config.port(), None);
        assert_eq!(config.host_key(), None);

        let (_dir, path) = write_config("port = nope\n[passwords]\nalice = \"secret\"\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let (_dir, path) = write_config("host = \"\"\n[passwords]\nalice = \"secret\"\n");
        assert!(ServerConfig::from_file(&path).is_err());
        let error =
            config_error("host = \"127.0.0.1\"\nhost = \"10.0.0.1\"\n[passwords]\nalice = \"s\"\n");
        assert!(
            error.contains("duplicate host \"127.0.0.1\" and \"10.0.0.1\""),
            "{error}"
        );

        let error = config_error("port = 2200\nport = \"2201\"\n[passwords]\nalice = \"s\"\n");
        assert!(
            error.contains("duplicate port 2200 and \"2201\""),
            "{error}"
        );

        let error = config_error(
            "host-key = \"keys/one\"\nhost-key = \"keys/two\"\n[passwords]\nalice = \"s\"\n",
        );
        assert!(error.contains("duplicate host-key"), "{error}");
        assert!(error.contains("keys") && error.contains("two"), "{error}");

        let error = config_error("[passwords]\nalice = \"one\"\nalice = \"two\"\n");
        assert!(
            error.contains("duplicate password user \"alice\""),
            "{error}"
        );
        assert!(!error.contains("one") && !error.contains("two"), "{error}");

        let error = config_error("[passwords]\nalice = \"unterminated\n");
        assert!(
            error.contains("invalid quoted value") || error.contains("invalid password entry"),
            "{error}"
        );
        let error = config_error("port = \"2222\n[passwords]\nalice = secret\n");
        assert!(error.contains("invalid quoted value"), "{error}");
        let error = config_error("[passwords]\nalice = \"secret\"suffix\"\n");
        assert!(error.contains("invalid password entry"), "{error}");
        assert_eq!(
            parse_password("alice = \"quote: \\\"\"").unwrap().1,
            "quote: \""
        );

        let (_dir, path) = write_config("[passwords]\nalice = \"secret\"\nport = 2201\n");
        let config = ServerConfig::from_file(&path).unwrap();
        assert_eq!(config.port(), None);
        assert!(config.accepts_password("alice", "secret"));
        assert!(config.accepts_password("port", "2201"));

        let absolute = dir.0.join("absolute-host-key");
        let (dir, path) = write_config(&format!(
            "host-key = \"{}\"\n[passwords]\nalice = \"secret\"\n",
            absolute.display()
        ));
        let config = ServerConfig::from_file(&path).unwrap();
        assert_eq!(config.host_key(), Some(absolute.as_path()));
        drop(dir);
    }

    #[test]
    fn example_config_enables_password_key_and_certificate() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/server.conf");
        let example = std::fs::read_to_string(&path).unwrap();
        let fallback = LoginFallback {
            public_key: ed25519(),
            ca: ed25519(),
        };
        assert_loaded_login(&example, &path, &fallback);

        for name in ["public_keys", "certificates", "passwords"] {
            let stripped = strip_section(&example, name);
            assert!(!section_present(&stripped, name), "{name}");
            assert_loaded_login(&stripped, &path, &fallback);
        }

        let mut bare = example;
        for name in ["public_keys", "certificates", "passwords"] {
            bare = strip_section(&bare, name);
        }
        assert_loaded_login(&bare, &path, &fallback);
    }

    #[test]
    fn no_config_uses_cli_overrides_and_built_in_defaults() {
        let CliCommand::Run(empty) = parse_cli(std::iter::empty::<&str>()).unwrap() else {
            panic!("help");
        };
        let (listen, config) = resolve_startup(&empty, None).unwrap();
        assert_eq!(listen.host, "0.0.0.0");
        assert_eq!(listen.port, 2222);
        assert_eq!(listen.host_key, None);
        assert!(config.accepts_password("admin", "admpass"));

        let CliCommand::Run(cli_overrides) = parse_cli([
            "--host",
            "10.0.0.8",
            "--port",
            "22",
            "--user",
            "bob",
            "--password",
            "s",
            "--host-key",
            "cli-key",
        ])
        .unwrap() else {
            panic!("help");
        };
        let (listen, config) = resolve_startup(&cli_overrides, None).unwrap();
        assert_eq!(listen.host, "10.0.0.8");
        assert_eq!(listen.port, 22);
        assert_eq!(listen.host_key.as_deref(), Some(Path::new("cli-key")));
        assert!(config.accepts_password("bob", "s"));
    }

    #[test]
    fn config_file_merges_listen_fields_but_owns_authentication() {
        let CliCommand::Run(cli_with_bad_port) = parse_cli([
            "--host",
            "10.0.0.8",
            "--port",
            "not-a-port",
            "--user",
            "bob",
            "--password",
            "s",
            "--host-key",
            "cli-key",
            "--config",
            "server.conf",
        ])
        .unwrap() else {
            panic!("help");
        };
        let (dir, file_config_path) = write_config(
            "host = \"127.0.0.1\"\nport = 2200\nhost-key = \"keys/host_key\"\n[passwords]\nalice = \"secret\"\n",
        );
        let file = ServerConfig::from_file(&file_config_path).unwrap();
        let (listen, config) = resolve_startup(&cli_with_bad_port, Some(file)).unwrap();
        assert_eq!(listen.host, "127.0.0.1");
        assert_eq!(listen.port, 2200);
        assert_eq!(
            listen.host_key.as_deref(),
            Some(dir.0.join("keys").join("host_key").as_path())
        );
        assert!(config.accepts_password("alice", "secret"));
        assert!(!config.accepts_password("bob", "s"));
        assert!(resolve_startup(&cli_with_bad_port, None).is_err());

        let CliCommand::Run(cli_overrides) = parse_cli([
            "--host",
            "10.0.0.8",
            "--port",
            "22",
            "--user",
            "bob",
            "--password",
            "s",
            "--host-key",
            "cli-key",
        ])
        .unwrap() else {
            panic!("help");
        };

        // Missing listen fields fall back to CLI values, but credentials in the
        // file remain the only password logins when a config is loaded.
        let (_listen_fallback_dir, listen_fallback_path) =
            write_config("[passwords]\nalice = \"secret\"\n");
        let file = ServerConfig::from_file(&listen_fallback_path).unwrap();
        let (listen, config) = resolve_startup(&cli_overrides, Some(file)).unwrap();
        assert_eq!(listen.host, "10.0.0.8");
        assert_eq!(listen.port, 22);
        assert_eq!(listen.host_key.as_deref(), Some(Path::new("cli-key")));
        assert!(config.accepts_password("alice", "secret"));
        assert!(!config.accepts_password("bob", "s"));

        // When the file omits `port`, an invalid CLI `--port` is still validated.
        let file = ServerConfig::from_file(&listen_fallback_path).unwrap();
        assert!(resolve_startup(&cli_with_bad_port, Some(file)).is_err());

        // CLI password credentials do not add password auth to a key-only file.
        let key = ed25519();
        let (_key_only_dir, key_only_path) =
            write_config(&format!("[public_keys]\n{}\n", openssh(&key)));
        let file = ServerConfig::from_file(&key_only_path).unwrap();
        let (_, config) = resolve_startup(&cli_overrides, Some(file)).unwrap();
        assert!(config.accepts_public_key(key.public_key()));
        assert!(!config.accepts_password("bob", "s"));
    }

    #[test]
    fn cli_validation_rejects_malformed_flags_and_defers_port_check() {
        assert!(matches!(parse_cli(["-h"]), Ok(CliCommand::Help)));
        assert!(parse_cli(["--port"]).is_err());
        assert!(parse_cli(["--port", "nope"]).is_ok());
        assert!(parse_cli(["--host", "--port"]).is_err());
        assert!(parse_cli(["--port", "1", "--port", "2"]).is_err());
        assert!(parse_cli(["--wat"]).is_err());
        assert!(parse_cli(["--host", ""]).is_err());
    }
}
