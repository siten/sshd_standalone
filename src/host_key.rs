//! Ed25519 host key persistence with fallback to an in-memory key.

use std::path::{Path, PathBuf};

fn executable_host_key_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|directory| directory.join("host_key"))
}

fn displayable_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        }
    })
}

fn create_host_key_file(path: &Path) -> anyhow::Result<()> {
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

fn open_or_create_host_key(path: &Path) -> Option<russh::keys::PrivateKey> {
    if path.exists() {
        return match russh::keys::load_secret_key(path, None) {
            Ok(key) => Some(key),
            Err(error) => {
                log::warn!(
                    "could not load host key '{}', trying fallback: {error}",
                    path.display()
                );
                None
            }
        };
    }

    match create_host_key_file(path) {
        Ok(()) => match russh::keys::load_secret_key(path, None) {
            Ok(key) => Some(key),
            Err(error) => {
                log::warn!(
                    "could not load newly-created host key '{}': {error}",
                    path.display()
                );
                None
            }
        },
        Err(error) => {
            log::warn!(
                "cannot persist host key at '{}', trying fallback: {error}",
                path.display()
            );
            None
        }
    }
}

/// Candidate order for the persistent host identity: explicit path first,
/// then the executable directory, without trying an identical path twice.
fn host_key_candidates(requested: Option<&Path>, beside_exe: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = requested {
        paths.push(path.to_path_buf());
    }
    if let Some(path) = beside_exe {
        if !paths.iter().any(|existing| existing == path) {
            paths.push(path.to_path_buf());
        }
    }
    paths
}

/// Load or create one Ed25519 host key.
///
/// Try the requested path, then `host_key` beside the executable when that path
/// is different. An existing file is loaded or skipped. A missing file is
/// created or skipped. When every candidate is skipped, keep a key in memory.
pub fn load_or_create_host_key(
    requested: Option<&Path>,
) -> anyhow::Result<(russh::keys::PrivateKey, Option<PathBuf>)> {
    let beside_exe = executable_host_key_path();
    for path in host_key_candidates(requested, beside_exe.as_deref()) {
        if let Some(key) = open_or_create_host_key(&path) {
            return Ok((key, Some(displayable_path(&path))));
        }
    }

    log::warn!("host key is not persistent; using a new in-memory key for this run");
    let key = russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)?;
    Ok((key, None))
}

#[cfg(test)]
mod tests {
    use super::host_key_candidates;
    use std::path::PathBuf;

    #[test]
    fn host_key_candidates_try_requested_path_then_executable_path_once() {
        let requested = PathBuf::from("requested").join("host_key");
        let beside = PathBuf::from("exe").join("host_key");
        assert_eq!(
            host_key_candidates(Some(&requested), Some(&beside)),
            vec![requested.clone(), beside.clone()]
        );
        assert_eq!(
            host_key_candidates(Some(&beside), Some(&beside)),
            vec![beside.clone()]
        );
        assert_eq!(host_key_candidates(None, Some(&beside)), vec![beside]);
        assert!(host_key_candidates(None, None).is_empty());
    }
}
