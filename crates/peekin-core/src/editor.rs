//! `peekin config`: open config.ini in `$EDITOR`, else nano, else vi.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorError {
    NotFound,
}

impl std::fmt::Display for EditorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(
                f,
                "No text editor found. Install nano or vi, or set EDITOR \
                 (with sudo, 'sudo -E peekin config' keeps your EDITOR)."
            ),
        }
    }
}

impl std::error::Error for EditorError {}

/// Search `PATH` for `name`.
fn which(name: &str, path_dirs: &[&Path]) -> Option<PathBuf> {
    let name_path = Path::new(name);
    // Paths with a separator are used as given.
    if name.contains('/') {
        return is_executable(name_path).then(|| name_path.to_path_buf());
    }
    for dir in path_dirs {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.is_file()
        && std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

fn path_dirs_from_env(path_var: &str) -> Vec<PathBuf> {
    std::env::split_paths(path_var).collect()
}

pub fn resolve_editor(
    preferred_editor: Option<&str>,
    path_var: &str,
) -> Result<PathBuf, EditorError> {
    let dirs: Vec<PathBuf> = path_dirs_from_env(path_var);
    let dir_refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();

    if let Some(pref) = preferred_editor {
        if !pref.is_empty() {
            if let Some(found) = which(pref, &dir_refs) {
                return Ok(found);
            }
        }
    }
    if let Some(nano) = which("nano", &dir_refs) {
        return Ok(nano);
    }
    if let Some(vi) = which("vi", &dir_refs) {
        return Ok(vi);
    }
    Err(EditorError::NotFound)
}

pub fn resolve_editor_from_env() -> Result<PathBuf, EditorError> {
    let pref = std::env::var("EDITOR").ok();
    let path_var = std::env::var("PATH").unwrap_or_default();
    resolve_editor(pref.as_deref(), &path_var)
}

pub fn editor_display_name(editor: &Path) -> String {
    editor
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| editor.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn fake_bin_dir(name: &str, bins: &[&str]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("peekin-editor-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for b in bins {
            let p = dir.join(b);
            fs::write(&p, "#!/bin/sh\n").unwrap();
            let mut perms = fs::metadata(&p).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&p, perms).unwrap();
        }
        dir
    }

    #[test]
    fn prefers_editor_env() {
        let dir = fake_bin_dir("pref", &["nano", "vi", "emacs"]);
        let path_var = dir.to_string_lossy().to_string();
        let got = resolve_editor(Some("emacs"), &path_var).unwrap();
        assert_eq!(got, dir.join("emacs"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_nano_then_vi() {
        let dir = fake_bin_dir("fallback", &["nano", "vi"]);
        let path_var = dir.to_string_lossy().to_string();
        assert_eq!(resolve_editor(None, &path_var).unwrap(), dir.join("nano"));
        let _ = fs::remove_file(dir.join("nano"));
        assert_eq!(
            resolve_editor(Some("does-not-exist"), &path_var).unwrap(),
            dir.join("vi")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_when_nothing_found() {
        let dir = fake_bin_dir("empty", &[]);
        let path_var = dir.to_string_lossy().to_string();
        assert_eq!(resolve_editor(None, &path_var), Err(EditorError::NotFound));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn display_name_is_basename() {
        assert_eq!(editor_display_name(Path::new("/usr/bin/nano")), "nano");
    }
}
