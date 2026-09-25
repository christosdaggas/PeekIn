//! Runs the `peekin` CLI through `pkexec`, or directly against private directories in `--dev` mode.

use peekin_core::i18n::tr;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub cli: PathBuf,
    pub helper: PathBuf,
    pub elevate: bool,
    pub config_dir: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub user: String,
}

/// pkexec exit codes when the authentication dialog is dismissed or denied.
pub const PKEXEC_DISMISSED: i32 = 126;
pub const PKEXEC_NOT_AUTHORIZED: i32 = 127;

impl Backend {
    pub fn config_file(&self) -> PathBuf {
        self.config_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/peekin"))
            .join("config.ini")
    }

    pub fn argv(&self, args: &[String]) -> Vec<String> {
        let mut argv = Vec::new();
        if self.elevate {
            argv.push("pkexec".to_string());
        }
        argv.push(self.cli.display().to_string());
        for (flag, dir) in [
            ("--config-dir", &self.config_dir),
            ("--data-dir", &self.data_dir),
        ] {
            if let Some(dir) = dir {
                argv.push(flag.to_string());
                argv.push(dir.display().to_string());
            }
        }
        argv.extend(args.iter().cloned());
        argv
    }

    /// The narrow helper in production; the normal CLI against private fixtures in dev mode.
    pub fn management_argv(&self, operation: &str, args: &[String]) -> Vec<String> {
        if self.elevate {
            let mut out = vec![
                "pkexec".into(),
                self.helper.display().to_string(),
                operation.into(),
            ];
            out.extend(args.iter().cloned());
            out
        } else {
            let command = match operation {
                "enroll" => "import-model",
                "add-samples" => "import-samples",
                other => other,
            };
            let mut command_args = vec![command.to_string()];
            command_args.extend(args.iter().cloned());
            command_args.extend(["-U".into(), self.user.clone()]);
            self.argv(&command_args)
        }
    }

    /// The CLI's root check is skipped in dev mode only.
    pub fn env(&self) -> Vec<(&'static str, &'static str)> {
        if self.elevate {
            Vec::new()
        } else {
            vec![("EUID_CHECK_SKIP", "1")]
        }
    }
}

/// Last meaningful line of a failed command, without the "Error: " prefix.
pub fn error_summary(exit_code: i32, output: &str) -> String {
    match exit_code {
        PKEXEC_DISMISSED | PKEXEC_NOT_AUTHORIZED => return tr("Authorization was cancelled"),
        _ => {}
    }
    output
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .map(|l| l.trim_start_matches("Error: ").to_string())
        .unwrap_or_else(|| format!("peekin exited with code {exit_code}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn production_uses_pkexec_and_default_paths() {
        let b = Backend {
            cli: "/usr/bin/peekin".into(),
            helper: "/usr/libexec/peekin/peekin-helper".into(),
            elevate: true,
            config_dir: None,
            data_dir: None,
            user: "alice".into(),
        };
        assert_eq!(
            b.argv(&args(&["set", "timeout", "5"])),
            ["pkexec", "/usr/bin/peekin", "set", "timeout", "5"]
        );
        assert!(b.env().is_empty());
        assert_eq!(b.config_file(), PathBuf::from("/etc/peekin/config.ini"));
        let management = b.management_argv("remove", &["7".into()]);
        assert_eq!(
            management,
            ["pkexec", "/usr/libexec/peekin/peekin-helper", "remove", "7"]
        );
        assert!(!management.iter().any(|a| a == "-U" || a == "--config-dir"));
    }

    #[test]
    fn dev_mode_runs_directly_against_private_dirs() {
        let b = Backend {
            cli: "/src/target/debug/peekin".into(),
            helper: "/src/target/debug/peekin-helper".into(),
            elevate: false,
            config_dir: Some("/tmp/h/etc".into()),
            data_dir: Some("/tmp/h/data".into()),
            user: "alice".into(),
        };
        assert_eq!(
            b.argv(&args(&["list", "--plain", "-U", "alice"])),
            [
                "/src/target/debug/peekin",
                "--config-dir",
                "/tmp/h/etc",
                "--data-dir",
                "/tmp/h/data",
                "list",
                "--plain",
                "-U",
                "alice"
            ]
        );
        assert_eq!(b.env(), [("EUID_CHECK_SKIP", "1")]);
        assert_eq!(b.config_file(), PathBuf::from("/tmp/h/etc/config.ini"));
    }

    #[test]
    fn error_summaries() {
        assert_eq!(
            error_summary(126, "whatever"),
            "Authorization was cancelled"
        );
        assert_eq!(
            error_summary(
                1,
                "New face model\nError: No face in view; enrollment stopped\n\n"
            ),
            "No face in view; enrollment stopped"
        );
        assert_eq!(error_summary(3, ""), "peekin exited with code 3");
    }
}
