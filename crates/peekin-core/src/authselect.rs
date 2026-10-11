//! PAM integration through a copy of the active Fedora authselect profile.
//!
//! Generated PAM files are never edited. Unrecognised authentication control
//! flow is refused, the previous selection is saved, and it is restored only
//! while our profile is still active.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PROFILE: &str = "custom/peekin";
pub const RULE: &str = "auth        [success=done default=ignore]    pam_peekin.so\n";
const TEMPLATES: [&str; 2] = ["system-auth", "password-auth"];
const FLAGS: [&str; 2] = ["--system-auth", "--password-auth"];

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub control: String,
    pub module: String,
    pub args: Vec<String>,
}

impl Rule {
    fn is(&self, control: &str, module: &str) -> bool {
        self.control == control && self.module == module
    }

    fn has_arg(&self, arg: &str) -> bool {
        self.args.iter().any(|a| a == arg)
    }
}

/// Non-comment lines, split into words (a comment starts at " #").
fn auth_lines(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines().filter_map(|original| {
        let line = original.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            None
        } else {
            Some(line.split_whitespace().collect())
        }
    })
}

fn is_auth_line(parts: &[&str]) -> bool {
    matches!(parts[0], "auth" | "-auth" | "@include")
}

pub fn auth_rules(text: &str) -> Result<Vec<Rule>, Error> {
    let mut rules = Vec::new();
    for parts in auth_lines(text).filter(|p| is_auth_line(p)) {
        if parts[0] != "auth" || parts.len() < 3 {
            return err("unsupported authselect control flow");
        }
        let (control, module, args) = if parts[1].starts_with('[') {
            let end = (1..parts.len()).find(|&i| parts[i].ends_with(']'));
            match end {
                Some(end) if end + 1 < parts.len() => {
                    (parts[1..=end].join(" "), parts[end + 1], &parts[end + 2..])
                }
                _ => return err("malformed PAM control"),
            }
        } else {
            (parts[1].to_string(), parts[2], &parts[3..])
        };
        rules.push(Rule {
            control,
            module: module.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        });
    }
    Ok(rules)
}

/// `[key=value ...]` as a map; `None` for a plain control like `required`.
fn control_values(control: &str) -> Result<Option<BTreeMap<&str, &str>>, Error> {
    let Some(inner) = control.strip_prefix('[').and_then(|c| c.strip_suffix(']')) else {
        return Ok(None);
    };
    let mut values = BTreeMap::new();
    for item in inner.split_whitespace() {
        let mut kv = item.splitn(3, '=');
        match (kv.next(), kv.next(), kv.next()) {
            (Some(k), Some(v), None) if !k.is_empty() && !v.is_empty() => {
                if values.insert(k, v).is_some() {
                    return err("malformed PAM control");
                }
            }
            _ => return err("malformed PAM control"),
        }
    }
    Ok(Some(values))
}

fn control_is(control: &str, expected: &[(&str, &str)]) -> Result<bool, Error> {
    Ok(control_values(control)?.is_some_and(|v| {
        v.len() == expected.len() && expected.iter().all(|(k, x)| v.get(k) == Some(x))
    }))
}

const REGULAR_DISPATCH: [(&str, &str); 3] =
    [("default", "1"), ("ignore", "ignore"), ("success", "ok")];

fn is_regular_dispatch(rule: &Rule) -> Result<bool, Error> {
    Ok(rule.module == "pam_usertype.so"
        && rule.has_arg("isregular")
        && control_is(&rule.control, &REGULAR_DISPATCH)?)
}

fn validate_sssd_tail(rules: &[Rule], start: usize, unix: usize, deny: usize) -> Result<(), Error> {
    let mut i = start;
    if i >= unix || !is_regular_dispatch(&rules[i])? {
        return err("unsupported SSSD user dispatch");
    }
    i += 1;
    if i >= unix || rules[i].module != "pam_localuser.so" {
        return err("unsupported SSSD local-user dispatch");
    }
    let skips_smartcard = control_is(
        &rules[i].control,
        &[("default", "2"), ("ignore", "ignore"), ("success", "ok")],
    )?;
    if !skips_smartcard && !control_is(&rules[i].control, &REGULAR_DISPATCH)? {
        return err("unsupported SSSD local-user control");
    }
    i += 1;
    if skips_smartcard {
        let cert = [
            ("success", "done"),
            ("authinfo_unavail", "ignore"),
            ("user_unknown", "ignore"),
            ("ignore", "ignore"),
            ("default", "die"),
        ];
        if i >= unix
            || rules[i].module != "pam_sss.so"
            || !control_is(&rules[i].control, &cert)?
            || !rules[i].has_arg("try_cert_auth")
        {
            return err("unsupported SSSD smartcard dispatch");
        }
        i += 1;
    }
    if i != unix {
        return err("unsupported rules before the password fallback");
    }

    i = unix + 1;
    if i < deny && rules[i].is("sufficient", "pam_systemd_home.so") {
        i += 1;
    }
    if i < deny
        && is_regular_dispatch(&rules[i])?
        && i + 1 < deny
        && rules[i + 1].is("sufficient", "pam_sss_gss.so")
    {
        i += 2;
    }
    if i + 1 >= deny
        || !is_regular_dispatch(&rules[i])?
        || !rules[i + 1].is("sufficient", "pam_sss.so")
        || !rules[i + 1].has_arg("forward_pass")
    {
        return err("SSSD password fallback is missing or altered");
    }
    i += 2;
    if i < deny && rules[i].is("required", "pam_faillock.so") && rules[i].has_arg("authfail") {
        i += 1;
    }
    if i < deny && rules[i].is("optional", "pam_gnome_keyring.so") {
        i += 1;
    }
    if i != deny {
        return err("unsupported rule after the SSSD password fallback");
    }
    Ok(())
}

/// sudo and GDM must use Fedora's stock include/substack layout.
pub fn validate_services(pam_dir: &Path) -> Result<(), Error> {
    let read = |name: &str| -> Result<Vec<Vec<String>>, Error> {
        let text = fs::read_to_string(pam_dir.join(name))?;
        Ok(auth_lines(&text)
            .filter(|p| is_auth_line(p))
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect())
    };
    let words = |lines: &[&str]| -> Vec<Vec<String>> {
        lines
            .iter()
            .map(|l| l.split_whitespace().map(str::to_string).collect())
            .collect()
    };
    if read("sudo")? != words(&["auth include system-auth"]) {
        return err("unsupported sudo authentication layout");
    }
    let gdm = read("gdm-password")?;
    let gate = words(&["auth [success=done ignore=ignore default=bad] pam_selinux_permit.so"]);
    if gdm.first() != gate.first() {
        return err("unsupported GDM SELinux gate");
    }
    let full = words(&[
        "auth substack password-auth",
        "auth optional pam_gnome_keyring.so",
        "auth include postlogin",
    ]);
    let short = words(&["auth substack password-auth"]);
    if gdm[1..] != full[..] && gdm[1..] != short[..] {
        return err("unsupported GDM authentication layout");
    }
    Ok(())
}

fn positions(rules: &[Rule], module: &str) -> Vec<usize> {
    (0..rules.len())
        .filter(|&i| rules[i].module == module)
        .collect()
}

/// Check that face login can only ever add a way in before the password,
/// never skip or override another rule. `installed`: our rule must be present.
pub fn validate_stack(text: &str, installed: bool) -> Result<(), Error> {
    let auth = auth_rules(text)?;
    if auth.is_empty() {
        return err("unsupported authselect control flow");
    }
    let face = positions(&auth, "pam_peekin.so");
    let mut unix = positions(&auth, "pam_unix.so");
    let mut deny = positions(&auth, "pam_deny.so");
    if unix.len() != 1
        || deny.len() != 1
        || auth[unix[0]].control != "sufficient"
        || !matches!(auth[deny[0]].control.as_str(), "required" | "requisite")
        || deny[0] != auth.len() - 1
    {
        return err("authselect profile has no single supported password fallback");
    }

    let mut dispatch = unix[0];
    for (i, rule) in auth.iter().enumerate().take(unix[0]) {
        if is_regular_dispatch(rule)? {
            dispatch = i;
            break;
        }
    }
    let rest: Vec<Rule>;
    if installed {
        let ours = Rule {
            control: "[success=done default=ignore]".into(),
            module: "pam_peekin.so".into(),
            args: vec![],
        };
        if face.len() != 1 || Some(face[0]) != dispatch.checked_sub(1) || auth[face[0]] != ours {
            return err("PeekIn rule missing or in an unsafe position");
        }
        rest = auth
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != face[0])
            .map(|(_, r)| r.clone())
            .collect();
        unix = vec![unix[0] - 1];
        deny = vec![deny[0] - 1];
        dispatch = face[0];
    } else if !face.is_empty() {
        return err("authselect profile already mentions PeekIn");
    } else {
        rest = auth;
    }

    for rule in &rest[..dispatch] {
        let values = control_values(&rule.control)?;
        if let Some(values) = &values {
            if values
                .values()
                .any(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()))
            {
                return err("numeric PAM jump before PeekIn is unsupported");
            }
        }
        if values.is_some()
            || !matches!(
                rule.control.as_str(),
                "required" | "requisite" | "sufficient"
            )
        {
            return err("unsupported pre-face PAM control");
        }
    }

    if dispatch < unix[0] {
        return validate_sssd_tail(&rest, dispatch, unix[0], deny[0]);
    }
    let mut i = unix[0] + 1;
    if i < deny[0] && rest[i].is("required", "pam_faillock.so") && rest[i].has_arg("authfail") {
        i += 1;
    }
    if i < deny[0] && rest[i].is("optional", "pam_gnome_keyring.so") {
        i += 1;
    }
    if i != deny[0] {
        return err("mandatory post-password PAM rule might be skipped");
    }
    Ok(())
}

fn words_are(row: &str, expected: &[&str]) -> bool {
    let words: Vec<&str> = row.split_whitespace().collect();
    words.len() >= expected.len() && words[..expected.len()] == *expected
}

/// Insert [`RULE`] before the SSSD user dispatch, or else before pam_unix.
pub fn insert_rule(template: &str) -> Result<String, Error> {
    let mut rows: Vec<&str> = template.split_inclusive('\n').collect();
    let unix: Vec<usize> = (0..rows.len())
        .filter(|&i| words_are(rows[i], &["auth", "sufficient", "pam_unix.so"]))
        .collect();
    let dispatch_words = [
        "auth",
        "[default=1",
        "ignore=ignore",
        "success=ok]",
        "pam_usertype.so",
        "isregular",
    ];
    let dispatch: Vec<usize> = if unix.len() == 1 {
        (0..unix[0])
            .filter(|&i| words_are(rows[i], &dispatch_words))
            .collect()
    } else {
        vec![]
    };
    let mentions_us = rows
        .iter()
        .any(|r| r.contains("pam_peekin.so") && !r.trim_start().starts_with('#'));
    if unix.len() != 1 || dispatch.len() > 1 || mentions_us {
        return err("profile template has no unique, unmodified pam_unix rule");
    }
    rows.insert(dispatch.first().copied().unwrap_or(unix[0]), RULE);
    Ok(rows.concat())
}

/// Whether a PAM file has an active (uncommented) line naming pam_peekin.so.
pub fn file_uses_module(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|body| {
        body.lines().any(|line| {
            let line = line.trim_start();
            !line.starts_with('#') && line.contains("pam_peekin.so")
        })
    })
}

/// Whether `/etc/pam.d/<service>` reaches pam_peekin.so for authentication:
/// directly, or through an included or substacked `system-auth` or
/// `password-auth` that has the rule.
pub fn service_uses_module(pam_dir: &Path, service: &str) -> bool {
    let Ok(body) = fs::read_to_string(pam_dir.join(service)) else {
        return false;
    };
    body.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with('#') && line.starts_with("auth"))
        .any(|line| {
            line.contains("pam_peekin.so")
                || ["system-auth", "password-auth"].iter().any(|stack| {
                    line.split_whitespace().nth(2) == Some(stack)
                        && file_uses_module(&pam_dir.join(stack))
                })
        })
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_profile(s: &str) -> bool {
    is_name(s.strip_prefix("custom/").unwrap_or(s))
}

fn valid_selection(selection: &[String]) -> bool {
    !selection.is_empty() && is_profile(&selection[0]) && selection[1..].iter().all(|f| is_name(f))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct State {
    previous: Vec<String>,
    /// Our templates as written, to tell whether someone changed them since.
    templates: BTreeMap<String, String>,
}

pub struct Installer {
    authselect: PathBuf,
    pam: PathBuf,
    profile_dir: PathBuf,
    state: PathBuf,
}

impl Installer {
    pub fn new(root: &Path, authselect: impl Into<PathBuf>) -> Self {
        Installer {
            authselect: authselect.into(),
            pam: root.join("etc/pam.d"),
            profile_dir: root.join("etc/authselect/custom/peekin"),
            state: root.join("var/lib/peekin/authselect-previous.json"),
        }
    }

    fn run(&self, args: &[&str]) -> Result<String, Error> {
        let out = Command::new(&self.authselect)
            .args(args)
            .output()
            .map_err(|e| Error(format!("{}: {e}", self.authselect.display())))?;
        if !out.status.success() {
            return err(format!(
                "authselect {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8(out.stdout).or_else(|_| err("authselect printed invalid UTF-8"))
    }

    fn selection(&self) -> Result<Vec<String>, Error> {
        let selection: Vec<String> = self
            .run(&["current", "--raw"])?
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if !valid_selection(&selection) {
            return err("invalid authselect selection");
        }
        Ok(selection)
    }

    fn select(&self, selection: &[String]) -> Result<(), Error> {
        let mut args = vec!["select"];
        args.extend(selection.iter().map(String::as_str));
        args.push("-b");
        self.run(&args).map(drop)
    }

    fn validate_rendered(&self, features: &[String]) -> Result<(), Error> {
        for flag in FLAGS {
            let mut args = vec!["test", PROFILE];
            args.extend(features.iter().map(String::as_str));
            args.push(flag);
            validate_stack(&self.run(&args)?, true)?;
        }
        Ok(())
    }

    fn templates(&self) -> Result<BTreeMap<String, String>, Error> {
        TEMPLATES
            .iter()
            .map(|name| {
                Ok((
                    name.to_string(),
                    fs::read_to_string(self.profile_dir.join(name))?,
                ))
            })
            .collect()
    }

    pub fn install(&self) -> Result<(), Error> {
        validate_services(&self.pam)?;
        self.run(&["check"])?;
        let previous = self.selection()?;
        if previous[0] == PROFILE {
            if !self.state.is_file() {
                return err("managed profile active without previous selection");
            }
            return self.validate_rendered(&previous[1..]);
        }
        if self.state.exists() || self.profile_dir.exists() {
            return err("PeekIn profile/state already exists; refusing to overwrite it");
        }
        for name in TEMPLATES {
            validate_stack(&fs::read_to_string(self.pam.join(name))?, false)?;
        }
        let base = format!("--base-on={}", previous[0]);
        self.run(&["create-profile", "peekin", &base, "--symlink-meta"])?;
        // On failure the inactive copied profile is left for inspection.
        for name in TEMPLATES {
            let path = self.profile_dir.join(name);
            let meta = fs::symlink_metadata(&path);
            if !meta.as_ref().is_ok_and(|m| m.file_type().is_file()) {
                return err(format!("unsafe authselect template: {name}"));
            }
            let updated = insert_rule(&fs::read_to_string(&path)?)?;
            let temporary = self.profile_dir.join(format!("{name}.peekin-new"));
            fs::write(&temporary, updated)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(meta?.mode() & 0o777))?;
            fs::rename(&temporary, &path)?;
        }
        self.validate_rendered(&previous[1..])?;
        self.write_state(&previous)?;
        let selected = self.select_ours(&previous[1..]);
        if let Err(e) = selected {
            if self.selection()?[0] == PROFILE {
                self.select(&previous)?;
            }
            fs::remove_file(&self.state)?;
            return Err(e);
        }
        Ok(())
    }

    fn select_ours(&self, features: &[String]) -> Result<(), Error> {
        let mut ours = vec![PROFILE.to_string()];
        ours.extend_from_slice(features);
        self.select(&ours)?;
        self.run(&["check"]).map(drop)
    }

    fn write_state(&self, previous: &[String]) -> Result<(), Error> {
        let parent = self.state.parent().expect("state path has a parent");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            return err("authselect recovery state directory is not private");
        }
        let state = State {
            previous: previous.to_vec(),
            templates: self.templates()?,
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.state)?;
        file.write_all(&serde_json::to_vec(&state).map_err(|e| Error(e.to_string()))?)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn remove(&self) -> Result<(), Error> {
        if self.selection()?[0] != PROFILE {
            return Ok(());
        }
        self.run(&["check"])?;
        if !fs::symlink_metadata(&self.state).is_ok_and(|m| m.is_file()) {
            return err("previous authselect selection unavailable");
        }
        let state: State = serde_json::from_str(&fs::read_to_string(&self.state)?)
            .or_else(|_| err("invalid saved authselect selection"))?;
        if !valid_selection(&state.previous) || state.previous[0] == PROFILE {
            return err("invalid saved authselect selection");
        }
        self.select(&state.previous)?;
        self.run(&["check"])?;
        fs::remove_file(&self.state)?;
        if self.templates().ok().as_ref() == Some(&state.templates) {
            fs::remove_dir_all(&self.profile_dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAILLOCK: &str =
        "auth required pam_env.so\nauth required pam_faillock.so preauth silent\n\
        auth sufficient pam_unix.so nullok\nauth required pam_faillock.so authfail\n\
        auth required pam_deny.so\n";

    const SSSD_SAFE: &str = "auth required pam_env.so\n\
        auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
        auth [default=1 ignore=ignore success=ok] pam_localuser.so\n\
        auth sufficient pam_unix.so nullok\n\
        auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
        auth sufficient pam_sss.so forward_pass\n\
        auth required pam_deny.so\n";

    #[test]
    fn unknown_post_password_rule_is_rejected() {
        let text = "auth required pam_env.so\nauth sufficient pam_unix.so\n\
            auth required pam_custom_gate.so\nauth required pam_deny.so\n";
        assert!(validate_stack(text, false).is_err());
    }

    #[test]
    fn faillock_hooks_are_kept_but_jump_controls_are_rejected() {
        validate_stack(FAILLOCK, false).unwrap();
        validate_stack(&insert_rule(FAILLOCK).unwrap(), true).unwrap();
        let jump = format!("auth [success=1 default=ignore] pam_echo.so\n{FAILLOCK}");
        assert!(validate_stack(&jump, false).is_err());
    }

    #[test]
    fn jumps_that_skip_or_land_on_face_are_rejected() {
        validate_stack(SSSD_SAFE, false).unwrap();
        validate_stack(&insert_rule(SSSD_SAFE).unwrap(), true).unwrap();
        for unsafe_stack in [
            format!("auth [success=1 default=ignore] pam_echo.so\n{RULE}{SSSD_SAFE}"),
            format!(
                "auth [success=1 default=ignore] pam_echo.so\nauth required pam_env.so\n{RULE}{SSSD_SAFE}"
            ),
        ] {
            assert!(validate_stack(&unsafe_stack, true).is_err());
        }
    }

    #[test]
    fn rule_goes_before_the_sssd_dispatch_and_changes_nothing_else() {
        let installed = insert_rule(SSSD_SAFE).unwrap();
        assert!(installed.find("pam_peekin.so") < installed.find("pam_usertype.so"));
        assert_eq!(installed.replacen(RULE, "", 1), SSSD_SAFE);
        assert!(insert_rule(&installed).is_err());
    }

    #[test]
    fn malformed_controls_are_rejected() {
        for text in [
            "auth [success=done auth required pam_deny.so\n",
            "auth [a=b a=c] pam_x.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n",
            "auth [a] pam_x.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n",
            "-auth sufficient pam_x.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n",
        ] {
            assert!(validate_stack(text, false).is_err(), "{text}");
        }
    }

    #[test]
    fn services_reach_the_module_directly_or_through_a_shared_stack() {
        let dir = std::env::temp_dir().join(format!("peekin-pamd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("system-auth"),
            format!("auth required pam_env.so\n{RULE}"),
        )
        .unwrap();
        fs::write(dir.join("password-auth"), "auth required pam_env.so\n").unwrap();
        fs::write(dir.join("polkit-1"), "auth include system-auth\n").unwrap();
        fs::write(dir.join("login"), "auth substack password-auth\n").unwrap();
        fs::write(dir.join("sudo"), format!("{RULE}@include common-auth\n")).unwrap();
        fs::write(
            dir.join("su"),
            "# auth sufficient pam_peekin.so\nauth include system-auth\n",
        )
        .unwrap();
        assert!(service_uses_module(&dir, "polkit-1"));
        assert!(!service_uses_module(&dir, "login"));
        assert!(service_uses_module(&dir, "sudo"));
        assert!(service_uses_module(&dir, "su"), "through system-auth");
        assert!(!service_uses_module(&dir, "missing"));
        assert!(!file_uses_module(&dir.join("password-auth")));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn selections_are_checked() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(valid_selection(&s(&["sssd", "with-faillock"])));
        assert!(valid_selection(&s(&["custom/peekin"])));
        assert!(!valid_selection(&s(&[])));
        assert!(!valid_selection(&s(&["../etc"])));
        assert!(!valid_selection(&s(&["sssd", "with;rm"])));
    }
}
