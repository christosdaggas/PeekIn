//! `peekin set <option> <value>` and `peekin disable 0|1` config rewrites.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SetError {
    #[error("Name a setting and its new value, e.g. peekin set timeout 3")]
    MissingArgs,
    #[error("Could not find a \"{0}\" config option to set")]
    UnknownOption(String),
    #[error("Config values cannot contain line breaks")]
    MultilineValue,
    #[error("Config contains more than one [{0}] {1} option")]
    AmbiguousOption(String, String),
}

pub fn find_option_line(config_text: &str, name: &str) -> Result<String, SetError> {
    let prefix = format!("{name} ");
    config_text
        .split_inclusive('\n')
        .rfind(|line| line.starts_with(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| SetError::UnknownOption(name.to_string()))
}

pub fn apply_set(config_text: &str, name: &str, value: &str) -> Result<String, SetError> {
    if value.contains(['\n', '\r']) {
        return Err(SetError::MultilineValue);
    }
    let found = find_option_line(config_text, name)?;
    let replacement = format!("{name} = {value}\n");
    Ok(config_text
        .split_inclusive('\n')
        .map(|line| {
            if line == found {
                replacement.as_str()
            } else {
                line
            }
        })
        .collect())
}

/// Like [`apply_set`], but a known option missing from the file is added.
pub fn apply_set_or_insert(config_text: &str, name: &str, value: &str) -> Result<String, SetError> {
    match apply_set(config_text, name, value) {
        Err(SetError::UnknownOption(_)) => {}
        other => return other,
    }
    let section = crate::config::known_section(name)
        .ok_or_else(|| SetError::UnknownOption(name.to_string()))?;
    let line = format!("{name} = {value}\n");
    let header = format!("[{section}]");
    let mut out = String::with_capacity(config_text.len() + line.len() + header.len() + 2);
    let mut inserted = false;
    for l in config_text.split_inclusive('\n') {
        out.push_str(l);
        if !inserted && l.trim().eq_ignore_ascii_case(&header) {
            if !l.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&line);
            inserted = true;
        }
    }
    if !inserted {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("\n{header}\n{line}"));
    }
    Ok(out)
}

/// Strict, section-aware update for security-sensitive keys: duplicates are
/// rejected rather than leaving a stale value.
pub fn apply_known(config_text: &str, name: &str, value: &str) -> Result<String, SetError> {
    if value.contains(['\n', '\r']) {
        return Err(SetError::MultilineValue);
    }
    let section =
        crate::config::known_section(name).ok_or_else(|| SetError::UnknownOption(name.into()))?;
    let mut current = String::new();
    let mut matches = 0usize;
    for line in config_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        if current.eq_ignore_ascii_case(section)
            && !trimmed.starts_with(['#', ';'])
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        {
            matches += 1;
        }
    }
    if matches > 1 {
        return Err(SetError::AmbiguousOption(section.into(), name.into()));
    }
    if matches == 0 {
        let header = format!("[{section}]");
        let line = format!("{name} = {value}\n");
        let mut out = String::with_capacity(config_text.len() + line.len());
        let mut inserted = false;
        for part in config_text.split_inclusive('\n') {
            out.push_str(part);
            if !inserted && part.trim().eq_ignore_ascii_case(&header) {
                out.push_str(&line);
                inserted = true;
            }
        }
        if !inserted {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("\n{header}\n{line}"));
        }
        return Ok(out);
    }
    let mut current = String::new();
    Ok(config_text
        .split_inclusive('\n')
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                current = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
                return line.to_owned();
            }
            if current.eq_ignore_ascii_case(section)
                && !trimmed.starts_with(['#', ';'])
                && trimmed
                    .split_once('=')
                    .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
            {
                let indent = &line[..line.len() - line.trim_start().len()];
                format!(
                    "{indent}{name} = {value}{}",
                    if line.ends_with('\n') { "\n" } else { "" }
                )
            } else {
                line.to_owned()
            }
        })
        .collect())
}

pub fn parse_set_args(args: &[String]) -> Result<(&str, &str), SetError> {
    if args.len() < 2 {
        return Err(SetError::MissingArgs);
    }
    Ok((args[0].as_str(), args[1].as_str()))
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("No \"disabled = ...\" line found in the [core] section of the config")]
pub struct DisabledLineMissing;

/// Set `disabled` in `[core]`, keeping comments and layout.
pub fn apply_disabled(config_text: &str, disabled: bool) -> Result<String, DisabledLineMissing> {
    let mut in_core = false;
    let mut replaced = false;
    let out: String = config_text
        .split_inclusive('\n')
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_core = trimmed.eq_ignore_ascii_case("[core]");
                return line.to_owned();
            }
            let is_disabled_key = trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("disabled"));
            if in_core && !replaced && is_disabled_key {
                replaced = true;
                let newline = if line.ends_with('\n') { "\n" } else { "" };
                format!("disabled = {disabled}{newline}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    if replaced {
        Ok(out)
    } else {
        Err(DisabledLineMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "[core]\ndetection_notice = false\ncertainty = 3.5\n[video]\ncertainty = 3.5\ntimeout = 4\n";

    #[test]
    fn last_matching_line_wins() {
        let text = "[core]\ncertainty = 1\n[video]\ncertainty = 3.5\n";
        assert_eq!(
            find_option_line(text, "certainty").unwrap(),
            "certainty = 3.5\n"
        );
        let out = apply_set(text, "certainty", "4").unwrap();
        assert_eq!(out, "[core]\ncertainty = 1\n[video]\ncertainty = 4\n");
    }

    #[test]
    fn identical_lines_are_all_replaced() {
        let out = apply_set(SAMPLE, "certainty", "2").unwrap();
        assert_eq!(out.matches("certainty = 2\n").count(), 2);
    }

    #[test]
    fn unknown_option_errors() {
        assert_eq!(
            find_option_line(SAMPLE, "nosuchkey"),
            Err(SetError::UnknownOption("nosuchkey".into()))
        );
        // Prefix requires trailing space: "cert" alone must not match "certainty ".
        assert!(find_option_line(SAMPLE, "cert").is_err());
    }

    #[test]
    fn apply_rewrites_line_and_keeps_the_rest() {
        let out = apply_set(SAMPLE, "timeout", "10").unwrap();
        assert!(out.contains("timeout = 10\n"));
        assert!(!out.contains("timeout = 4"));
        assert!(out.contains("detection_notice = false\n"));
    }

    #[test]
    fn values_cannot_inject_lines() {
        assert_eq!(
            apply_set(SAMPLE, "timeout", "1\ndisabled = true"),
            Err(SetError::MultilineValue)
        );
    }

    #[test]
    fn missing_known_option_is_inserted_into_its_section() {
        let text = "[core]\ndisabled = false\n[video]\ntimeout = 4\n";
        let out = apply_set_or_insert(text, "ir_only", "true").unwrap();
        assert_eq!(
            out,
            "[core]\ndisabled = false\n[video]\nir_only = true\ntimeout = 4\n"
        );
        // Existing lines are still replaced in place.
        assert_eq!(
            apply_set_or_insert(&out, "ir_only", "false").unwrap(),
            text.replace("[video]\n", "[video]\nir_only = false\n")
        );
    }

    #[test]
    fn missing_section_is_created_and_unknown_keys_rejected() {
        let out = apply_set_or_insert("[core]\ndisabled = false", "ir_only", "true").unwrap();
        assert_eq!(out, "[core]\ndisabled = false\n\n[video]\nir_only = true\n");
        assert_eq!(
            apply_set_or_insert("[core]\n", "bogus", "1"),
            Err(SetError::UnknownOption("bogus".into()))
        );
        assert_eq!(
            apply_set_or_insert("[core]\n", "ir_only", "a\nb"),
            Err(SetError::MultilineValue)
        );
    }

    #[test]
    fn strict_update_is_section_aware_and_rejects_duplicates() {
        let text = "[core]\ndisabled = false\n[debug]\ndisabled = true\n";
        let out = apply_known(text, "disabled", "true").unwrap();
        assert_eq!(out, "[core]\ndisabled = true\n[debug]\ndisabled = true\n");
        assert!(matches!(
            apply_known(
                "[core]\ndisabled=false\ndisabled=true\n",
                "disabled",
                "true"
            ),
            Err(SetError::AmbiguousOption(_, _))
        ));
    }

    #[test]
    fn arg_validation() {
        assert_eq!(parse_set_args(&[]), Err(SetError::MissingArgs));
        assert_eq!(
            parse_set_args(&["certainty".to_string()]),
            Err(SetError::MissingArgs)
        );
        let argv = ["certainty".to_string(), "3".to_string()];
        assert_eq!(parse_set_args(&argv).unwrap(), ("certainty", "3"));
    }

    #[test]
    fn disabled_is_rewritten_whatever_its_spelling() {
        for line in ["disabled = False", "Disabled=0", "  disabled   =   no  "] {
            let text = format!("# comment\n[core]\n{line}\nabort_if_ssh = true\n");
            let out = apply_disabled(&text, true).unwrap();
            assert_eq!(
                out, "# comment\n[core]\ndisabled = true\nabort_if_ssh = true\n",
                "{line}"
            );
        }
    }

    #[test]
    fn disabled_only_in_core_section() {
        let text = "[core]\nabort_if_ssh = true\n[debug]\ndisabled = false\n";
        assert_eq!(apply_disabled(text, true), Err(DisabledLineMissing));
        assert_eq!(
            apply_disabled("[core]\n# disabled = false\n", true),
            Err(DisabledLineMissing)
        );
    }
}
