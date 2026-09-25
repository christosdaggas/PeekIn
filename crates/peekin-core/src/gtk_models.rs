//! `peekin` argument vectors for the model buttons, and parsing of
//! `peekin list --plain`. Argument vectors, not shell strings, so a model name
//! cannot inject a command.

pub fn build_add_command(model_name: &str, user: &str) -> Vec<String> {
    ["peekin", "add", model_name, "-y", "-U", user]
        .map(str::to_owned)
        .to_vec()
}

pub fn build_remove_command(id: &str, user: &str) -> Vec<String> {
    ["peekin", "remove", id, "-y", "-U", user]
        .map(str::to_owned)
        .to_vec()
}

pub fn build_list_command(user: &str) -> Vec<String> {
    ["peekin", "list", "--plain", "-U", user]
        .map(str::to_owned)
        .to_vec()
}

/// One `id,time,label` row; lines with fewer fields are skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedModel {
    pub id: String,
    pub created: String,
    pub label: String,
}

pub fn parse_plain_list(output: &str) -> Vec<ListedModel> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, ',');
            let (id, created, label) = (parts.next()?, parts.next()?, parts.next()?);
            if label.is_empty() && created.is_empty() {
                return None;
            }
            Some(ListedModel {
                id: id.to_string(),
                created: created.to_string(),
                label: label.to_string(),
            })
        })
        .collect()
}

pub fn delete_confirm_text(id: &str, name: &str) -> String {
    format!("Delete face model {id} ({name})?")
}

/// Model names are limited to 24 characters.
pub fn truncate_model_name(name: &str) -> String {
    name.chars().take(24).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_argument_vectors() {
        assert_eq!(
            build_add_command("work", "alice"),
            ["peekin", "add", "work", "-y", "-U", "alice"]
        );
        assert_eq!(
            build_remove_command("2", "alice"),
            ["peekin", "remove", "2", "-y", "-U", "alice"]
        );
        assert_eq!(
            build_list_command("alice"),
            ["peekin", "list", "--plain", "-U", "alice"]
        );
    }

    #[test]
    fn quotes_in_names_stay_one_argument() {
        let argv = build_add_command("Chris's laptop'; rm -rf / #", "alice");
        assert_eq!(argv[2], "Chris's laptop'; rm -rf / #");
        assert_eq!(argv.len(), 6);
    }

    #[test]
    fn parses_plain_output() {
        let out = "0,2024-01-01 10:00:00,Model #0\n1,2024-01-02 11:00:00,work\n";
        let models = parse_plain_list(out);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "0");
        assert_eq!(models[0].label, "Model #0");
        assert_eq!(models[1].label, "work");
    }

    #[test]
    fn skips_short_lines() {
        assert!(parse_plain_list("garbage\n").is_empty());
        assert!(parse_plain_list("").is_empty());
    }

    #[test]
    fn confirm_text_and_truncation() {
        assert_eq!(
            delete_confirm_text("1", "work"),
            "Delete face model 1 (work)?"
        );
        assert_eq!(truncate_model_name(&"x".repeat(30)).len(), 24);
    }
}
