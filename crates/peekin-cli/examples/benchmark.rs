//! Time-to-accepted-match over repeated `peekin test` runs; starts the camera.
//! `benchmark [runs] [user]`; `CLI` overrides the peekin binary.

use serde_json::{Map, Value};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REQUIRED: [&str; 5] = [
    "total_ms",
    "models_ms",
    "camera_ms",
    "detection_ms",
    "recognition_ms",
];
const OPTIONAL: [&str; 4] = [
    "first_frame_ms",
    "first_usable_ms",
    "first_match_ms",
    "accepted_ms",
];

type Record = Map<String, Value>;

fn ms(record: &Record, key: &str) -> Option<u64> {
    record.get(key).and_then(Value::as_u64)
}

fn parse_record(output: &str) -> Result<Record, String> {
    let lines: Vec<&str> = output
        .lines()
        .filter_map(|l| l.strip_prefix("timing "))
        .collect();
    let [line] = lines[..] else {
        return Err("expected exactly one timing record".into());
    };
    let Ok(Value::Object(record)) = serde_json::from_str(line) else {
        return Err("invalid timing schema".into());
    };
    if record.get("version").and_then(Value::as_u64) != Some(1)
        || !record.get("accepted").is_some_and(Value::is_boolean)
    {
        return Err("invalid timing schema".into());
    }
    for key in REQUIRED.iter().chain(&OPTIONAL) {
        let optional_null = OPTIONAL.contains(key) && record.get(*key) == Some(&Value::Null);
        if !optional_null && ms(&record, key).is_none() {
            return Err(format!("invalid or missing {key}"));
        }
    }
    let accepted = ms(&record, "accepted_ms");
    if record["accepted"].as_bool() != Some(accepted.is_some()) {
        return Err("acceptance flag disagrees with latency".into());
    }
    if let Some(accepted) = accepted {
        let consistent = ms(&record, "first_match_ms")
            .is_some_and(|first| first <= accepted && accepted <= ms(&record, "total_ms").unwrap());
        if !consistent {
            return Err("inconsistent matching timestamps".into());
        }
    }
    Ok(record)
}

fn summarize(records: &[Record]) -> Result<String, String> {
    if records.is_empty() {
        return Err("no timing records".into());
    }
    let runs = records.len();
    let accepted = records
        .iter()
        .filter(|r| r["accepted"].as_bool() == Some(true))
        .count();
    let mut lines = vec![format!(
        "runs={runs} accepted={accepted} no_match={} acceptance_rate={:.1}%",
        runs - accepted,
        accepted as f64 * 100.0 / runs as f64
    )];
    for key in REQUIRED.iter().chain(&OPTIONAL) {
        let mut values: Vec<u64> = records.iter().filter_map(|r| ms(r, key)).collect();
        if values.is_empty() {
            lines.push(format!("{key}: no successful observations"));
            continue;
        }
        values.sort_unstable();
        let n = values.len();
        let median = if n % 2 == 1 {
            values[n / 2] as f64
        } else {
            (values[n / 2 - 1] + values[n / 2]) as f64 / 2.0
        };
        let p95 = values[((n as f64 * 0.95).ceil() as usize).max(1) - 1];
        lines.push(format!("{key}: median={median} p95={p95} n={n}"));
    }
    Ok(lines.join("\n"))
}

fn run_once(cli: &str, user: &str) -> Result<String, String> {
    let mut child = Command::new(cli)
        .args([
            "--plain",
            "-U",
            user,
            "test",
            "--seconds",
            "15",
            "--until-match",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{cli}: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(23);
    while child.try_wait().map_err(|e| e.to_string())?.is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("peekin test did not finish within 23 s".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("peekin test failed: {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runs: usize = args.first().map_or(Ok(20), |a| a.parse()).unwrap_or(0);
    let user = args
        .get(1)
        .cloned()
        .or_else(|| std::env::var("SUDO_USER").ok())
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_default();
    if !(1..=1000).contains(&runs) || user.is_empty() {
        eprintln!("usage: benchmark [runs 1..1000] [user]");
        std::process::exit(2);
    }
    let cli = std::env::var("CLI").unwrap_or_else(|_| "peekin".into());
    let result = (0..runs)
        .map(|_| run_once(&cli, &user).and_then(|out| parse_record(&out)))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|records| summarize(&records));
    match result {
        Ok(report) => println!("{report}"),
        Err(e) => {
            eprintln!("benchmark: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(accepted: Option<u64>) -> String {
        let value = serde_json::json!({
            "version": 1, "total_ms": 900, "models_ms": 100, "camera_ms": 50,
            "detection_ms": 40, "recognition_ms": 50, "first_frame_ms": 20,
            "first_usable_ms": 30, "first_match_ms": accepted.map(|_| 100),
            "accepted_ms": accepted, "accepted": accepted.is_some(),
        });
        format!("timing {value}")
    }

    #[test]
    fn latency_and_failures_are_not_confused_with_run_duration() {
        let records: Vec<_> = [Some(200), Some(400), None]
            .into_iter()
            .map(|a| parse_record(&record(a)).unwrap())
            .collect();
        let report = summarize(&records).unwrap();
        assert!(report.contains("accepted=2 no_match=1"), "{report}");
        assert!(
            report.contains("accepted_ms: median=300 p95=400 n=2"),
            "{report}"
        );
    }

    #[test]
    fn missing_duplicate_and_inconsistent_records_are_rejected() {
        for payload in ["", "timing {}", "timing {}\ntiming {}"] {
            assert!(parse_record(payload).is_err(), "{payload:?}");
        }
        assert!(parse_record(&record(Some(950))).is_err());
    }
}
