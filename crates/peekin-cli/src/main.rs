//! The `peekin` command-line tool.

mod doctor;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use peekin_core::compare::{
    classify_frame, ChallengeMode, ChallengeOrder, ChallengeStage, ChallengeTracker, FrameClass,
    TemporalDecision, TemporalMatcher, VerifyParams,
};
use peekin_core::enroll::{
    enroll, pick_label, slowdown_warning_applies, EnrollParams, LabelSource,
};
use peekin_core::matcher::best_match;
use peekin_core::models::{self, usable_embeddings, EMBEDDING_FORMAT};
use peekin_core::paths::validate_username;
use peekin_core::source::FaceSource;
use peekin_core::{set_option, FaceModel, ModelError, PeekinConfig, PeekinPaths};
use peekin_vision::{OpenCvFaceSource, OpenError};
use std::ffi::CStr;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(name = "peekin", version, about = "PeekIn face authentication CLI")]
struct Cli {
    /// Account to act on (default: $SUDO_USER/$DOAS_USER, the pkexec caller or the current user).
    #[arg(short = 'U', long, global = true)]
    user: Option<String>,
    /// Answer yes to every question.
    #[arg(short = 'y', long, default_value_t = false, global = true)]
    assume_yes: bool,
    /// Output for scripts instead of people.
    #[arg(long, default_value_t = false, global = true)]
    plain: bool,
    #[command(subcommand)]
    command: Command,
    /// Override config dir (packaging/tests). Defaults to /etc/peekin.
    #[arg(long, hide = true, global = true)]
    config_dir: Option<PathBuf>,
    /// Override data dir holding models/*.onnx. Defaults to /usr/share/peekin.
    #[arg(long, hide = true, global = true)]
    data_dir: Option<PathBuf>,
    /// Override models dir. Defaults to <config_dir>/models.
    #[arg(long, hide = true, global = true)]
    models_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add a face model for a user.
    Add { label: Option<String> },
    /// Save a face model enrolled elsewhere; reads JSON samples from stdin.
    #[command(hide = true)]
    ImportModel { label: Option<String> },
    /// Add samples to an existing face model; reads JSON samples from stdin.
    #[command(hide = true)]
    ImportSamples { id: String },
    /// Apply one complete settings transaction from JSON on stdin (development/integration use).
    #[command(hide = true)]
    ApplySettings,
    /// List cameras usable for face authentication (infrared first).
    Cameras {
        /// Print only the path of the preferred camera.
        #[arg(long, conflicts_with_all = ["attest", "revoke"])]
        best: bool,
        /// Show the attestation of this infrared camera, for review.
        #[arg(long, value_name = "CAMERA", conflicts_with = "revoke")]
        attest: Option<PathBuf>,
        /// Add the attestation to /etc/peekin/ir-profiles.json (root).
        #[arg(long, requires_all = ["attest", "evidence"])]
        save: bool,
        /// How you checked that this is the infrared sensor and its emitter lights up
        /// ("-" reads it from stdin).
        #[arg(long, requires = "save")]
        evidence: Option<String>,
        /// Attest every unit of this model instead of this serial number.
        #[arg(long, requires = "attest")]
        any_unit: bool,
        /// Remove the attestation of this camera (root).
        #[arg(long, value_name = "CAMERA")]
        revoke: Option<PathBuf>,
    },
    /// Remove all face models for a user.
    Clear,
    /// Open config.ini in an editor.
    Config,
    /// Enable (0) or disable (1) face authentication.
    Disable { value: String },
    /// Check configuration, camera, permissions, PAM and SELinux, and explain
    /// why face authentication would not start.
    Doctor,
    /// List all saved face models for a user.
    List,
    /// Remove a specific model by ID.
    Remove { id: String },
    /// Set a config option: `peekin set <name> <value>`.
    Set { args: Vec<String> },
    /// Show live detection and match results from the camera.
    Test {
        /// How long to run.
        #[arg(long, default_value_t = 18, value_parser = clap::value_parser!(u64).range(1..=30))]
        seconds: u64,
        /// Stop after the same temporal decision that PAM requires.
        #[arg(long)]
        until_match: bool,
    },
    /// Decrypt the encrypted face models into memory (run at boot).
    UnsealModels,
    /// Turn PeekIn on or off in the authselect PAM profile (run by the package).
    #[command(hide = true)]
    PamSetup {
        #[arg(value_parser = ["install", "remove"])]
        action: String,
    },
    /// Print version.
    Version,
}

fn username_for_uid(uid: libc::uid_t) -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers reference live, correctly sized buffers.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: on success pw_name points into `buf`, NUL-terminated.
    Some(
        unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// Decrypts the face models into memory at boot, sealing plaintext models found on disk first.
/// `AUTHSELECT_TEST_ROOT` and `AUTHSELECT_TEST_BINARY` point it at a fixture.
fn cmd_pam_setup(action: &str) -> Result<()> {
    use peekin_core::authselect::Installer;
    let root =
        std::env::var_os("AUTHSELECT_TEST_ROOT").map_or_else(|| PathBuf::from("/"), PathBuf::from);
    // SAFETY: geteuid has no preconditions.
    if root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("authselect profile management requires root");
    }
    let binary = std::env::var_os("AUTHSELECT_TEST_BINARY").unwrap_or_else(|| "authselect".into());
    let installer = Installer::new(&root, binary);
    let result = if action == "install" {
        installer.install()
    } else {
        installer.remove()
    };
    result.map_err(|e| anyhow::anyhow!("peekin authselect: {e}"))
}

fn cmd_unseal_models(paths: &PeekinPaths) -> Result<()> {
    let Some(sealed_dir) = paths.sealed_models_dir() else {
        println!("Face models of this tree are not encrypted; nothing to do");
        return Ok(());
    };
    let (uid, gid) = model_owner(paths)?;
    let report = peekin_core::sealed::unseal_all(
        std::path::Path::new(peekin_core::sealed::TOOL),
        sealed_dir,
        paths.user_models_dir(),
        uid,
        gid,
    )
    .with_context(|| format!("reading {}", sealed_dir.display()))?;
    let mut failed = false;
    for entry in &report {
        match &entry.result {
            Ok(()) if entry.migrated => println!(
                "{}: plaintext face model encrypted with {} and removed from the disk",
                entry.user,
                peekin_core::sealed::key_description()
            ),
            Ok(()) => println!("{}: face models decrypted", entry.user),
            Err(error) => {
                failed = true;
                eprintln!("{}: {error}", entry.user);
            }
        }
    }
    if failed {
        bail!("some face models could not be decrypted; face login stays off for those accounts");
    }
    Ok(())
}

fn model_owner(paths: &PeekinPaths) -> Result<(libc::uid_t, libc::gid_t)> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok((unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
    }
    let name = std::ffi::CString::new("peekin")?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        bail!("Cannot resolve dedicated peekin service account");
    }
    models::prepare_model_store(paths.user_models_dir(), 0, pwd.pw_gid)?;
    Ok((0, pwd.pw_gid))
}

/// --user > SUDO_USER > DOAS_USER > pkexec caller > $USER.
fn resolve_user(flag: Option<String>) -> Result<String> {
    let env = |k| std::env::var(k).ok().filter(|v: &String| !v.is_empty());
    let pkexec_user = || {
        env("PKEXEC_UID")
            .and_then(|uid| uid.parse::<libc::uid_t>().ok())
            .and_then(username_for_uid)
    };
    let user = flag
        .or_else(|| env("SUDO_USER"))
        .or_else(|| env("DOAS_USER"))
        .or_else(pkexec_user)
        .or_else(|| env("USER"))
        .or_else(|| env("LOGNAME"))
        .ok_or_else(|| anyhow!("Cannot tell which account to use; name it with -U/--user"))?;
    if user == "root" {
        bail!("Running as root without a login user; name the account with -U/--user");
    }
    validate_username(&user)?;
    Ok(user)
}

fn paths_from(cli: &Cli) -> PeekinPaths {
    let config_dir = cli
        .config_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/peekin"));
    let data_dir = cli
        .data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("/usr/share/peekin"));
    let mut paths = PeekinPaths::from_dirs(config_dir, data_dir);
    if let Some(m) = &cli.models_dir {
        paths.user_models_dir = m.clone();
    }
    paths
}

fn confirm(prompt: &str, assume_yes: bool) -> Result<bool> {
    if assume_yes {
        return Ok(true);
    }
    print!("{prompt} [y/N]: ");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}

fn load_config(paths: &PeekinPaths) -> Result<PeekinConfig> {
    let config = PeekinConfig::load(&paths.config_file_path())?;
    for warning in config.invalid_values() {
        eprintln!("Warning: {warning}");
    }
    Ok(config)
}

fn open_camera(config: &PeekinConfig, paths: &PeekinPaths) -> Result<OpenCvFaceSource> {
    let source = OpenCvFaceSource::open(config, paths).map_err(|e| match e {
        OpenError::MissingModels(_) => anyhow!(
            "{e}\nDownload them into {} with fetch-models.sh",
            paths.vision_model_dir.display()
        ),
        other => anyhow!("{other}"),
    })?;
    for warning in source.warnings() {
        eprintln!("Warning: {warning}");
    }
    Ok(source)
}

fn cmd_add(
    paths: &PeekinPaths,
    user: &str,
    label: Option<String>,
    assume_yes: bool,
    plain: bool,
) -> Result<()> {
    let config = load_config(paths)?;
    let mut existing = match models::load_user_models(paths.user_models_dir(), user) {
        Ok(m) => m,
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if slowdown_warning_applies(existing.len()) {
        println!(
            "Note: every extra face model makes recognition a little slower (Ctrl+C cancels)\n"
        );
    }
    if !plain {
        println!("New face model for {user}");
    }
    let next_id = FaceModel::next_id(&existing);
    let source = match label {
        Some(l) => LabelSource::Arg(l),
        None if assume_yes => LabelSource::Default,
        None => {
            print!("Name for the new face model [Model #{next_id}]: ");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            LabelSource::Prompt(line.trim_end_matches(['\n', '\r']).to_string())
        }
    };
    if matches!(&source, LabelSource::Arg(l) | LabelSource::Prompt(l) if l.contains(',')) {
        println!("Note: commas are not allowed in a model label and were removed");
    }
    let label = pick_label(source, next_id);
    if assume_yes {
        println!("Using label \"{label}\" because of -y flag");
    }

    let mut camera = open_camera(&config, paths)?;
    println!("\nLook at the camera and hold still");
    let samples = enroll(
        &mut camera,
        &EnrollParams::with_dark_threshold(config.dark_threshold()),
    )?;
    drop(camera);

    let _lock = models::lock_user_models(paths.user_models_dir(), user)?;
    existing = match models::load_user_models(paths.user_models_dir(), user) {
        Ok(models) => models,
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let committed_id = FaceModel::next_id(&existing);
    existing.push(FaceModel {
        id: committed_id,
        label,
        time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        format: Some(EMBEDDING_FORMAT.into()),
        data: samples
            .into_iter()
            .map(|e| e.into_iter().map(f64::from).collect())
            .collect(),
    });
    let (uid, gid) = model_owner(paths)?;
    peekin_core::sealed::replace_models(paths, user, Some(&existing), uid, gid)?;
    println!("\nScan complete\nAdded a new model to {user}");
    Ok(())
}

/// Text-only live test: per-interval detection and match lines.
fn cmd_test(paths: &PeekinPaths, user: &str, seconds: u64, until_match: bool) -> Result<()> {
    let total_started = Instant::now();
    let config = load_config(paths)?;
    if !config.security_errors().is_empty() {
        bail!("security-critical configuration is invalid");
    }
    let models = match models::load_user_models(paths.user_models_dir(), user) {
        Ok(models) => models,
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let known = usable_embeddings(&models);
    let threshold = config.effective_min_similarity(&known);
    if known.is_empty() {
        println!("No usable face model for {user}: showing detection only");
    }
    let mut camera = open_camera(&config, paths)?;
    let kind = peekin_core::cameras::kind_of(camera.device());
    let mode = ChallengeMode::for_config(config.movement_required(kind))?;
    // Like PAM: light from the screen for a colour camera in a dark room.
    let mut low_light = (config.brighten_screen()
        && kind == Some(peekin_core::cameras::CameraKind::Colour))
    .then(peekin_core::lowlight::LowLightWatch::default);
    let mut boost = None;
    let (w, h) = camera.frame_size();
    let run = Duration::from_secs(seconds.min(config.attempt_secs(mode.is_movement()) as u64));
    println!(
        "Camera {} at {w}x{h}, min_similarity {threshold}, movement challenge {}, running for {} s (Ctrl+C to stop)\n{}\n",
        camera.device().display(),
        if matches!(mode, ChallengeMode::Movement(_)) { "on" } else { "off" },
        run.as_secs(),
        mode.prompt()
    );

    let (mut frames, mut dark, mut with_face, mut matched) = (0u64, 0u64, 0u64, 0u64);
    let mut best: Option<f32> = None;
    let mut last_print = Instant::now() - Duration::from_secs(1);
    let params = VerifyParams::authentication(run, config.dark_threshold(), threshold);
    let mut temporal = TemporalMatcher::new(params);
    let mut movement: Option<ChallengeTracker> = None;
    let mut challenge_failed = false;
    let (mut first_match_ms, mut accepted_ms) = (None, None);
    loop {
        let stats = camera.next_frame()?;
        if stats.at > run {
            break;
        }
        if low_light.as_mut().is_some_and(|w| w.observe(&stats.hist)) {
            match peekin_core::backlight::raise(std::path::Path::new(
                peekin_core::backlight::BACKLIGHT_DIR,
            )) {
                Ok(Some(raised)) => {
                    println!("Dark scene: screen at full brightness until the test ends");
                    boost = Some(raised);
                }
                Ok(None) => println!("Dark scene: no screen backlight to raise"),
                Err(error) => println!("Dark scene: cannot brighten the screen: {error}"),
            }
        }
        frames += 1;
        let class = classify_frame(&stats.hist, config.dark_threshold());
        let darkness = match class {
            FrameClass::Black => 100.0,
            FrameClass::Dark { darkness } | FrameClass::Scan { darkness } => darkness,
        };
        let line = if matches!(class, FrameClass::Scan { .. }) {
            let faces = camera.analyze()?;
            let top = if let [face] = faces.as_slice() {
                best_match(&known, &face.embedding)
                    .map(|(model, similarity)| (face.score, model, similarity))
            } else {
                None
            };
            if !faces.is_empty() {
                with_face += 1;
            }
            match top {
                Some((detect, model, sim)) => {
                    best = Some(best.map_or(sim, |b| b.max(sim)));
                    if sim >= threshold && first_match_ms.is_none() {
                        first_match_ms = Some(total_started.elapsed().as_millis());
                    }
                    let verdict = if let Some(tracker) = movement.as_mut() {
                        let stage = tracker.observe(
                            stats.at,
                            faces[0].yaw.map(|yaw| (model, sim, yaw)),
                            &params,
                        );
                        let ChallengeMode::Movement(challenge) = mode else {
                            unreachable!("a tracker only exists in movement mode")
                        };
                        if stage == ChallengeStage::Complete {
                            matched += 1;
                            accepted_ms.get_or_insert_with(|| total_started.elapsed().as_millis());
                            "ACCEPTED after movement challenge".to_string()
                        } else if stage == ChallengeStage::Failed {
                            challenge_failed = true;
                            "WRONG MOVEMENT ORDER; use password or retry".to_string()
                        } else {
                            format!(
                                "{} (stage {} of {})",
                                stage.instruction(challenge),
                                stage.number(),
                                ChallengeOrder::STAGES
                            )
                        }
                    } else {
                        match temporal.observe(stats.at, Some((model, sim))) {
                            TemporalDecision::Accepted { model, .. } => match mode {
                                ChallengeMode::Movement(challenge) => {
                                    movement = Some(ChallengeTracker::new(challenge, model));
                                    "identity matched; start movement challenge".to_string()
                                }
                                ChallengeMode::Passive => {
                                    matched += 1;
                                    accepted_ms
                                        .get_or_insert_with(|| total_started.elapsed().as_millis());
                                    "ACCEPTED (movement challenge off)".to_string()
                                }
                            },
                            TemporalDecision::Progress { .. } => {
                                "collecting consistent frames".to_string()
                            }
                            TemporalDecision::Rejected { .. } => "no match".to_string(),
                        }
                    };
                    format!(
                        "{} face(s), detect {detect:.2}, similarity {sim:.3} {verdict}",
                        faces.len()
                    )
                }
                None => {
                    if let Some(tracker) = movement.as_mut() {
                        tracker.reset();
                    } else {
                        temporal.reset();
                    }
                    format!("{} face(s); no acceptance", faces.len())
                }
            }
        } else {
            dark += 1;
            "DARK frame, skipped".to_string()
        };
        if last_print.elapsed() >= Duration::from_millis(250) {
            println!(
                "{:>6} ms  darkness {darkness:>5.1}%  {line}",
                stats.at.as_millis()
            );
            last_print = Instant::now();
        }
        if challenge_failed || (until_match && accepted_ms.is_some()) {
            break;
        }
    }
    if let Some(mut boost) = boost {
        if let Err(error) = boost.restore() {
            println!("Cannot restore the screen brightness: {error}");
        }
    }
    let fps = frames as f64 / total_started.elapsed().as_secs_f64().max(0.001);
    println!(
        "\n{frames} frames ({fps:.1} fps): {dark} dark, {with_face} with a face, {matched} matched; best similarity {}",
        best.map_or("n/a".into(), |b| format!("{b:.3}"))
    );
    let timing = camera.timings();
    println!(
        "timing {}",
        serde_json::json!({
            "version": 1, "total_ms": total_started.elapsed().as_millis(),
            "models_ms": timing.models.as_millis(), "camera_ms": timing.camera.as_millis(),
            "first_frame_ms": timing.first_frame.map(|t| t.as_millis()),
            "first_usable_ms": timing.first_usable.map(|t| t.as_millis()),
            "detection_ms": timing.detection.as_millis(), "detections": timing.detections,
            "recognition_ms": timing.recognition.as_millis(), "recognitions": timing.recognitions,
            "first_match_ms": first_match_ms, "accepted_ms": accepted_ms,
            "accepted": accepted_ms.is_some(), "frames": frames,
        })
    );
    Ok(())
}

fn cmd_list(paths: &PeekinPaths, user: &str, plain: bool) -> Result<()> {
    let models = match models::load_user_models(paths.user_models_dir(), user) {
        Ok(m) => m,
        Err(ModelError::NotInitialised) => {
            bail!("{user} has no face model yet; add one with:\n\n\tsudo peekin -U {user} add\n")
        }
        Err(ModelError::NoModelForUser(_)) if plain => std::process::exit(1),
        Err(ModelError::NoModelForUser(_)) => {
            bail!("{user} has no face model yet; add one with:\n\n\tsudo peekin -U {user} add\n")
        }
        Err(e) => return Err(e.into()),
    };
    if !plain {
        println!("Face models of {user}:");
        println!("\n\x1b[1;29mID  Date                 Label\x1b[0m");
    }
    for m in &models {
        println!("{}", models::format_model_row(m, plain));
    }
    println!();
    Ok(())
}

fn cmd_clear(paths: &PeekinPaths, user: &str, assume_yes: bool) -> Result<()> {
    if !confirm(&format!("Delete every face model of {user}?"), assume_yes)? {
        println!("\nNot confirmed; nothing was deleted");
        std::process::exit(1);
    }
    let _lock = models::lock_user_models(paths.user_models_dir(), user)?;
    // The model file must exist; a damaged one can still be cleared.
    match models::load_user_models(paths.user_models_dir(), user) {
        Ok(_) | Err(ModelError::Corrupt(_) | ModelError::TooLarge | ModelError::Io(_)) => {}
        Err(error) => return Err(error).with_context(|| format!("clearing models for {user}")),
    }
    let (uid, gid) = model_owner(paths)?;
    peekin_core::sealed::replace_models(paths, user, None, uid, gid)
        .with_context(|| format!("clearing models for {user}"))?;
    println!("\nModels cleared");
    Ok(())
}

fn cmd_remove(paths: &PeekinPaths, user: &str, id: &str, assume_yes: bool) -> Result<()> {
    let models = models::load_user_models(paths.user_models_dir(), user)?;
    let Some(target) = models.iter().find(|m| m.id.to_string() == id) else {
        bail!("{user} has no face model {id} (see: sudo peekin list)");
    };
    if !confirm(
        &format!(
            "This will remove the model called \"{}\" for {user}\nDo you want to continue",
            target.label
        ),
        assume_yes,
    )? {
        println!("\nNot confirmed; nothing was deleted");
        std::process::exit(1);
    }
    let _lock = models::lock_user_models(paths.user_models_dir(), user)?;
    let current = models::load_user_models(paths.user_models_dir(), user)?;
    if !current.iter().any(|m| m.id.to_string() == id) {
        bail!("Model {id} changed while awaiting confirmation");
    }
    let kept: Vec<FaceModel> = current
        .into_iter()
        .filter(|m| m.id.to_string() != id)
        .collect();
    let (uid, gid) = model_owner(paths)?;
    let new = (!kept.is_empty()).then_some(kept.as_slice());
    peekin_core::sealed::replace_models(paths, user, new, uid, gid)?;
    if kept.is_empty() {
        println!("Removed last model, face authentication disabled for user");
    } else {
        println!("Removed model {id}");
    }
    Ok(())
}

fn cmd_disable(paths: &PeekinPaths, value: &str) -> Result<()> {
    let want = PeekinConfig::parse_disabled_arg(value)
        .ok_or_else(|| anyhow!("Expected 1 to disable face authentication or 0 to enable it"))?;
    let cfg_path = paths.config_file_path();
    if PeekinConfig::load(&cfg_path)?.disabled() == want {
        println!("Nothing to change: disabled is already {want}");
        std::process::exit(1);
    }
    peekin_core::management::update_option(&cfg_path, "disabled", &want.to_string())?;
    println!(
        "PeekIn has been {}",
        if want { "disabled" } else { "enabled" }
    );
    Ok(())
}

fn cmd_config(paths: &PeekinPaths) -> Result<()> {
    use peekin_core::editor;
    let editor_bin = editor::resolve_editor_from_env().map_err(|e| anyhow!("{e}"))?;
    println!(
        "Editing config.ini with {}",
        editor::editor_display_name(&editor_bin)
    );
    let status = std::process::Command::new(&editor_bin)
        .arg(paths.config_file_path())
        .status()
        .with_context(|| format!("opening {}", paths.config_file_path().display()))?;
    if !status.success() {
        bail!("Editor exited with status {status}");
    }
    Ok(())
}

fn cmd_set(paths: &PeekinPaths, args: &[String]) -> Result<()> {
    let (name, value) = set_option::parse_set_args(args)
        .map_err(|e| anyhow!("{e}\nFor example:\n\n\tpeekin set timeout 5"))?;
    let cfg_path = paths.config_file_path();
    peekin_core::management::update_option(&cfg_path, name, value)?;
    println!("Setting saved");
    Ok(())
}

/// Stores samples enrolled by the settings app. Input: {"format": ..., "embeddings": [[f32; 128], ...]}.
fn cmd_import_samples(paths: &PeekinPaths, user: &str, id: &str) -> Result<()> {
    use std::io::Read;
    let mut json = String::new();
    io::stdin().take(1 << 20).read_to_string(&mut json)?;
    let data = models::parse_import(&json).map_err(|e| anyhow!(e))?;
    let _lock = models::lock_user_models(paths.user_models_dir(), user)?;
    let mut existing = models::load_user_models(paths.user_models_dir(), user)?;
    let count = models::append_samples(&mut existing, id, user, data)?;
    let (uid, gid) = model_owner(paths)?;
    peekin_core::sealed::replace_models(paths, user, Some(&existing), uid, gid)?;
    println!("Model {id} of {user} now has {count} samples");
    Ok(())
}

fn cmd_import_model(paths: &PeekinPaths, user: &str, label: Option<String>) -> Result<()> {
    use std::io::Read;
    let mut json = String::new();
    io::stdin().take(1 << 20).read_to_string(&mut json)?;
    let data = models::parse_import(&json).map_err(|e| anyhow!(e))?;
    let _lock = models::lock_user_models(paths.user_models_dir(), user)?;
    let mut existing = match models::load_user_models(paths.user_models_dir(), user) {
        Ok(m) => m,
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let next_id = FaceModel::next_id(&existing);
    let label = pick_label(
        label.map_or(LabelSource::Default, LabelSource::Arg),
        next_id,
    );
    existing.push(FaceModel {
        id: next_id,
        label: label.clone(),
        time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
        format: Some(EMBEDDING_FORMAT.into()),
        data,
    });
    let (uid, gid) = model_owner(paths)?;
    peekin_core::sealed::replace_models(paths, user, Some(&existing), uid, gid)?;
    println!("Added model {next_id} (\"{label}\") for {user}");
    Ok(())
}

fn cmd_apply_settings(paths: &PeekinPaths) -> Result<()> {
    use std::io::Read;
    let mut json = String::new();
    io::stdin().take(64 * 1024 + 1).read_to_string(&mut json)?;
    if json.len() > 64 * 1024 {
        bail!("request too large")
    }
    let update: peekin_core::management::SettingsUpdate = serde_json::from_str(&json)?;
    println!(
        "{}",
        peekin_core::management::apply_settings(&paths.config_file_path(), &update)?
    );
    Ok(())
}

fn require_root(what: &str) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("{what} needs root:\n\n\tsudo peekin cameras ...");
    }
    Ok(())
}

fn cmd_attest(
    camera: &std::path::Path,
    save: bool,
    evidence: Option<&str>,
    pin_serial: bool,
) -> Result<()> {
    use peekin_core::ir_profile::{self, Attested, Store};
    let candidate = ir_profile::inspect(camera)?;
    let id = &candidate.identity;
    let serial = id.serial.as_deref().unwrap_or("none");
    println!(
        "{} ({}:{}, serial {serial}, interface {}, index {}, {})",
        candidate.name, id.vid, id.pid, id.interface_number, id.capture_index, id.driver
    );
    if !save {
        let placeholder =
            "<how you checked that this is the infrared sensor and its emitter lights up>";
        println!("{}", ir_profile::profile_json(id, placeholder, pin_serial));
        println!(
            "\nSave it with:\n\n\tsudo peekin cameras --attest {} --save --evidence \"...\"",
            camera.display()
        );
        return Ok(());
    }
    require_root("Saving an attestation")?;
    let evidence = match evidence.unwrap_or_default() {
        "-" => {
            let mut text = String::new();
            io::Read::read_to_string(&mut io::Read::take(io::stdin(), 4096), &mut text)?;
            text
        }
        given => given.to_string(),
    };
    match Store::system().attest(id, &evidence, pin_serial)? {
        Attested::Added => println!("Attestation added to {}", ir_profile::PROFILES),
        Attested::AlreadyAttested => println!("This camera is already attested"),
    }
    if peekin_core::cameras::kind_of(camera)
        != Some(peekin_core::cameras::CameraKind::VerifiedInfrared)
    {
        bail!(
            "{} is still not verified; check {}",
            camera.display(),
            ir_profile::PROFILES
        );
    }
    println!(
        "{} is now an administrator-approved infrared camera",
        camera.display()
    );
    Ok(())
}

fn cmd_revoke(camera: &std::path::Path) -> Result<()> {
    use peekin_core::ir_profile::{self, Store};
    require_root("Removing an attestation")?;
    let candidate = ir_profile::inspect(camera)?;
    match Store::system().revoke(&candidate.identity)? {
        0 => println!("{} was not attested", camera.display()),
        n => println!("Removed {n} attestation(s) of {}", camera.display()),
    }
    Ok(())
}

fn cmd_cameras(best_only: bool, plain: bool) -> Result<()> {
    use peekin_core::cameras;
    let list = cameras::list();
    if best_only {
        let best = cameras::best(&list).ok_or_else(|| anyhow!("No camera found"))?;
        println!("{}", best.path.display());
        return Ok(());
    }
    if list.is_empty() {
        bail!("No camera found in {}", cameras::V4L_BY_PATH);
    }
    let best = cameras::best(&list).map(|c| c.path.clone());
    for c in &list {
        if plain {
            let kind = match c.kind {
                cameras::CameraKind::VerifiedInfrared => "verified-infrared",
                cameras::CameraKind::InfraredCandidate => "infrared-candidate",
                cameras::CameraKind::Colour => "colour",
            };
            println!("{},{kind},{},{}", c.path.display(), c.node, c.name);
        } else {
            let mark = if Some(&c.path) == best.as_ref() {
                "*"
            } else {
                " "
            };
            println!(
                "{mark} {}\n    device_path = {}",
                c.label(),
                c.path.display()
            );
        }
    }
    if !plain {
        println!("\n* preferred; only devices labelled verified-infrared satisfy ir_only");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Cameras {
        best,
        attest,
        save,
        evidence,
        any_unit,
        revoke,
    } = &cli.command
    {
        if let Some(camera) = attest {
            return cmd_attest(camera, *save, evidence.as_deref(), !*any_unit);
        }
        if let Some(camera) = revoke {
            return cmd_revoke(camera);
        }
        return cmd_cameras(*best, cli.plain);
    }
    if let Command::PamSetup { action } = &cli.command {
        return cmd_pam_setup(action);
    }
    // SAFETY: geteuid has no preconditions.
    if std::env::var_os("EUID_CHECK_SKIP").is_none() && unsafe { libc::geteuid() } != 0 {
        eprintln!("This command needs root:\n\n\tsudo peekin ...");
        std::process::exit(1);
    }
    let paths = paths_from(&cli);
    // Unsealing at boot concerns every account, not one user.
    if let Command::UnsealModels = &cli.command {
        return cmd_unseal_models(&paths);
    }
    let user = resolve_user(cli.user.clone())?;

    match &cli.command {
        Command::Add { label } => cmd_add(&paths, &user, label.clone(), cli.assume_yes, cli.plain),
        Command::ApplySettings => cmd_apply_settings(&paths),
        Command::Cameras { .. } => unreachable!("handled before the root check"),
        Command::ImportModel { label } => cmd_import_model(&paths, &user, label.clone()),
        Command::ImportSamples { id } => cmd_import_samples(&paths, &user, id),
        Command::Clear => cmd_clear(&paths, &user, cli.assume_yes),
        Command::Config => cmd_config(&paths),
        Command::Disable { value } => cmd_disable(&paths, value),
        Command::Doctor => {
            let report = doctor::run(&paths, &user);
            report.print();
            if report.worst() == doctor::Level::Fail {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::List => cmd_list(&paths, &user, cli.plain),
        Command::Remove { id } => cmd_remove(&paths, &user, id, cli.assume_yes),
        Command::Set { args } => cmd_set(&paths, args),
        Command::Test {
            seconds,
            until_match,
        } => cmd_test(&paths, &user, *seconds, *until_match),
        Command::UnsealModels => unreachable!("handled before resolving a user"),
        Command::PamSetup { .. } => unreachable!("handled before the root check"),
        Command::Version => {
            println!("PeekIn {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
