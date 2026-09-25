//! PeekIn settings app (GTK4 + libadwaita); privileged changes go through `peekin-helper`.
//! `--dev` runs `peekin` directly (no pkexec) against private directories.

mod backend;
mod commands;
mod preview;
mod settings;
mod ui_state;

use adw::prelude::*;
use backend::{error_summary, Backend};
use gtk::{gio, glib};
use peekin_core::cameras;
use peekin_core::config::{MAX_AUTH_TIMEOUT_SECS, MAX_SIMILARITY, MIN_SIMILARITY};
use peekin_core::gtk_models::{build_list_command, build_remove_command, parse_plain_list};
use peekin_core::i18n::{tr, tr_args, trn};
use peekin_core::models::EMBEDDING_FORMAT;
use peekin_core::paths::validate_username;
use peekin_core::PeekinConfig;
use settings::Settings;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;
use ui_state::{Operation, Readiness, ReadinessValue};

const APP_ID: &str = "com.chrisdaggas.peekin";
const TEST_SECONDS: u32 = 18;
const SUBPROCESS_DEADLINE: Duration = Duration::from_secs(45);

struct Ui {
    backend: Backend,
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    apply: gtk::Button,
    enabled: adw::SwitchRow,
    device: adw::ComboRow,
    devices: RefCell<Vec<String>>,
    cameras: RefCell<Vec<cameras::Camera>>,
    ir_only: adw::SwitchRow,
    min_similarity: adw::SpinRow,
    timeout: adw::SpinRow,
    dark_threshold: adw::SpinRow,
    detection_notice: adw::SwitchRow,
    confirm_success: adw::SwitchRow,
    abort_if_ssh: adw::SwitchRow,
    abort_if_lid_closed: adw::SwitchRow,
    movement_challenge: adw::SwitchRow,
    require_movement_without_ir: adw::SwitchRow,
    personal_threshold: adw::SwitchRow,
    brighten_screen: adw::SwitchRow,
    save_failed_snapshots: adw::SwitchRow,
    security_level: adw::ComboRow,
    applying_preset: Cell<bool>,
    lock_when_away: adw::SwitchRow,
    away_secs: adw::SpinRow,
    away_camera: adw::ComboRow,
    away_cameras: RefCell<Vec<peekin_core::session::CameraChoice>>,
    /// Set while session settings are being shown, so that does not save them.
    loading_session: Cell<bool>,
    notify_failed: adw::SwitchRow,
    snapshots_flow: gtk::FlowBox,
    activity_group: adw::PreferencesGroup,
    activity_rows: RefCell<Vec<gtk::Widget>>,
    show_snapshots: gtk::Button,
    clear_snapshots: gtk::Button,
    service_sudo: adw::SwitchRow,
    service_login_screen: adw::SwitchRow,
    service_lock_screen: adw::SwitchRow,
    service_polkit: adw::SwitchRow,
    service_console: adw::SwitchRow,
    loaded: RefCell<Option<Settings>>,
    operation: Cell<Operation>,
    operation_status: gtk::Label,
    operation_spinner: gtk::Spinner,
    operation_cancel: gtk::Button,
    active_command: RefCell<Option<commands::CommandControl>>,
    settings_page: adw::PreferencesPage,
    loading_settings: Cell<bool>,
    models_group: adw::PreferencesGroup,
    model_rows: RefCell<Vec<gtk::Widget>>,
    readiness: adw::ActionRow,
    readiness_camera: adw::ActionRow,
    readiness_pam: adw::ActionRow,
    readiness_models: adw::ActionRow,
    readiness_attempts: adw::ActionRow,
    resume_face_login: gtk::Button,
    readiness_state: RefCell<Readiness>,
    #[cfg(test)]
    stack: adw::ViewStack,
    refresh_models: gtk::Button,
    add_model_button: gtk::Button,
    test_output: gtk::TextView,
    test_picture: gtk::Picture,
    test_status: gtk::Label,
    test_button: gtk::Button,
    test_stop: gtk::Button,
    active_test: Rc<RefCell<Option<std::sync::Arc<preview::Control>>>>,
    active_enrollment: Rc<RefCell<Option<std::sync::Arc<preview::Control>>>>,
    enrollment_label: Rc<RefCell<String>>,
}

impl Ui {
    fn toast(&self, msg: &str) {
        self.toasts.add_toast(adw::Toast::new(msg));
    }

    fn refresh_readiness(&self) {
        let state = self.readiness_state.borrow();
        self.readiness.set_subtitle(state.config.text());
        self.readiness_camera.set_subtitle(state.camera.text());
        self.readiness_pam.set_subtitle(state.pam.text());
        self.readiness_models.set_subtitle(state.models.text());
        self.readiness_attempts.set_subtitle(state.attempts.text());
        self.resume_face_login
            .set_visible(matches!(state.attempts, ReadinessValue::Blocked(_)));
    }

    fn begin_operation(&self, operation: Operation) -> bool {
        if self.operation.get() != Operation::Idle {
            self.toast(&tr("Another operation is already running"));
            return false;
        }
        self.operation.set(operation);
        self.operation_status.set_label(&operation.status());
        self.refresh_controls();
        true
    }

    fn end_operation(&self) {
        self.operation.set(Operation::Idle);
        self.operation_status.set_label("");
        self.refresh_controls();
    }

    fn refresh_controls(&self) {
        if self.loading_settings.get() {
            return;
        }
        let idle = self.operation.get() == Operation::Idle;
        self.operation_spinner.set_visible(!idle);
        self.operation_spinner.set_spinning(!idle);
        self.operation_status.set_visible(!idle);
        let command = self.active_command.borrow();
        self.operation_cancel
            .set_visible(!idle && command.is_some());
        self.operation_cancel.set_sensitive(
            command
                .as_ref()
                .is_some_and(commands::CommandControl::cancellation_safe),
        );
        drop(command);
        self.settings_page.set_sensitive(idle);
        self.models_group.set_sensitive(idle);
        self.apply
            .set_sensitive(idle && self.is_dirty() && self.widgets_valid());
        self.refresh_models.set_sensitive(idle);
        self.add_model_button.set_sensitive(idle);
        self.test_button.set_sensitive(idle);
        self.resume_face_login.set_sensitive(idle);
        self.show_snapshots.set_sensitive(idle);
        self.clear_snapshots.set_sensitive(idle);
        self.refresh_readiness();
    }

    fn is_dirty(&self) -> bool {
        self.loaded
            .borrow()
            .as_ref()
            .is_some_and(|old| *old != self.read_widgets())
    }

    fn refresh_apply(&self) {
        self.refresh_controls();
        self.sync_security_level();
    }

    fn recognition_widgets(&self) -> ui_state::Recognition {
        ui_state::Recognition {
            movement_challenge: self.movement_challenge.is_active(),
            require_movement_without_ir: self.require_movement_without_ir.is_active(),
            min_similarity: self.min_similarity.value(),
            personal_threshold: self.personal_threshold.is_active(),
        }
    }

    fn sync_security_level(&self) {
        if self.applying_preset.get() {
            return;
        }
        let preset = ui_state::Preset::of(self.recognition_widgets());
        let index = ui_state::Preset::ALL
            .iter()
            .position(|p| *p == preset)
            .unwrap_or(0) as u32;
        self.applying_preset.set(true);
        self.security_level.set_selected(index);
        self.applying_preset.set(false);
        self.security_level.set_subtitle(&preset.description());
    }

    fn apply_preset(&self) {
        if self.applying_preset.get() {
            return;
        }
        let preset = ui_state::Preset::ALL
            .get(self.security_level.selected() as usize)
            .copied()
            .unwrap_or(ui_state::Preset::Custom);
        if let Some(v) = preset.values() {
            self.applying_preset.set(true);
            self.movement_challenge.set_active(v.movement_challenge);
            self.require_movement_without_ir
                .set_active(v.require_movement_without_ir);
            self.min_similarity.set_value(v.min_similarity);
            self.personal_threshold.set_active(v.personal_threshold);
            self.applying_preset.set(false);
        }
        self.refresh_apply();
    }

    fn widgets_valid(&self) -> bool {
        let settings = self.read_widgets();
        peekin_core::management::valid_device_path(&settings.device_path)
    }

    async fn prepare_camera_action(&self) -> bool {
        if self.operation.get() != Operation::Idle {
            return false;
        }
        if !self.is_dirty() {
            return true;
        }
        let dialog = adw::AlertDialog::new(
            Some(&tr("Unsaved system-wide settings")),
            Some(&tr(
                "Save these settings before opening the camera, discard them, or cancel. \
                 Camera operations always use the settings on disk.",
            )),
        );
        dialog.add_responses(&[
            ("cancel", &tr("Cancel")),
            ("discard", &tr("Discard")),
            ("save", &tr("Save")),
        ]);
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        match dialog.choose_future(Some(&self.window)).await.as_str() {
            "save" => self.apply_settings().await,
            "discard" => self.load_settings(),
            _ => false,
        }
    }

    async fn run_command(
        &self,
        argv: Vec<String>,
        input: String,
        write: bool,
        mut on_line: impl FnMut(&str),
    ) -> commands::CommandResult {
        let control = if write && self.backend.elevate {
            commands::CommandControl::with_ready_handshake()
        } else {
            commands::CommandControl::new(write)
        };
        // No cancellation: it could race the helper's write.
        if write && input.is_empty() {
            control.mark_input_committed();
        }
        *self.active_command.borrow_mut() = Some(control.clone());
        self.refresh_controls();
        let cancel_button = self.operation_cancel.clone();
        let monitor = control.clone();
        let poll = glib::timeout_add_local(Duration::from_millis(60), move || {
            let can_cancel = monitor.cancellation_safe() && !monitor.is_cancelling();
            cancel_button.set_sensitive(can_cancel);
            glib::ControlFlow::Continue
        });
        let result = commands::execute(
            argv,
            self.backend.env(),
            input,
            SUBPROCESS_DEADLINE,
            control,
        )
        .await;
        poll.remove();
        self.active_command.borrow_mut().take();
        for line in result.output.lines() {
            on_line(line);
        }
        result
    }

    fn read_widgets(&self) -> Settings {
        let devices = self.devices.borrow();
        Settings {
            revision: self
                .loaded
                .borrow()
                .as_ref()
                .map(|s| s.revision.clone())
                .unwrap_or_default(),
            enabled: self.enabled.is_active(),
            device_path: devices
                .get(self.device.selected() as usize)
                .cloned()
                .unwrap_or_else(|| "none".into()),
            ir_only: self.ir_only.is_active(),
            min_similarity: self.min_similarity.value(),
            timeout: self.timeout.value().round() as i64,
            dark_threshold: self.dark_threshold.value(),
            detection_notice: self.detection_notice.is_active(),
            confirm_success: self.confirm_success.is_active(),
            abort_if_ssh: self.abort_if_ssh.is_active(),
            abort_if_lid_closed: self.abort_if_lid_closed.is_active(),
            movement_challenge: self.movement_challenge.is_active(),
            require_movement_without_ir: self.require_movement_without_ir.is_active(),
            personal_threshold: self.personal_threshold.is_active(),
            brighten_screen: self.brighten_screen.is_active(),
            save_failed_snapshots: self.save_failed_snapshots.is_active(),
            services: peekin_core::management::ServicesUpdate {
                sudo: self.service_sudo.is_active(),
                login_screen: self.service_login_screen.is_active(),
                lock_screen: self.service_lock_screen.is_active(),
                polkit: self.service_polkit.is_active(),
                console: self.service_console.is_active(),
            },
        }
    }

    fn restore_pending_settings(&self, pending: &Settings) {
        self.loading_settings.set(true);
        self.fill_devices(&pending.device_path);
        self.enabled.set_active(pending.enabled);
        self.ir_only.set_active(pending.ir_only);
        self.min_similarity.set_value(pending.min_similarity);
        self.timeout.set_value(pending.timeout as f64);
        self.dark_threshold.set_value(pending.dark_threshold);
        self.detection_notice.set_active(pending.detection_notice);
        self.confirm_success.set_active(pending.confirm_success);
        self.abort_if_ssh.set_active(pending.abort_if_ssh);
        self.abort_if_lid_closed
            .set_active(pending.abort_if_lid_closed);
        self.movement_challenge
            .set_active(pending.movement_challenge);
        self.require_movement_without_ir
            .set_active(pending.require_movement_without_ir);
        self.personal_threshold
            .set_active(pending.personal_threshold);
        self.brighten_screen.set_active(pending.brighten_screen);
        self.save_failed_snapshots
            .set_active(pending.save_failed_snapshots);
        self.show_services(pending.services);
        self.loading_settings.set(false);
        self.refresh_controls();
    }

    fn show_services(&self, services: peekin_core::management::ServicesUpdate) {
        self.service_sudo.set_active(services.sudo);
        self.service_login_screen.set_active(services.login_screen);
        self.service_lock_screen.set_active(services.lock_screen);
        self.service_polkit.set_active(services.polkit);
        self.service_console.set_active(services.console);
    }

    fn load_settings(&self) -> bool {
        let path = self.backend.config_file();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                self.toast(&tr_args("Cannot read settings: {e}", &[("e", &e)]));
                *self.loaded.borrow_mut() = None;
                self.readiness_state.borrow_mut().config =
                    if e.kind() == std::io::ErrorKind::NotFound {
                        ReadinessValue::Blocked(tr("not installed: config.ini is missing"))
                    } else {
                        ReadinessValue::Unknown(tr("settings read failed"))
                    };
                self.refresh_controls();
                return false;
            }
        };
        let config = match PeekinConfig::parse(&raw, path.display().to_string()) {
            Ok(c) => c,
            Err(e) => {
                self.toast(&tr_args("Cannot read settings: {e}", &[("e", &e)]));
                *self.loaded.borrow_mut() = None;
                self.apply.set_sensitive(false);
                self.readiness_state.borrow_mut().config =
                    ReadinessValue::Blocked(tr("invalid configuration"));
                self.refresh_controls();
                return false;
            }
        };
        for warning in config.invalid_values() {
            self.toast(&warning);
        }
        let s = Settings::from_config(&config, peekin_core::management::revision(&raw));
        self.loading_settings.set(true);
        *self.cameras.borrow_mut() = cameras::list();
        self.ir_only.set_active(s.ir_only);
        self.fill_devices(&s.device_path);

        self.enabled.set_active(s.enabled);
        self.min_similarity.set_value(s.min_similarity);
        self.timeout.set_value(s.timeout as f64);
        self.timeout
            .set_subtitle(&if config.legacy_default_timeout() {
                legacy_timeout_subtitle()
            } else {
                timeout_subtitle()
            });
        self.dark_threshold.set_value(s.dark_threshold);
        self.detection_notice.set_active(s.detection_notice);
        self.confirm_success.set_active(s.confirm_success);
        self.abort_if_ssh.set_active(s.abort_if_ssh);
        self.abort_if_lid_closed.set_active(s.abort_if_lid_closed);
        self.movement_challenge.set_active(s.movement_challenge);
        self.require_movement_without_ir
            .set_active(s.require_movement_without_ir);
        self.personal_threshold.set_active(s.personal_threshold);
        self.brighten_screen.set_active(s.brighten_screen);
        self.save_failed_snapshots
            .set_active(s.save_failed_snapshots);
        self.show_services(s.services);
        let camera_state = if !config.security_errors().is_empty() {
            ReadinessValue::Blocked(tr("invalid security settings"))
        } else {
            match cameras::resolve(&s.device_path) {
                Err(cameras::ResolveError::NoCamera) => {
                    ReadinessValue::Blocked(tr("automatic selection found no camera"))
                }
                Err(cameras::ResolveError::Missing(_)) => {
                    ReadinessValue::Blocked(tr("configured device missing"))
                }
                Ok(device) => match cameras::kind_of(&device) {
                    None => ReadinessValue::Blocked(tr("device is not a usable camera")),
                    Some(kind) if s.ir_only && kind != cameras::CameraKind::VerifiedInfrared => {
                        ReadinessValue::Blocked(tr("IR profile not verified"))
                    }
                    Some(_) if config.device_is_automatic() => ReadinessValue::Ready(tr_args(
                        "automatic: {camera}",
                        &[("camera", &device_label(&device.display().to_string()))],
                    )),
                    Some(_) => ReadinessValue::Ready(tr("configured device present")),
                },
            }
        };
        let sudo = std::fs::read_to_string("/etc/pam.d/sudo");
        let gdm = std::fs::read_to_string("/etc/pam.d/gdm-password");
        let pam_ready = match (sudo.as_deref(), gdm.as_deref()) {
            (Ok(sudo), Ok(gdm)) => {
                (ui_state::pam_rule_present(sudo) && ui_state::pam_rule_present(gdm))
                    || (ui_state::authselect_services(sudo, gdm)
                        && std::fs::read_to_string("/etc/authselect/authselect.conf")
                            .is_ok_and(|raw| raw.lines().next() == Some("custom/peekin"))
                        && ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
                            .iter()
                            .all(|path| {
                                std::fs::read_to_string(path)
                                    .is_ok_and(|body| ui_state::pam_rule_present(&body))
                            }))
            }
            _ => false,
        };
        let mut readiness = self.readiness_state.borrow_mut();
        readiness.config = if config.security_errors().is_empty() {
            ReadinessValue::Ready(if config.disabled() {
                tr("saved; disabled system-wide")
            } else {
                tr("saved and enabled")
            })
        } else {
            ReadinessValue::Blocked(tr("invalid security settings"))
        };
        readiness.camera = camera_state;
        readiness.pam = if pam_ready {
            ReadinessValue::Ready(tr("sudo/GDM rules present; administrator review required"))
        } else {
            ReadinessValue::Blocked(tr("validated sudo/GDM rules not detected"))
        };
        drop(readiness);
        *self.loaded.borrow_mut() = Some(s);
        self.loading_settings.set(false);
        self.refresh_controls();
        true
    }

    /// "Automatic" first, then every usable camera, keeping `current` selected.
    fn fill_devices(&self, current: &str) {
        let found = self.cameras.borrow();
        let recommended = cameras::best(&found);
        let mut devices = vec!["none".to_string()];
        let mut labels = vec![match recommended {
            Some(camera) => tr_args("Automatic · now {camera}", &[("camera", &camera.label())]),
            None => tr("Automatic · no camera found"),
        }];
        for camera in found.iter() {
            devices.push(camera.path.display().to_string());
            labels.push(if recommended.is_some_and(|r| r.path == camera.path) {
                tr_args("{camera} · recommended", &[("camera", &camera.label())])
            } else {
                camera.label()
            });
        }
        let selected = if peekin_core::config::is_automatic_device(current) {
            0
        } else {
            match devices.iter().skip(1).position(|d| same_node(d, current)) {
                Some(i) => {
                    devices[i + 1] = current.to_string();
                    i + 1
                }
                None => {
                    devices.insert(1, current.to_string());
                    labels.insert(1, device_label(current));
                    1
                }
            }
        };
        let unapproved_ir = found
            .iter()
            .any(|c| c.kind == cameras::CameraKind::InfraredCandidate)
            && !found
                .iter()
                .any(|c| c.kind == cameras::CameraKind::VerifiedInfrared);
        self.device.set_subtitle(&if unapproved_ir {
            tr(
                "An infrared camera is connected but not approved, so face login does not \
                prefer it yet; see “Physical infrared attestations” in the README",
            )
        } else {
            tr("Used for face login; the away lock can use another one")
        });
        let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        self.device
            .set_model(Some(&gtk::StringList::new(&label_refs)));
        self.device.set_selected(selected as u32);
        *self.devices.borrow_mut() = devices;
    }

    async fn apply_settings(&self) -> bool {
        if !self.begin_operation(Operation::Saving) {
            return false;
        }
        let Some(old) = self.loaded.borrow().clone() else {
            self.end_operation();
            return false;
        };
        let new = self.read_widgets();
        if old == new {
            self.toast(&tr("No changes to apply"));
            self.end_operation();
            return true;
        }
        let request = serde_json::json!({
            "expected_revision": old.revision, "enabled": new.enabled,
            "device_path": new.device_path, "ir_only": new.ir_only,
            "min_similarity": new.min_similarity, "timeout": new.timeout,
            "dark_threshold": new.dark_threshold, "detection_notice": new.detection_notice,
            "confirm_success": new.confirm_success, "abort_if_ssh": new.abort_if_ssh,
            "abort_if_lid_closed": new.abort_if_lid_closed,
            "movement_challenge": new.movement_challenge,
            "require_movement_without_ir": new.require_movement_without_ir,
            "personal_threshold": new.personal_threshold,
            "brighten_screen": new.brighten_screen,
            "save_failed_snapshots": new.save_failed_snapshots,
            "services": new.services
        })
        .to_string();
        let result = self
            .run_command(
                self.backend.management_argv("apply-settings", &[]),
                request,
                true,
                |_| {},
            )
            .await;
        let success =
            result.termination == commands::Termination::Completed && result.exit_code == 0;
        // Reconcile an uncertain write, then retain any unsaved edits instead
        // of silently discarding the user's work on cancel/timeout/failure.
        if self.load_settings() && !success {
            self.restore_pending_settings(&new);
        }
        self.end_operation();
        let message = match result.termination {
            commands::Termination::Cancelled => tr("Save cancelled; your edits are still here"),
            commands::Termination::TimedOut => {
                tr("Save timed out; checked disk and kept any unsaved edits")
            }
            commands::Termination::Completed if success => tr("Settings saved"),
            commands::Termination::Completed => tr_args(
                "Could not save: {error}",
                &[("error", &error_summary(result.exit_code, &result.output))],
            ),
        };
        self.toast(&message);
        success
    }

    fn clear_model_rows(&self) {
        for row in self.model_rows.borrow_mut().drain(..) {
            self.models_group.remove(&row);
        }
    }

    fn show_placeholder(&self, title: &str, subtitle: &str) {
        self.clear_model_rows();
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(subtitle)
            .build();
        self.models_group.add(&row);
        self.model_rows.borrow_mut().push(row.upcast());
    }

    async fn load_models(self: &Rc<Self>) {
        if !self.begin_operation(Operation::Loading) {
            return;
        }
        let user = self.backend.user.clone();
        let argv = if self.backend.elevate {
            self.backend.management_argv("metadata", &[])
        } else {
            self.backend.argv(&build_list_command(&user)[1..])
        };
        let result = self.run_command(argv, String::new(), false, |_| {}).await;
        let (code, output) = (result.exit_code, result.output);
        if result.termination == commands::Termination::Cancelled {
            let mut readiness = self.readiness_state.borrow_mut();
            readiness.models = ReadinessValue::Unknown(tr("load cancelled"));
            readiness.attempts = ReadinessValue::Unknown(tr("load cancelled"));
            drop(readiness);
            self.end_operation();
            self.toast(&tr("Model loading cancelled"));
            return;
        }
        if result.termination == commands::Termination::TimedOut {
            let mut readiness = self.readiness_state.borrow_mut();
            readiness.models = ReadinessValue::Unknown(tr("load timed out"));
            readiness.attempts = ReadinessValue::Unknown(tr("load timed out"));
            drop(readiness);
            self.end_operation();
            self.toast(&tr("Model loading timed out"));
            return;
        }
        // Replaced below once the helper's response has been validated.
        self.readiness_state.borrow_mut().attempts = if !self.backend.elevate {
            ReadinessValue::Unknown(tr("not available in development mode"))
        } else if code != 0 {
            ReadinessValue::Unknown(tr("authorization/read failed"))
        } else {
            ReadinessValue::Unknown(tr("invalid helper response"))
        };
        if !self.backend.elevate
            && code == 1
            && (output.trim().is_empty() || output.contains("no models initialised"))
        {
            self.readiness_state.borrow_mut().models =
                ReadinessValue::Blocked(tr("none; password fallback"));
            self.end_operation();
            self.refresh_readiness();
            self.show_placeholder(
                &tr("No face models yet"),
                &tr("Use “Add” to enroll your face"),
            );
            return;
        }
        if code != 0 {
            self.readiness_state.borrow_mut().models =
                ReadinessValue::Unknown(tr("authorization/read failed"));
            self.end_operation();
            self.refresh_readiness();
            self.show_placeholder(&tr("Face models are locked"), &error_summary(code, &output));
            return;
        }
        let (models, usable) = if self.backend.elevate {
            match ui_state::parse_model_metadata(&output, &self.backend.user) {
                Ok(result) => {
                    self.readiness_state.borrow_mut().attempts = attempts_state(&output);
                    self.personal_threshold.set_subtitle(
                        &match ui_state::parse_personal_threshold(&output) {
                            Some(value) => format!(
                                "{} {}",
                                personal_subtitle(),
                                tr_args("For you: {value}.", &[("value", &format!("{value:.3}"))])
                            ),
                            None => format!(
                                "{} {}",
                                personal_subtitle(),
                                tr("Needs a face model with two samples.")
                            ),
                        },
                    );
                    result
                }
                Err(e) => {
                    self.readiness_state.borrow_mut().models =
                        ReadinessValue::Unknown(tr("invalid helper response"));
                    self.end_operation();
                    self.refresh_readiness();
                    self.show_placeholder(&tr("Could not read model metadata"), &e.to_string());
                    return;
                }
            }
        } else {
            let listed = parse_plain_list(&output);
            let paths = peekin_core::PeekinPaths::from_dirs(
                self.backend
                    .config_dir
                    .clone()
                    .unwrap_or_else(|| "/etc/peekin".into()),
                self.backend
                    .data_dir
                    .clone()
                    .unwrap_or_else(|| "/usr/share/peekin".into()),
            );
            let usable = peekin_core::models::load_user_models(paths.user_models_dir(), &user)
                .map(|models| peekin_core::models::usable_embeddings(&models).len())
                .unwrap_or(0);
            (listed, usable)
        };
        if models.is_empty() {
            self.readiness_state.borrow_mut().models =
                ReadinessValue::Blocked(tr("none; password fallback"));
            self.end_operation();
            self.refresh_readiness();
            self.show_placeholder(
                &tr("No face models yet"),
                &tr("Use “Add” to enroll your face"),
            );
            return;
        }
        self.clear_model_rows();
        self.readiness_state.borrow_mut().models = if usable > 0 {
            ReadinessValue::Ready(trn(
                "{n} usable sample; Test required",
                "{n} usable samples; Test required",
                usable as u64,
            ))
        } else {
            ReadinessValue::Blocked(tr("no valid current embeddings"))
        };
        self.end_operation();
        self.refresh_readiness();
        // "Last used" comes from the user's own history (see load_activity).
        let used = peekin_core::activity::read(
            std::path::Path::new(peekin_core::activity::ACTIVITY_DIR),
            &user,
        )
        .map(|entries| peekin_core::activity::last_used(&entries))
        .unwrap_or_default();
        for m in models {
            let created = m
                .created
                .strip_prefix("Unix time ")
                .and_then(|t| t.parse().ok())
                .map_or_else(|| m.created.clone(), local_date);
            let last =
                m.id.parse::<i64>()
                    .ok()
                    .and_then(|id| used.iter().find(|(model, _)| *model == id))
                    .map(|(_, time)| local_date(*time as i64));
            let subtitle = match last {
                Some(when) => tr_args(
                    "Added {created} · last used {when}",
                    &[("created", &created), ("when", &when)],
                ),
                None => tr_args("Added {created} · not used yet", &[("created", &created)]),
            };
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&m.label))
                .subtitle(subtitle)
                .build();
            let improve = gtk::Button::builder()
                .icon_name("list-add-symbolic")
                .tooltip_text(tr("Improve recognition: add samples to this model"))
                .valign(gtk::Align::Center)
                .css_classes(["flat"])
                .build();
            {
                let ui = self.clone();
                let target = (m.id.clone(), m.label.clone());
                improve.connect_clicked(move |_| {
                    let (ui, target) = (ui.clone(), target.clone());
                    glib::spawn_future_local(async move { ui.add_model(Some(target)).await });
                });
            }
            row.add_suffix(&improve);
            let remove = gtk::Button::builder()
                .icon_name("user-trash-symbolic")
                .tooltip_text(tr("Remove this model"))
                .valign(gtk::Align::Center)
                .css_classes(["flat"])
                .build();
            let ui = self.clone();
            remove.connect_clicked(move |_| {
                let ui = ui.clone();
                let (id, label) = (m.id.clone(), m.label.clone());
                glib::spawn_future_local(async move { ui.remove_model(&id, &label).await });
            });
            row.add_suffix(&remove);
            self.models_group.add(&row);
            self.model_rows.borrow_mut().push(row.upcast());
        }
    }

    async fn confirm(
        &self,
        heading: &str,
        body: &str,
        action: &str,
        destructive: bool,
        extra: Option<&gtk::Widget>,
    ) -> bool {
        let dialog = adw::AlertDialog::new(Some(heading), Some(body));
        dialog.add_responses(&[("cancel", &tr("Cancel")), ("ok", action)]);
        dialog.set_response_appearance(
            "ok",
            if destructive {
                adw::ResponseAppearance::Destructive
            } else {
                adw::ResponseAppearance::Suggested
            },
        );
        dialog.set_default_response(Some(if destructive { "cancel" } else { "ok" }));
        dialog.set_close_response("cancel");
        if let Some(w) = extra {
            dialog.set_extra_child(Some(w));
        }
        dialog.choose_future(Some(&self.window)).await == "ok"
    }

    /// Capture samples for a new face model, or (`improve` = model ID and label) add them to an existing one.
    async fn add_model(self: &Rc<Self>, improve: Option<(String, String)>) {
        if !self.prepare_camera_action().await {
            return;
        }
        if !self.begin_operation(Operation::Enrolling) {
            return;
        }
        let picture = gtk::Picture::builder()
            .content_fit(gtk::ContentFit::Contain)
            .height_request(340)
            .hexpand(true)
            .build();
        let frame = gtk::Frame::builder()
            .child(&picture)
            .css_classes(["card"])
            .build();
        let status = gtk::Label::builder()
            .label(tr("Starting the camera…"))
            .wrap(true)
            .css_classes(["heading"])
            .build();
        let hint = gtk::Label::builder()
            .label(tr(
                "Look straight at the camera. The green box shows that your face was found.",
            ))
            .wrap(true)
            .css_classes(["dim-label"])
            .build();
        let progress = gtk::ProgressBar::builder().visible(false).build();
        let entry = adw::EntryRow::builder()
            .title(tr("Label (optional), e.g. “With glasses”"))
            .build();
        entry.set_text(&self.enrollment_label.borrow());
        {
            let saved = self.enrollment_label.clone();
            entry.connect_changed(move |e| *saved.borrow_mut() = e.text().to_string());
        }
        let labels = gtk::ListBox::builder()
            .css_classes(["boxed-list"])
            .selection_mode(gtk::SelectionMode::None)
            .build();
        labels.append(&entry);
        let capture = gtk::Button::builder()
            .label(tr("Capture"))
            .sensitive(false)
            .halign(gtk::Align::Center)
            .css_classes(["pill", "suggested-action"])
            .build();
        let body = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();
        for w in [
            frame.upcast_ref::<gtk::Widget>(),
            status.upcast_ref(),
            hint.upcast_ref(),
            progress.upcast_ref(),
            labels.upcast_ref(),
            capture.upcast_ref(),
        ] {
            body.append(w);
        }
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());
        let body_scroll = gtk::ScrolledWindow::builder()
            .child(&body)
            .propagate_natural_height(true)
            .build();
        toolbar.set_content(Some(&body_scroll));
        if improve.is_some() {
            entry.set_visible(false);
            hint.set_label(&tr(
                "Add samples where recognition fails, e.g. in dim light or with glasses. \
                 The green box shows that your face was found.",
            ));
        }
        let dialog = adw::Dialog::builder()
            .title(match &improve {
                Some((_, label)) => tr_args("Improve “{label}”", &[("label", label)]),
                None => tr("Add a face model"),
            })
            .content_width(560)
            .child(&toolbar)
            .build();

        let config_dir = self
            .backend
            .config_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/peekin"));
        let data_dir = self
            .backend
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/usr/share/peekin"));
        let closed = Rc::new(std::cell::Cell::new(false));
        let (actions, action_events) = async_channel::bounded(2);
        {
            let (active, closed, actions) = (
                self.active_enrollment.clone(),
                closed.clone(),
                actions.clone(),
            );
            dialog.connect_closed(move |_| {
                if let Some(control) = active.borrow().as_ref() {
                    control
                        .cancel
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                closed.set(true);
                let _ = actions.try_send(false);
            });
        }
        let capturing = Rc::new(std::cell::Cell::new(false));
        let retrying = Rc::new(Cell::new(false));
        {
            let (active, capturing, status, hint, progress, entry, retrying) = (
                self.active_enrollment.clone(),
                capturing.clone(),
                status.clone(),
                hint.clone(),
                progress.clone(),
                entry.clone(),
                retrying.clone(),
            );
            capture.connect_clicked(move |b| {
                if retrying.get() {
                    b.set_sensitive(false);
                    let _ = actions.try_send(true);
                    return;
                }
                if let Some(control) = active.borrow().as_ref() {
                    control
                        .capture
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                capturing.set(true);
                b.set_sensitive(false);
                entry.set_sensitive(false);
                status.set_label(&tr("Hold still…"));
                hint.set_label(&tr("Taking 5 samples of your face."));
                progress.set_fraction(0.0);
                progress.set_visible(true);
            });
        }
        dialog.present(Some(&self.window));

        let mut samples = None;
        let mut save_attempted = false;
        'session: loop {
            if samples.is_none() {
                retrying.set(false);
                capturing.set(false);
                capture.set_label(&tr("Capture"));
                capture.set_sensitive(false);
                entry.set_sensitive(true);
                progress.set_visible(false);
                picture.set_paintable(None::<&gtk::gdk::Paintable>);
                status.set_label(&tr("Starting the camera…"));
                let (events, control) = preview::start(config_dir.clone(), data_dir.clone());
                *self.active_enrollment.borrow_mut() = Some(control);
                while let Ok(event) = events.recv().await {
                    if closed.get() {
                        break 'session;
                    }
                    match event {
                        preview::Event::Frame(f) => {
                            let bytes = glib::Bytes::from_owned(f.rgb);
                            let texture = gtk::gdk::MemoryTexture::new(
                                f.width,
                                f.height,
                                gtk::gdk::MemoryFormat::R8g8b8,
                                &bytes,
                                (f.width * 3) as usize,
                            );
                            picture.set_paintable(Some(&texture));
                            if !capturing.get() {
                                let (text, ready) = match f.faces {
                                    0 => (tr("No face found — move into the camera's view"), false),
                                    1 => (tr("Face found — press Capture"), true),
                                    _ => (
                                        tr("More than one face — only you should be in view"),
                                        false,
                                    ),
                                };
                                status.set_label(&text);
                                capture.set_sensitive(ready);
                            }
                        }
                        preview::Event::Sample(n, total) => {
                            progress.set_fraction(n as f64 / total as f64);
                            status.set_label(&tr_args(
                                "Sample {n} of {total}",
                                &[("n", &n), ("total", &total)],
                            ));
                        }
                        preview::Event::Quality(message) => status.set_label(&tr(&message)),
                        preview::Event::Challenge(_) => {}
                        preview::Event::Status(_) => {}
                        preview::Event::Finished(Ok(s)) => {
                            samples = Some(s);
                            break;
                        }
                        preview::Event::Finished(Err(e)) | preview::Event::Failed(e) => {
                            status.set_label(&tr_args(
                                "Could not add the model: {e}",
                                &[("e", &tr(&e))],
                            ));
                            hint.set_label(&tr(
                                "Your label has been kept. Check the camera and press Retry.",
                            ));
                            progress.set_visible(false);
                            break;
                        }
                        preview::Event::FrameReady => unreachable!(),
                    }
                }
                drop(events);
            }
            if closed.get() {
                break;
            }
            if samples.is_none() {
                *self.active_enrollment.borrow_mut() = None;
                capture.set_label(&tr("Retry capture"));
                capture.set_sensitive(true);
                retrying.set(true);
                if action_events.recv().await != Ok(true) {
                    break;
                }
                continue;
            }
            *self.active_enrollment.borrow_mut() = None;

            status.set_label(&tr("Saving…"));
            hint.set_label(&tr("Your password may be requested to store the model."));
            capture.set_sensitive(false);
            dialog.set_can_close(false);
            self.operation.set(Operation::Saving);
            self.operation_status.set_label(&Operation::Saving.status());
            save_attempted = true;
            let label = entry.text().trim().to_string();
            let mut args = vec!["import-model".to_string()];
            if !label.is_empty() {
                args.push(label);
            }
            let input =
            serde_json::json!({ "format": EMBEDDING_FORMAT, "embeddings": samples.as_ref().unwrap() }).to_string();
            let argv = match &improve {
                Some((id, _)) => self
                    .backend
                    .management_argv("add-samples", std::slice::from_ref(id)),
                None => self.backend.management_argv("enroll", &args[1..]),
            };
            let result = self.run_command(argv, input, true, |_| {}).await;
            dialog.set_can_close(true);
            self.operation.set(Operation::Enrolling);
            self.operation_status
                .set_label(&Operation::Enrolling.status());
            if result.termination == commands::Termination::Completed && result.exit_code == 0 {
                self.enrollment_label.borrow_mut().clear();
                dialog.close();
                self.toast(&if improve.is_some() {
                    tr("Face model improved")
                } else {
                    tr("Face model added")
                });
                self.end_operation();
                self.load_models().await;
                return;
            } else {
                let detail = match result.termination {
                    commands::Termination::Cancelled => tr("Save cancelled before handoff"),
                    commands::Termination::TimedOut => {
                        tr("Save timed out; model list will be reloaded when this dialog closes")
                    }
                    commands::Termination::Completed => {
                        error_summary(result.exit_code, &result.output)
                    }
                };
                status.set_label(&tr_args(
                    "Could not confirm model save: {detail}",
                    &[("detail", &detail)],
                ));
                hint.set_label(&tr("The model list will be reconciled from disk. Captured samples remain available for retry until this dialog closes."));
                progress.set_visible(false);
                capture.set_label(&tr("Retry save"));
                capture.set_sensitive(true);
                retrying.set(true);
                if action_events.recv().await != Ok(true) {
                    break;
                }
            }
        }
        if let Some(control) = self.active_enrollment.borrow_mut().take() {
            control
                .cancel
                .store(true, std::sync::atomic::Ordering::Release);
        }
        self.end_operation();
        if save_attempted {
            self.load_models().await;
        }
    }

    async fn remove_model(self: &Rc<Self>, id: &str, label: &str) {
        let body = tr_args(
            "“{label}” will be deleted. If this is your last usable model, face authentication \
             for your account stops and the password remains available.",
            &[("label", &label)],
        );
        if !self
            .confirm(&tr("Remove face model?"), &body, &tr("Remove"), true, None)
            .await
        {
            return;
        }
        if !self.begin_operation(Operation::Removing) {
            return;
        }
        let argv = if self.backend.elevate {
            self.backend.management_argv("remove", &[id.into()])
        } else {
            self.backend
                .argv(&build_remove_command(id, &self.backend.user)[1..])
        };
        let confirmation = if self.backend.elevate { "remove\n" } else { "" };
        let command = self
            .run_command(argv, confirmation.into(), true, |_| {})
            .await;
        let result = match command.termination {
            commands::Termination::Cancelled => Err(tr("Removal cancelled; reloading models")),
            commands::Termination::TimedOut => Err(tr(
                "Removal timed out; reloading models to check whether it committed",
            )),
            commands::Termination::Completed if command.exit_code == 0 => Ok(command.output),
            commands::Termination::Completed => {
                Err(error_summary(command.exit_code, &command.output))
            }
        };
        self.end_operation();
        if let Err(e) = result {
            self.toast(&tr_args("Could not remove model: {e}", &[("e", &e)]));
        } else {
            self.toast(&tr("Model removed; removing the last usable model disables face authentication for your account"));
        }
        self.load_models().await;
    }

    async fn resume_face_login(self: &Rc<Self>) {
        if !self.backend.elevate || !self.begin_operation(Operation::Resuming) {
            return;
        }
        let argv = self.backend.management_argv("reset-attempts", &[]);
        let command = self.run_command(argv, "reset\n".into(), true, |_| {}).await;
        let message = match command.termination {
            commands::Termination::Cancelled => tr("Resume cancelled"),
            commands::Termination::TimedOut => tr("Resume timed out"),
            commands::Termination::Completed if command.exit_code == 0 => tr("Face login resumed"),
            commands::Termination::Completed => tr_args(
                "Could not resume face login: {error}",
                &[("error", &error_summary(command.exit_code, &command.output))],
            ),
        };
        self.end_operation();
        self.toast(&message);
        self.load_models().await;
    }

    /// Read directly: the history file carries a read ACL for its user.
    fn load_activity(&self) {
        for row in self.activity_rows.borrow_mut().drain(..) {
            self.activity_group.remove(&row);
        }
        let add = |row: adw::ActionRow| {
            self.activity_group.add(&row);
            self.activity_rows.borrow_mut().push(row.upcast());
        };
        let dir = std::path::Path::new(peekin_core::activity::ACTIVITY_DIR);
        let entries = match peekin_core::activity::read(dir, &self.backend.user) {
            Ok(entries) => entries,
            Err(error) => {
                add(adw::ActionRow::builder()
                    .title(tr("The history cannot be read"))
                    .subtitle(error.to_string())
                    .build());
                return;
            }
        };
        if entries.is_empty() {
            add(adw::ActionRow::builder()
                .title(tr("No face login attempts yet"))
                .build());
            return;
        }
        for entry in entries.iter().rev().take(20) {
            let when = local_date(entry.time as i64);
            let icon = if entry.outcome == peekin_core::activity::Outcome::Success {
                "emblem-ok-symbolic"
            } else if entry.outcome.is_failed_face() {
                "dialog-warning-symbolic"
            } else {
                "dialog-information-symbolic"
            };
            let row = adw::ActionRow::builder()
                .title(ui_state::outcome_text(entry.outcome))
                .subtitle(format!(
                    "{when} · {}",
                    ui_state::service_name(&entry.service)
                ))
                .build();
            row.add_prefix(&gtk::Image::from_icon_name(icon));
            add(row);
        }
    }

    fn load_session_settings(&self) {
        if let Some((config, state)) = peekin_core::session::xdg_bases() {
            let _ = peekin_core::session::migrate_legacy_files(&config, &state);
        }
        let s = peekin_core::session::SessionSettings::path()
            .map(|p| peekin_core::session::SessionSettings::load(&p))
            .unwrap_or_default();
        self.loading_session.set(true);
        self.lock_when_away.set_active(s.lock_when_away);
        self.away_secs.set_value(f64::from(s.away_secs));
        self.notify_failed.set_active(s.notify_failed_attempts);
        self.fill_away_cameras(&s.camera);
        self.loading_session.set(false);
    }

    /// The kinds, then every connected camera (and the saved one, if it is not connected now).
    fn fill_away_cameras(&self, current: &peekin_core::session::CameraChoice) {
        use peekin_core::session::CameraChoice;
        let mut choices = vec![
            CameraChoice::SameAsLogin,
            CameraChoice::AnyColour,
            CameraChoice::AnyInfrared,
        ];
        let mut labels = vec![
            tr("Same as face login"),
            tr("Any colour camera"),
            tr("Any infrared camera"),
        ];
        for camera in cameras::list() {
            choices.push(CameraChoice::Device(camera.path.display().to_string()));
            labels.push(camera.label());
        }
        let selected = match current {
            CameraChoice::Device(path) => match choices
                .iter()
                .position(|c| matches!(c, CameraChoice::Device(p) if same_node(p, path)))
            {
                Some(i) => i,
                None => {
                    choices.push(current.clone());
                    labels.push(device_label(path));
                    choices.len() - 1
                }
            },
            other => choices.iter().position(|c| c == other).unwrap_or(0),
        };
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        self.away_camera
            .set_model(Some(&gtk::StringList::new(&refs)));
        self.away_camera.set_selected(selected as u32);
        *self.away_cameras.borrow_mut() = choices;
    }

    fn save_session_settings(&self) {
        if self.loading_session.get() {
            return;
        }
        let settings = peekin_core::session::SessionSettings {
            lock_when_away: self.lock_when_away.is_active(),
            away_secs: self.away_secs.value().round() as u32,
            notify_failed_attempts: self.notify_failed.is_active(),
            camera: self
                .away_cameras
                .borrow()
                .get(self.away_camera.selected() as usize)
                .cloned()
                .unwrap_or_default(),
        };
        let saved = peekin_core::session::SessionSettings::path()
            .ok_or_else(|| std::io::Error::other("no home directory"))
            .and_then(|path| settings.save(&path));
        if let Err(e) = saved {
            self.toast(&tr_args("Could not save: {error}", &[("error", &e)]));
        }
    }

    fn show_snapshot_placeholder(&self, text: &str) {
        self.snapshots_flow.remove_all();
        self.snapshots_flow.append(
            &gtk::Label::builder()
                .label(text)
                .wrap(true)
                .css_classes(["dim-label"])
                .build(),
        );
    }

    async fn load_snapshots(self: &Rc<Self>) {
        if !self.backend.elevate {
            self.show_snapshot_placeholder(&tr("not available in development mode"));
            return;
        }
        if !self.begin_operation(Operation::LoadingSnapshots) {
            return;
        }
        let argv = self.backend.management_argv("snapshots", &[]);
        let result = self.run_command(argv, String::new(), false, |_| {}).await;
        self.end_operation();
        if result.termination != commands::Termination::Completed || result.exit_code != 0 {
            self.show_snapshot_placeholder(&error_summary(result.exit_code, &result.output));
            return;
        }
        let photos = match ui_state::parse_snapshots(&result.output, &self.backend.user) {
            Ok(photos) => photos,
            Err(error) => {
                self.show_snapshot_placeholder(&error);
                return;
            }
        };
        self.snapshots_flow.remove_all();
        self.clear_snapshots.set_visible(!photos.is_empty());
        if photos.is_empty() {
            self.show_snapshot_placeholder(&tr("No photos of failed attempts"));
            return;
        }
        for (time, jpeg) in photos {
            let when = local_date(time);
            let bytes = glib::Bytes::from_owned(glib::base64_decode(&jpeg));
            let Ok(texture) = gtk::gdk::Texture::from_bytes(&bytes) else {
                continue;
            };
            let picture = gtk::Picture::builder()
                .paintable(&texture)
                .content_fit(gtk::ContentFit::Contain)
                .width_request(200)
                .height_request(150)
                .alternative_text(tr_args(
                    "Photo of a failed attempt, {time}",
                    &[("time", &when)],
                ))
                .build();
            let card = gtk::Box::builder()
                .orientation(gtk::Orientation::Vertical)
                .spacing(4)
                .build();
            card.append(&picture);
            card.append(
                &gtk::Label::builder()
                    .label(&when)
                    .css_classes(["caption"])
                    .build(),
            );
            self.snapshots_flow.append(&card);
        }
    }

    async fn clear_snapshots(self: &Rc<Self>) {
        if !self
            .confirm(
                &tr("Delete all photos?"),
                &tr("The photos of failed attempts on your account will be deleted."),
                &tr("Delete"),
                true,
                None,
            )
            .await
        {
            return;
        }
        if !self.begin_operation(Operation::ClearingSnapshots) {
            return;
        }
        let argv = self.backend.management_argv("clear-snapshots", &[]);
        let result = self.run_command(argv, "clear\n".into(), true, |_| {}).await;
        self.end_operation();
        self.toast(&match result.termination {
            commands::Termination::Completed if result.exit_code == 0 => tr("Photos deleted"),
            commands::Termination::Completed => tr_args(
                "Could not delete the photos: {error}",
                &[("error", &error_summary(result.exit_code, &result.output))],
            ),
            _ => tr("Deleting the photos did not finish"),
        });
        self.load_snapshots().await;
    }

    async fn run_test(&self) {
        if !self.prepare_camera_action().await {
            return;
        }
        if !self.begin_operation(Operation::Testing) {
            return;
        }
        let buffer = self.test_output.buffer();
        buffer.set_text("");
        let argv = if self.backend.elevate {
            self.backend
                .management_argv("test", &[TEST_SECONDS.to_string()])
        } else {
            let config_dir = self
                .backend
                .config_dir
                .clone()
                .unwrap_or_else(|| "/etc/peekin".into());
            let data_dir = self
                .backend
                .data_dir
                .clone()
                .unwrap_or_else(|| "/usr/share/peekin".into());
            vec![
                std::env::current_exe().unwrap().display().to_string(),
                "--preview-test-worker".into(),
                config_dir.display().to_string(),
                data_dir.display().to_string(),
                self.backend.user.clone(),
                TEST_SECONDS.to_string(),
            ]
        };
        let (events, control) = preview::start_test_command(&argv, TEST_SECONDS);
        *self.active_test.borrow_mut() = Some(control);
        self.test_stop.set_sensitive(true);
        self.test_status.set_label(&tr("Starting camera…"));
        let mut challenge_instruction = String::new();
        while let Ok(event) = events.recv().await {
            match event {
                preview::Event::Frame(f) => {
                    let bytes = glib::Bytes::from_owned(f.rgb);
                    let texture = gtk::gdk::MemoryTexture::new(
                        f.width,
                        f.height,
                        gtk::gdk::MemoryFormat::R8g8b8,
                        &bytes,
                        (f.width * 3) as usize,
                    );
                    self.test_picture.set_paintable(Some(&texture));
                    self.test_picture
                        .update_property(&[gtk::accessible::Property::Description(&trn(
                            "Live camera frame containing {n} detected face",
                            "Live camera frame containing {n} detected faces",
                            f.faces as u64,
                        ))]);
                }
                preview::Event::Status(status) => {
                    let detail = match status.state {
                        preview::TestState::Starting => tr("Starting camera"),
                        preview::TestState::Dark => tr("Image too dark"),
                        preview::TestState::Covered => tr("Camera covered or unavailable"),
                        preview::TestState::NoFace => tr("No face found"),
                        preview::TestState::MultipleFaces => tr("Multiple faces; sequence reset"),
                        preview::TestState::NoMatch => {
                            status.similarity.map_or(tr("No match"), |s| {
                                tr_args("No match ({score})", &[("score", &format!("{s:.3}"))])
                            })
                        }
                        preview::TestState::Matching => tr_args(
                            "Matching frame {n} of {total} ({score})",
                            &[
                                ("n", &status.streak),
                                ("total", &status.required),
                                (
                                    "score",
                                    &format!("{:.3}", status.similarity.unwrap_or_default()),
                                ),
                            ],
                        ),
                        preview::TestState::Challenge => tr_args(
                            "{instruction} · stage {n} of {total}",
                            &[
                                ("instruction", &challenge_instruction),
                                ("n", &status.streak),
                                ("total", &status.required),
                            ],
                        ),
                        preview::TestState::Match => tr_args(
                            "Accepted after {n} consistent frames ({score})",
                            &[
                                ("n", &status.required),
                                (
                                    "score",
                                    &format!("{:.3}", status.similarity.unwrap_or_default()),
                                ),
                            ],
                        ),
                    };
                    self.test_status.set_label(&format!(
                        "{detail} · {}",
                        trn(
                            "{n} second remaining",
                            "{n} seconds remaining",
                            status.remaining.into()
                        )
                    ));
                    append_bounded(&buffer, &format!("{detail}\n"));
                }
                preview::Event::Finished(Err(error)) => {
                    self.test_status.set_label(&tr(&error));
                    break;
                }
                preview::Event::Finished(Ok(_)) => {
                    let challenge = self.loaded.borrow().as_ref().is_none_or(|s| {
                        let camera = cameras::resolve(&s.device_path)
                            .ok()
                            .and_then(|path| cameras::kind_of(&path));
                        peekin_core::config::movement_required(
                            s.movement_challenge,
                            s.require_movement_without_ir,
                            camera,
                        )
                    });
                    self.test_status.set_label(&if challenge {
                        tr(
                            "Identity and movement challenge passed. This is not proof against \
                            interactive replay or masks.",
                        )
                    } else {
                        tr(
                            "Face recognised (head-movement check is off). A photo of you could \
                            also pass this check.",
                        )
                    });
                    break;
                }
                preview::Event::Failed(e) => {
                    self.test_status.set_label(&tr("Test stopped"));
                    append_bounded(&buffer, &format!("{e}\n"));
                    break;
                }
                preview::Event::Quality(instruction) => {
                    let instruction = tr(&instruction);
                    self.test_status.set_label(&instruction);
                    append_bounded(&buffer, &format!("{instruction}\n"));
                }
                preview::Event::Challenge(instruction) => {
                    // Made in the camera worker, which may not run in this locale.
                    let instruction = tr(&instruction);
                    challenge_instruction = instruction.clone();
                    self.test_status.set_label(&instruction);
                    append_bounded(&buffer, &format!("{instruction}\n"));
                }
                preview::Event::Sample(_, _) => {}
                preview::Event::FrameReady => unreachable!(),
            }
        }
        *self.active_test.borrow_mut() = None;
        self.test_stop.set_sensitive(false);
        self.test_button.set_label(&tr("Run another test"));
        self.end_operation();
    }
}

/// E.g. `usb-` and `usbv3-` aliases of the same kernel node.
fn same_node(a: &str, b: &str) -> bool {
    a == b
        || matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

fn device_label(path: &str) -> String {
    if peekin_core::config::is_automatic_device(path) {
        return tr("Automatic");
    }
    let Ok(target) = std::fs::canonicalize(path) else {
        return tr_args("{path} (not found)", &[("path", &path)]);
    };
    let node = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name =
        std::fs::read_to_string(format!("/sys/class/video4linux/{node}/name")).unwrap_or_default();
    let bus = path.rsplit('/').next().unwrap_or(path);
    let driver = bus
        .split("-platform-")
        .nth(1)
        .and_then(|s| s.split('.').next());
    match (name.trim(), driver) {
        ("", _) => node,
        (name, Some(driver)) => format!("{name} ({node}, {driver})"),
        (name, None) => format!("{name} ({node})"),
    }
}

fn append_bounded(buffer: &gtk::TextBuffer, text: &str) {
    buffer.insert(&mut buffer.end_iter(), text);
    const MAX_LOG_CHARS: i32 = 16 * 1024;
    let excess = buffer.char_count() - MAX_LOG_CHARS;
    if excess > 0 {
        let mut start = buffer.start_iter();
        let mut end = buffer.iter_at_offset(excess);
        buffer.delete(&mut start, &mut end);
    }
}

fn on_click<F, Fut>(button: &gtk::Button, ui: &Rc<Ui>, action: F)
where
    F: Fn(Rc<Ui>) -> Fut + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let ui = ui.clone();
    button.connect_clicked(move |_| {
        glib::spawn_future_local(action(ui.clone()));
    });
}

fn switch(title: &str, subtitle: &str) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .build()
}

fn spin(title: &str, subtitle: &str, min: f64, max: f64, step: f64, digits: u32) -> adw::SpinRow {
    let row = adw::SpinRow::with_range(min, max, step);
    row.set_title(title);
    row.set_subtitle(subtitle);
    row.set_digits(digits);
    row
}

fn group(title: &str, rows: &[&gtk::Widget]) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::builder().title(title).build();
    for r in rows {
        g.add(*r);
    }
    g
}

fn personal_subtitle() -> String {
    tr(
        "Raise the match threshold from your own enrollment samples; it is never lowered. \
        Stricter against other faces, but may reject yours more often.",
    )
}
fn timeout_subtitle() -> String {
    tr(
        "Seconds to look for your face before asking for the password (default 3). \
        The head-movement check gets up to 8 more seconds",
    )
}
fn legacy_timeout_subtitle() -> String {
    tr(
        "10 s is the default of Linux Hello before 1.3, kept by the upgrade. The default is \
        now 3 s. The head-movement check gets up to 8 more seconds",
    )
}

fn local_date(unix: i64) -> String {
    glib::DateTime::from_unix_local(unix)
        .and_then(|t| t.format("%Y-%m-%d %H:%M"))
        .map_or_else(|_| unix.to_string(), |t| t.to_string())
}

const AUTHOR: &str = "Christos A. Daggas";
const AUTHOR_EMAIL: &str = "info@chrisdaggas.com";
const WEBSITE: &str = "https://chrisdaggas.com";

fn open_uri(uri: &str) {
    gtk::UriLauncher::new(uri).launch(None::<&gtk::Window>, None::<&gio::Cancellable>, |_| {});
}

fn link_row(title: &str, subtitle: &str, uri: &'static str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .activatable(true)
        .build();
    row.add_suffix(&gtk::Image::from_icon_name("adw-external-link-symbolic"));
    row.connect_activated(move |_| open_uri(uri));
    row
}

fn about_page() -> adw::PreferencesPage {
    let page = adw::PreferencesPage::new();
    let header = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .margin_top(12)
        .margin_bottom(6)
        .halign(gtk::Align::Center)
        .build();
    header.append(
        &gtk::Image::builder()
            .icon_name(APP_ID)
            .pixel_size(128)
            .accessible_role(gtk::AccessibleRole::Presentation)
            .build(),
    );
    header.append(
        &gtk::Label::builder()
            .label("PeekIn")
            .css_classes(["title-1"])
            .build(),
    );
    header.append(
        &gtk::Label::builder()
            .label(tr("Look. Recognize. Unlock."))
            .css_classes(["title-4"])
            .build(),
    );
    header.append(
        &gtk::Label::builder()
            .label(tr_args(
                "Version {version}",
                &[("version", &env!("CARGO_PKG_VERSION"))],
            ))
            .css_classes(["dim-label"])
            .build(),
    );
    let top = adw::PreferencesGroup::new();
    top.add(&header);
    page.add(&top);

    let about = adw::PreferencesGroup::builder()
        .title(tr("What it does"))
        .build();
    about.add(
        &gtk::Label::builder()
            .label(tr(
                "PeekIn is face authentication for Linux. It unlocks sudo, the GNOME lock \
                 screen and the login screen when you look at the camera, and your password \
                 always keeps working. A random head-movement check makes photos harder to \
                 use, your face data is encrypted with the TPM, and nothing leaves your \
                 computer. Face recognition is a convenience, not a replacement for your \
                 password.",
            ))
            .wrap(true)
            .xalign(0.0)
            .css_classes(["body"])
            .build(),
    );
    page.add(&about);

    let author = adw::PreferencesGroup::builder().title(tr("Author")).build();
    author.add(
        &adw::ActionRow::builder()
            .title(AUTHOR)
            .subtitle(tr("Design and development"))
            .build(),
    );
    author.add(&link_row(&tr("Website"), WEBSITE, WEBSITE));
    author.add(&link_row(
        &tr("Email"),
        AUTHOR_EMAIL,
        "mailto:info@chrisdaggas.com",
    ));
    page.add(&author);

    let legal = adw::PreferencesGroup::new();
    legal.add(
        &adw::ActionRow::builder()
            .title(tr("License"))
            .subtitle(tr(
                "MIT; the face models: MIT (YuNet) and Apache-2.0 (SFace)",
            ))
            .build(),
    );
    legal.add(
        &adw::ActionRow::builder()
            .title(tr("Copyright"))
            .subtitle(format!("© 2026 {AUTHOR}"))
            .build(),
    );
    page.add(&legal);
    page
}

fn attempts_state(output: &str) -> ReadinessValue {
    match ui_state::parse_attempts(output) {
        Ok(attempts) => {
            let resume_at = attempts
                .paused_until
                .and_then(|time| glib::DateTime::from_unix_local(time).ok())
                .and_then(|time| time.format("%H:%M").ok())
                .map_or_else(|| "later".to_string(), |time| time.to_string());
            ui_state::attempts_readiness(attempts, &resume_at)
        }
        Err(_) => ReadinessValue::Unknown(tr("could not read failed attempts")),
    }
}

fn build_ui(app: &adw::Application, backend: Backend) -> Rc<Ui> {
    let enabled = switch(
        &tr("Face authentication"),
        &tr("Offer face unlock for sudo, the lock screen and login"),
    );
    let device = adw::ComboRow::builder().title(tr("Camera")).build();
    let ir_only = switch(&tr("Infrared camera only"), &tr("Require an administrator-attested physical IR profile. Infrared alone does not prove liveness."),
    );
    let min_similarity = spin(
        &tr("Match threshold"),
        &tr("Higher is stricter. Default 0.363; calibrate on your hardware"),
        MIN_SIMILARITY,
        MAX_SIMILARITY,
        0.01,
        3,
    );
    let timeout = spin(
        &tr("Scan time"),
        &timeout_subtitle(),
        1.0,
        MAX_AUTH_TIMEOUT_SECS as f64,
        1.0,
        0,
    );
    let dark_threshold = spin(
        &tr("Dark frame threshold"),
        &tr("Frames darker than this (percent) are skipped"),
        1.0,
        100.0,
        1.0,
        0,
    );
    let detection_notice = switch(
        &tr("Announce face scan"),
        &tr("Show a message before the face scan"),
    );
    let confirm_success = switch(
        &tr("Confirm recognition"),
        &tr("Show “Face recognised: …” after a match"),
    );
    let abort_if_ssh = switch(
        &tr("Disable for remote sessions"),
        &tr("Never scan for SSH logins"),
    );
    let abort_if_lid_closed = switch(
        &tr("Disable when the lid is closed"),
        &tr("The camera cannot see you"),
    );
    let movement_challenge = switch(&tr("Head-movement check"), &tr("Ask for a random sequence of head turns after recognising you. Turn off to unlock by just looking at the camera: faster, but a photo of you is more likely to work"),
    );
    let personal_threshold = switch(&tr("Personal threshold"), &personal_subtitle());
    let save_failed_snapshots = switch(
        &tr("Save photos of failed attempts"),
        &tr(
            "When a face is seen but not accepted, keep a photo of it (the newest 20). \
             Only you and administrators can see them, on the Face models page",
        ),
    );
    let brighten_screen = switch(&tr("Light up the screen in the dark"), &tr("Raise the laptop screen to full brightness while the colour camera scans a dark room, then restore it"),
    );
    let require_movement_without_ir = switch(&tr("Keep it on without an infrared camera"), &tr("When the head-movement check is off, still ask for it unless an administrator-approved infrared camera is used. A photo on paper or a phone then cannot unlock with the colour camera"),
    );

    let service_sudo = switch(&tr("sudo in a terminal"), &tr("Also sudo -i"));
    let service_login_screen = switch(
        &tr("Login screen"),
        &tr("After starting the computer. The keyring stays locked until you enter your password"),
    );
    let service_lock_screen = switch(
        &tr("Lock screen"),
        &tr("Unlocking a session that is already running"),
    );
    let service_polkit = switch(
        &tr("Administrator dialogs"),
        &tr("Password dialogs of apps and pkexec (experimental)"),
    );
    let service_console = switch(
        &tr("Text console login"),
        &tr("Logging in on a local text terminal, e.g. Ctrl+Alt+F3 (experimental)"),
    );

    let settings_page = adw::PreferencesPage::new();
    settings_page.set_description(&tr("System-wide settings; per-user face models."));
    let readiness = adw::ActionRow::builder()
        .title(tr("Configuration"))
        .subtitle(tr("Checking settings…"))
        .build();
    let readiness_camera = adw::ActionRow::builder().title(tr("Camera")).build();
    let readiness_pam = adw::ActionRow::builder()
        .title(tr("PAM integration"))
        .build();
    let readiness_models = adw::ActionRow::builder().title(tr("Face models")).build();
    let readiness_attempts = adw::ActionRow::builder()
        .title(tr("Failed face attempts"))
        .build();
    let resume_face_login = gtk::Button::builder()
        .label(tr("Resume"))
        .tooltip_text(tr("Allow face login again now"))
        .valign(gtk::Align::Center)
        .visible(false)
        .build();
    readiness_attempts.add_suffix(&resume_face_login);
    settings_page.add(&group(&tr("General"), &[enabled.upcast_ref()]));
    settings_page.add(&group(
        &tr("Use face login for"),
        &[
            service_sudo.upcast_ref(),
            service_login_screen.upcast_ref(),
            service_lock_screen.upcast_ref(),
            service_polkit.upcast_ref(),
            service_console.upcast_ref(),
        ],
    ));
    settings_page.add(&group(
        &tr("Camera"),
        &[
            ir_only.upcast_ref(),
            device.upcast_ref(),
            timeout.upcast_ref(),
            dark_threshold.upcast_ref(),
            brighten_screen.upcast_ref(),
        ],
    ));
    let preset_names: Vec<String> = ui_state::Preset::ALL.iter().map(|p| p.name()).collect();
    let preset_refs: Vec<&str> = preset_names.iter().map(String::as_str).collect();
    let security_level = adw::ComboRow::builder()
        .title(tr("Security level"))
        .model(&gtk::StringList::new(&preset_refs))
        .build();
    settings_page.add(&group(
        &tr("Recognition"),
        &[
            security_level.upcast_ref(),
            movement_challenge.upcast_ref(),
            require_movement_without_ir.upcast_ref(),
            min_similarity.upcast_ref(),
            personal_threshold.upcast_ref(),
        ],
    ));
    settings_page.add(&group(
        &tr("Messages and safety"),
        &[
            detection_notice.upcast_ref(),
            confirm_success.upcast_ref(),
            abort_if_ssh.upcast_ref(),
            abort_if_lid_closed.upcast_ref(),
            save_failed_snapshots.upcast_ref(),
        ],
    ));
    let lock_when_away = switch(
        &tr("Lock when you walk away"),
        &tr(
            "After the time below without keyboard or mouse input, the camera looks for a face; \
             with nobody there for 10 seconds the screen locks. The camera light is on while it \
             looks",
        ),
    );
    let away_secs = spin(
        &tr("Lock after"),
        &tr("Seconds without input before the camera looks"),
        f64::from(peekin_core::session::MIN_AWAY_SECS),
        f64::from(peekin_core::session::MAX_AWAY_SECS),
        10.0,
        0,
    );
    lock_when_away
        .bind_property("active", &away_secs, "sensitive")
        .sync_create()
        .build();
    let away_camera = adw::ComboRow::builder()
        .title(tr("Camera"))
        .subtitle(tr(
            "It only needs to see that someone is there, so it can differ from the face \
             login camera, e.g. the colour camera while face login uses the infrared one",
        ))
        .build();
    lock_when_away
        .bind_property("active", &away_camera, "sensitive")
        .sync_create()
        .build();
    let notify_failed = switch(
        &tr("Tell me about failed attempts"),
        &tr("After you unlock, a notification when faces were rejected while you were away"),
    );
    let away_page = adw::PreferencesPage::new();
    away_page.set_description(&tr("For this account only; changes are saved right away."));
    away_page.add(&group(
        &tr("Walk-away lock"),
        &[
            lock_when_away.upcast_ref(),
            away_secs.upcast_ref(),
            away_camera.upcast_ref(),
        ],
    ));
    away_page.add(&group(&tr("Notifications"), &[notify_failed.upcast_ref()]));
    settings_page.add(&group(
        &tr("System status"),
        &[
            readiness.upcast_ref(),
            readiness_camera.upcast_ref(),
            readiness_pam.upcast_ref(),
            readiness_models.upcast_ref(),
            readiness_attempts.upcast_ref(),
        ],
    ));

    let models_page = adw::PreferencesPage::new();
    let models_group = adw::PreferencesGroup::builder()
        .title(tr_args("Face models for {user}", &[("user", &backend.user)]))
        .description(tr("Each model holds several samples of your face. Add one per look, e.g. with and without glasses."))
        .build();
    let header_box = gtk::Box::builder()
        .spacing(6)
        .valign(gtk::Align::Center)
        .build();
    let refresh = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text(tr("Load models"))
        .css_classes(["flat"])
        .build();
    let add = gtk::Button::builder()
        .label(tr("Add"))
        .css_classes(["suggested-action"])
        .build();
    header_box.append(&refresh);
    header_box.append(&add);
    models_group.set_header_suffix(Some(&header_box));
    models_page.add(&models_group);
    let activity_group = adw::PreferencesGroup::builder()
        .title(tr("Activity"))
        .description(tr("The latest face login attempts on your account."))
        .build();
    models_page.add(&activity_group);
    let snapshots_group = adw::PreferencesGroup::builder()
        .title(tr("Photos of failed attempts"))
        .description(tr(
            "Faces that were seen but not accepted, when “Save photos of failed attempts” is on.",
        ))
        .build();
    let show_snapshots = gtk::Button::builder()
        .label(tr("Show"))
        .valign(gtk::Align::Center)
        .build();
    let clear_snapshots = gtk::Button::builder()
        .label(tr("Delete all"))
        .valign(gtk::Align::Center)
        .css_classes(["destructive-action"])
        .visible(false)
        .build();
    let snapshots_header = gtk::Box::builder().spacing(6).build();
    snapshots_header.append(&clear_snapshots);
    snapshots_header.append(&show_snapshots);
    snapshots_group.set_header_suffix(Some(&snapshots_header));
    let snapshots_flow = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .max_children_per_line(3)
        .row_spacing(12)
        .column_spacing(12)
        .build();
    snapshots_group.add(&snapshots_flow);
    models_page.add(&snapshots_group);

    let test_output = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .build();
    let test_scroll = gtk::ScrolledWindow::builder()
        .child(&test_output)
        .vexpand(true)
        .css_classes(["card"])
        .build();
    let test_button = gtk::Button::builder()
        .label(tr("Run recognition and movement test"))
        .halign(gtk::Align::Center)
        .css_classes(["pill", "suggested-action"])
        .build();
    let test_stop = gtk::Button::builder()
        .label(tr("Stop"))
        .sensitive(false)
        .halign(gtk::Align::Center)
        .build();
    let test_picture = gtk::Picture::builder()
        .content_fit(gtk::ContentFit::Contain)
        .height_request(320)
        .tooltip_text(tr("Live camera test preview"))
        .build();
    let test_status = gtk::Label::builder()
        .label(tr("Ready to test"))
        .wrap(true)
        .css_classes(["heading"])
        .build();
    let test_hint = gtk::Label::builder()
        .label(tr("Look at the camera. Each line shows whether a face was found and how closely it matches yours."))
        .wrap(true)
        .css_classes(["dim-label"])
        .build();
    let test_page = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    test_page.append(&test_hint);
    test_page.append(&test_picture);
    test_page.append(&test_status);
    test_page.append(&test_button);
    test_page.append(&test_stop);
    test_scroll.set_min_content_height(160);
    let diagnostics = gtk::Expander::builder()
        .label(tr("Diagnostic details"))
        .child(&test_scroll)
        .build();
    test_page.append(&diagnostics);
    let test_clamp = adw::Clamp::builder()
        .maximum_size(800)
        .child(&test_page)
        .build();

    let stack = adw::ViewStack::new();
    stack.add_titled_with_icon(
        &settings_page,
        Some("settings"),
        &tr("Settings"),
        "preferences-system-symbolic",
    );
    stack.add_titled_with_icon(
        &models_page,
        Some("models"),
        &tr("Face models"),
        "avatar-default-symbolic",
    );
    let test_page_scroll = gtk::ScrolledWindow::builder()
        .child(&test_clamp)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    stack.add_titled_with_icon(
        &test_page_scroll,
        Some("test"),
        &tr("Test"),
        "camera-web-symbolic",
    );
    stack.add_titled_with_icon(
        &away_page,
        Some("away"),
        &tr("Away lock"),
        "system-lock-screen-symbolic",
    );
    stack.add_titled_with_icon(
        &about_page(),
        Some("about"),
        &tr("About"),
        "help-about-symbolic",
    );

    let apply = gtk::Button::builder()
        .label(tr("Apply"))
        .css_classes(["suggested-action"])
        .build();
    apply.set_sensitive(false);
    let switcher = adw::ViewSwitcher::builder()
        .stack(&stack)
        .policy(adw::ViewSwitcherPolicy::Wide)
        .build();
    let header = adw::HeaderBar::builder().title_widget(&switcher).build();
    let reload = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text(tr("Reload saved settings"))
        .build();
    header.pack_start(&reload);
    header.pack_end(&apply);
    let operation_spinner = gtk::Spinner::new();
    operation_spinner.set_visible(false);
    let operation_status = gtk::Label::builder()
        .visible(false)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .max_width_chars(28)
        .build();
    let operation_cancel = gtk::Button::builder()
        .label(tr("Cancel"))
        .visible(false)
        .build();
    let operation_box = gtk::Box::builder()
        .spacing(6)
        .valign(gtk::Align::Center)
        .build();
    operation_box.append(&operation_spinner);
    operation_box.append(&operation_status);
    operation_box.append(&operation_cancel);
    header.pack_end(&operation_box);

    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&stack));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&toasts));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("PeekIn")
        .default_width(900)
        .default_height(680)
        .width_request(360)
        .height_request(480)
        .content(&toolbar)
        .build();
    let compact = adw::Breakpoint::new(
        adw::BreakpointCondition::parse("max-width: 650sp").expect("valid breakpoint"),
    );
    compact.add_setter(
        &switcher,
        "policy",
        Some(&adw::ViewSwitcherPolicy::Narrow.to_value()),
    );
    window.add_breakpoint(compact);

    let ui = Rc::new(Ui {
        backend,
        window: window.clone(),
        toasts,
        apply: apply.clone(),
        enabled,
        device,
        devices: RefCell::new(Vec::new()),
        cameras: RefCell::new(Vec::new()),
        ir_only: ir_only.clone(),
        min_similarity,
        timeout,
        dark_threshold,
        detection_notice,
        confirm_success,
        abort_if_ssh,
        abort_if_lid_closed,
        movement_challenge,
        require_movement_without_ir,
        personal_threshold,
        brighten_screen,
        save_failed_snapshots,
        security_level: security_level.clone(),
        applying_preset: Cell::new(false),
        lock_when_away,
        away_secs,
        away_camera,
        away_cameras: RefCell::new(Vec::new()),
        loading_session: Cell::new(false),
        notify_failed,
        snapshots_flow,
        activity_group,
        activity_rows: RefCell::new(Vec::new()),
        show_snapshots: show_snapshots.clone(),
        clear_snapshots: clear_snapshots.clone(),
        service_sudo,
        service_login_screen,
        service_lock_screen,
        service_polkit,
        service_console,
        loaded: RefCell::new(None),
        operation: Cell::new(Operation::Idle),
        operation_status: operation_status.clone(),
        operation_spinner: operation_spinner.clone(),
        operation_cancel: operation_cancel.clone(),
        active_command: RefCell::new(None),
        settings_page,
        loading_settings: Cell::new(false),
        models_group,
        model_rows: RefCell::new(Vec::new()),
        readiness,
        readiness_camera,
        readiness_pam,
        readiness_models,
        readiness_attempts,
        resume_face_login: resume_face_login.clone(),
        readiness_state: RefCell::new(Readiness::default()),
        #[cfg(test)]
        stack: stack.clone(),
        refresh_models: refresh.clone(),
        add_model_button: add.clone(),
        test_output,
        test_picture,
        test_status,
        test_button: test_button.clone(),
        test_stop: test_stop.clone(),
        active_test: Rc::new(RefCell::new(None)),
        active_enrollment: Rc::new(RefCell::new(None)),
        enrollment_label: Rc::new(RefCell::new(String::new())),
    });

    on_click(&apply, &ui, |ui| async move {
        let _ = ui.apply_settings().await;
    });
    on_click(&refresh, &ui, |ui| async move {
        ui.load_activity();
        ui.load_models().await
    });
    on_click(&add, &ui, |ui| async move { ui.add_model(None).await });
    on_click(&test_button, &ui, |ui| async move { ui.run_test().await });
    on_click(&show_snapshots, &ui, |ui| async move {
        ui.load_snapshots().await
    });
    on_click(&clear_snapshots, &ui, |ui| async move {
        ui.clear_snapshots().await
    });
    on_click(&resume_face_login, &ui, |ui| async move {
        ui.resume_face_login().await
    });
    {
        let weak = Rc::downgrade(&ui);
        operation_cancel.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else { return };
            let accepted = ui
                .active_command
                .borrow()
                .as_ref()
                .is_some_and(commands::CommandControl::cancel);
            button.set_sensitive(false);
            ui.operation_status.set_label(&if accepted {
                tr("Cancelling…")
            } else {
                tr("Finishing authorized change…")
            });
        });
    }
    on_click(&reload, &ui, |ui| async move {
        if ui.operation.get() != Operation::Idle {
            return;
        }
        if !ui.is_dirty()
            || ui
                .confirm(
                    &tr("Discard unsaved settings?"),
                    &tr(
                        "Reload the current settings from disk. Unsaved changes will be discarded.",
                    ),
                    &tr("Reload"),
                    true,
                    None,
                )
                .await
        {
            ui.load_settings();
        }
    });
    {
        let active = ui.active_test.clone();
        test_stop.connect_clicked(move |_| {
            if let Some(control) = active.borrow().as_ref() {
                control
                    .cancel
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        });
    }
    {
        let weak = Rc::downgrade(&ui);
        window.connect_close_request(move |_| {
            if let Some(ui) = weak.upgrade() {
                if ui.operation.get().is_write() {
                    ui.toast(&tr(
                        "Please wait for the authorized change to finish before closing.",
                    ));
                    return glib::Propagation::Stop;
                }
                if let Some(command) = ui.active_command.borrow().as_ref() {
                    command.cancel();
                }
                for active in [&ui.active_test, &ui.active_enrollment] {
                    if let Some(control) = active.borrow().as_ref() {
                        control
                            .cancel
                            .store(true, std::sync::atomic::Ordering::Release);
                    }
                }
            }
            glib::Propagation::Proceed
        });
    }

    macro_rules! dirty_switch {
        ($row:expr) => {{
            let ui = ui.clone();
            $row.connect_active_notify(move |_| ui.refresh_apply());
        }};
    }
    macro_rules! dirty_spin {
        ($row:expr) => {{
            let ui = ui.clone();
            $row.connect_value_notify(move |_| ui.refresh_apply());
        }};
    }
    dirty_switch!(ui.enabled);
    dirty_switch!(ui.ir_only);
    dirty_switch!(ui.detection_notice);
    dirty_switch!(ui.confirm_success);
    dirty_switch!(ui.abort_if_ssh);
    dirty_switch!(ui.abort_if_lid_closed);
    dirty_switch!(ui.movement_challenge);
    dirty_switch!(ui.require_movement_without_ir);
    dirty_switch!(ui.personal_threshold);
    dirty_switch!(ui.brighten_screen);
    dirty_switch!(ui.save_failed_snapshots);
    {
        let row = ui.require_movement_without_ir.clone();
        ui.movement_challenge
            .bind_property("active", &row, "sensitive")
            .invert_boolean()
            .sync_create()
            .build();
    }
    dirty_switch!(ui.service_sudo);
    dirty_switch!(ui.service_login_screen);
    dirty_switch!(ui.service_lock_screen);
    dirty_switch!(ui.service_polkit);
    dirty_switch!(ui.service_console);
    dirty_spin!(ui.min_similarity);
    dirty_spin!(ui.timeout);
    dirty_spin!(ui.dark_threshold);
    {
        let ui2 = ui.clone();
        ui.device
            .connect_selected_notify(move |_| ui2.refresh_apply());
    }

    ui.load_settings();
    ui.load_activity();
    ui.load_session_settings();
    ui.sync_security_level();
    {
        let ui2 = ui.clone();
        ui.security_level
            .connect_selected_notify(move |_| ui2.apply_preset());
    }
    {
        let save = {
            let ui = ui.clone();
            move || ui.save_session_settings()
        };
        let (a, b, c, d) = (save.clone(), save.clone(), save.clone(), save);
        ui.lock_when_away.connect_active_notify(move |_| a());
        ui.away_secs.connect_value_notify(move |_| b());
        ui.notify_failed.connect_active_notify(move |_| c());
        ui.away_camera.connect_selected_notify(move |_| d());
    }
    ui.show_placeholder(
        &tr("Models are only readable by an administrator"),
        &tr("Use the refresh button to load them (asks for your password)"),
    );
    if !ui.backend.elevate {
        let ui = ui.clone();
        glib::spawn_future_local(async move { ui.load_models().await });
    }
    window.present();
    ui
}

struct Options {
    backend: Backend,
    gtk_args: Vec<String>,
}

fn parse_options() -> Result<Options, String> {
    let uid = unsafe { libc::getuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    if unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) } != 0
        || result.is_null()
    {
        return Err("cannot resolve the signed-in uid".into());
    }
    let user = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    validate_username(&user).map_err(|e| e.to_string())?;
    let mut backend = Backend {
        cli: "/usr/bin/peekin".into(),
        helper: "/usr/libexec/peekin/peekin-helper".into(),
        elevate: true,
        config_dir: None,
        data_dir: None,
        user,
    };
    let mut args = std::env::args();
    let mut gtk_args = vec![args.next().unwrap_or_else(|| "peekin-settings".into())];
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .map(PathBuf::from)
                .ok_or(format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--cli" => backend.cli = value()?,
            "--helper" => backend.helper = value()?,
            "--config-dir" => backend.config_dir = Some(value()?),
            "--data-dir" => backend.data_dir = Some(value()?),
            "--dev" => backend.elevate = false,
            _ => gtk_args.push(arg),
        }
    }
    if !backend.cli.is_absolute() || !backend.helper.is_absolute() {
        return Err("--cli and --helper must be absolute paths".into());
    }
    if !backend.elevate && (backend.config_dir.is_none() || backend.data_dir.is_none()) {
        return Err("--dev requires explicit --config-dir and --data-dir".into());
    }
    if backend.elevate && (backend.config_dir.is_some() || backend.data_dir.is_some()) {
        return Err("custom configuration directories require --dev".into());
    }
    Ok(Options { backend, gtk_args })
}

fn main() -> glib::ExitCode {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(String::as_str) == Some("--preview-worker") {
        if let Err(error) = peekin_core::process::arm_parent_death() {
            eprintln!("cannot arm preview parent-death guard: {error}");
            return glib::ExitCode::FAILURE;
        }
        if raw_args.len() != 4 {
            eprintln!("invalid preview worker arguments");
            return glib::ExitCode::FAILURE;
        }
        return match preview::worker_main(
            std::path::Path::new(&raw_args[2]),
            std::path::Path::new(&raw_args[3]),
        ) {
            Ok(()) => glib::ExitCode::SUCCESS,
            Err(e) => {
                preview::report_failure(e);
                glib::ExitCode::FAILURE
            }
        };
    }
    if raw_args.get(1).map(String::as_str) == Some("--preview-test-worker") {
        if let Err(error) = peekin_core::process::arm_parent_death() {
            eprintln!("cannot arm test-worker parent-death guard: {error}");
            return glib::ExitCode::FAILURE;
        }
        if let Err(error) = peekin_core::process::disable_dumpability() {
            eprintln!("cannot disable test-worker dumpability: {error}");
            return glib::ExitCode::FAILURE;
        }
        if raw_args.len() != 6 {
            eprintln!("invalid preview test worker arguments");
            return glib::ExitCode::FAILURE;
        }
        let seconds = raw_args[5].parse().unwrap_or(0);
        return match preview::test_worker_main(
            std::path::Path::new(&raw_args[2]),
            std::path::Path::new(&raw_args[3]),
            &raw_args[4],
            seconds,
        ) {
            Ok(()) => glib::ExitCode::SUCCESS,
            Err(e) => {
                preview::report_failure(e);
                glib::ExitCode::FAILURE
            }
        };
    }
    let options = match parse_options() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("peekin-settings: {e}\nusage: peekin-settings [--cli PATH] [--dev --config-dir DIR --data-dir DIR]");
            return glib::ExitCode::FAILURE;
        }
    };
    gio::resources_register_include!("peekin.gresource").expect("embedded resources are valid");
    let app = adw::Application::builder().application_id(APP_ID).build();
    let backend = options.backend;
    app.connect_startup(|_| gtk::Window::set_default_icon_name(APP_ID));
    app.connect_activate(move |app| {
        if let Some(window) = app.active_window() {
            window.present();
        } else {
            build_ui(app, backend.clone());
        }
    });
    app.run_with_args(&options.gtk_args)
}

#[cfg(test)]
mod gtk_tests {
    use super::*;

    /// A private loopback Broadway display, stopped on drop.
    struct Broadway(std::process::Child);

    impl Drop for Broadway {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Starts one unless the caller chose a display with `GDK_BACKEND`.
    fn isolated_display() -> Option<Broadway> {
        if std::env::var_os("GDK_BACKEND").is_some() {
            return None;
        }
        let display = format!(":{}", 100 + std::process::id() % 20000);
        let mut child = std::process::Command::new("gtk4-broadwayd")
            .args(["--address=127.0.0.1", "--port=0", &display])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("gtk4-broadwayd (package gtk4) for an isolated display");
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(
            child.try_wait().unwrap().is_none(),
            "could not start an isolated GTK display"
        );
        for (key, value) in [
            ("GDK_BACKEND", "broadway"),
            ("BROADWAY_DISPLAY", display.as_str()),
            ("GSK_RENDERER", "cairo"),
            ("G_DEBUG", "fatal-criticals"),
        ] {
            std::env::set_var(key, value);
        }
        Some(Broadway(child))
    }

    #[test]
    #[ignore = "starts a GTK display; run with --ignored --test-threads=1"]
    fn gtk_smoke_preserves_settings_and_operation_guards() {
        let _display = isolated_display();
        adw::init().expect("GTK test display");
        gio::resources_register_include!("peekin.gresource").unwrap();
        let root = std::env::temp_dir().join(format!("peekin-ui-smoke-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("config.ini"),
            include_str!("../../../data/config.ini")
                .replace("min_similarity = 0.363", "min_similarity = 0.99"),
        )
        .unwrap();
        let app = adw::Application::builder()
            .application_id("com.chrisdaggas.peekin.smoketest")
            .flags(gio::ApplicationFlags::NON_UNIQUE)
            .build();
        app.register(None::<&gio::Cancellable>).unwrap();
        let backend = Backend {
            cli: "/bin/false".into(),
            helper: "/bin/false".into(),
            elevate: true,
            config_dir: Some(root.clone()),
            data_dir: Some(root.clone()),
            user: "fixture".into(),
        };
        let ui = build_ui(&app, backend);
        assert!(ui.stack.child_by_name("setup").is_none());
        assert_eq!(ui.stack.visible_child_name().as_deref(), Some("settings"));
        let pump = || {
            let context = glib::MainContext::default();
            for _ in 0..30 {
                while context.pending() {
                    context.iteration(false);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        pump();
        // Broadway without a browser has no window manager; recreate the surface at the narrow size.
        ui.window.set_visible(false);
        gtk::prelude::WidgetExt::unrealize(&ui.window);
        ui.window.set_default_size(400, 600);
        ui.window.present();
        pump();
        assert!(ui.window.current_breakpoint().is_some());
        assert!(ui.stack.child_by_name("test").is_some());
        assert_eq!(ui.min_similarity.value(), 0.99);
        assert!(!ui.is_dirty());
        assert!(!ui.apply.is_sensitive());
        ui.detection_notice
            .set_active(!ui.detection_notice.is_active());
        assert!(ui.is_dirty() && ui.apply.is_sensitive());
        assert!(ui.begin_operation(Operation::Saving));
        let pending = commands::CommandControl::with_ready_handshake();
        *ui.active_command.borrow_mut() = Some(pending.clone());
        ui.refresh_controls();
        assert!(ui.operation_spinner.is_visible());
        assert!(ui.operation_cancel.is_visible() && ui.operation_cancel.is_sensitive());
        ui.operation_cancel.emit_clicked();
        assert!(pending.is_cancelling());
        assert!(!ui.operation_cancel.is_sensitive());
        ui.active_command.borrow_mut().take();
        ui.min_similarity.set_value(0.8);
        assert!(
            !ui.apply.is_sensitive(),
            "notifications must not re-enable Apply while saving"
        );
        assert!(!ui.begin_operation(Operation::Testing));
        assert!(!ui.resume_face_login.is_sensitive());
        assert!(!ui.show_snapshots.is_sensitive() && !ui.clear_snapshots.is_sensitive());
        assert!(
            !ui.clear_snapshots.is_visible(),
            "nothing to delete before loading"
        );
        assert!(!ui.save_failed_snapshots.is_active(), "photos are opt-in");
        assert!(ui.stack.child_by_name("away").is_some(), "Away lock page");
        assert!(ui.stack.child_by_name("about").is_some(), "About page");
        assert!(
            ui.away_cameras.borrow().len() >= 3,
            "same as login, any colour, any infrared"
        );
        ui.end_operation();
        assert!(!ui.resume_face_login.is_visible());
        let paused = ui_state::Attempts {
            failures: 5,
            limit: 5,
            paused_until: Some(1_790_000_000),
        };
        ui.readiness_state.borrow_mut().attempts = ui_state::attempts_readiness(paused, "14:32");
        ui.refresh_controls();
        assert!(ui.resume_face_login.is_visible() && ui.resume_face_login.is_sensitive());
        ui.readiness_state.borrow_mut().attempts = ui_state::attempts_readiness(
            ui_state::Attempts {
                paused_until: None,
                ..paused
            },
            "",
        );
        ui.refresh_readiness();
        assert!(!ui.resume_face_login.is_visible());
        assert!(!ui.operation_spinner.is_visible());
        assert!(ui.load_settings());
        assert_eq!(ui.min_similarity.value(), 0.99);
        assert!(ui.movement_challenge.is_active(), "challenge defaults on");
        assert!(ui.require_movement_without_ir.is_active());
        assert!(
            !ui.require_movement_without_ir.is_sensitive(),
            "only matters while the check itself is off"
        );
        assert!(ui.service_sudo.is_active() && !ui.service_console.is_active());
        ui.service_console.set_active(true);
        assert!(ui.is_dirty() && ui.read_widgets().services.console);
        ui.service_console.set_active(false);
        ui.movement_challenge.set_active(false);
        assert!(ui.is_dirty() && ui.apply.is_sensitive());
        assert!(ui.require_movement_without_ir.is_sensitive());
        ui.require_movement_without_ir.set_active(false);
        assert!(!ui.read_widgets().require_movement_without_ir);
        ui.require_movement_without_ir.set_active(true);
        assert!(!ui.read_widgets().movement_challenge);
        ui.ir_only.set_active(true);
        ui.enabled.set_active(false);
        assert!(
            ui.apply.is_sensitive(),
            "disabling must work without a trusted/present camera"
        );
        let draft = ui.read_widgets();
        assert!(ui.load_settings());
        ui.restore_pending_settings(&draft);
        assert!(
            ui.is_dirty(),
            "an uncertain write must not discard pending edits"
        );
        assert!(!ui.enabled.is_active());
        assert!(
            !ui.movement_challenge.is_active(),
            "a pending challenge change must survive reconciliation"
        );
        ui.load_settings();
        assert!(ui.movement_challenge.is_active());
        assert_eq!(ui.security_level.selected(), 3, "Custom");
        ui.security_level.set_selected(2); // Secure
        assert_eq!(ui.min_similarity.value(), 0.45);
        assert!(ui.personal_threshold.is_active() && ui.movement_challenge.is_active());
        assert_eq!(ui.security_level.selected(), 2);
        ui.security_level.set_selected(0); // Fast
        assert!(!ui.movement_challenge.is_active());
        ui.min_similarity.set_value(0.5);
        assert_eq!(ui.security_level.selected(), 3, "a hand edit is Custom");
        assert!(ui.load_settings());
        *ui.enrollment_label.borrow_mut() = "Retry label".into();
        let enrollment_ui = ui.clone();
        glib::spawn_future_local(async move {
            enrollment_ui.add_model(None).await;
        });
        fn button(widget: &gtk::Widget, text: &str) -> Option<gtk::Button> {
            if let Some(button) = widget.downcast_ref::<gtk::Button>() {
                if button.label().as_deref() == Some(text) {
                    return Some(button.clone());
                }
            }
            let mut child = widget.first_child();
            while let Some(widget) = child {
                if let Some(found) = button(&widget, text) {
                    return Some(found);
                }
                child = widget.next_sibling();
            }
            None
        }
        let mut retry = None;
        for _ in 0..15 {
            pump();
            if let Some(dialog) = ui.window.visible_dialog() {
                retry = button(dialog.upcast_ref(), "Retry capture");
                if retry.is_some() {
                    break;
                }
            }
        }
        assert!(retry.is_some(), "camera failure must offer in-dialog Retry");
        retry.unwrap().emit_clicked();
        pump();
        assert_eq!(&*ui.enrollment_label.borrow(), "Retry label");
        ui.window.visible_dialog().unwrap().close();
        pump();
        assert_eq!(ui.operation.get(), Operation::Idle);
        assert!(!ui.timeout.subtitle().unwrap().contains("before 1.3"));
        std::fs::write(
            root.join("config.ini"),
            include_str!("../../../data/config.ini").replace(
                "timeout = 3",
                "# 10 s is the new-install default.\ntimeout = 10",
            ),
        )
        .unwrap();
        assert!(ui.load_settings());
        assert!(ui.timeout.subtitle().unwrap().contains("before 1.3"));
        std::fs::remove_file(root.join("config.ini")).unwrap();
        assert!(!ui.load_settings());
        assert!(ui.loaded.borrow().is_none());
        assert!(!ui.apply.is_sensitive());
        ui.window.destroy();
        std::fs::remove_dir_all(root).unwrap();
    }
}
