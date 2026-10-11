//! Config, paths, the face model store, and the authentication and enrollment
//! loops. No native dependencies; cameras live in `peekin-vision` behind
//! [`source::FaceSource`].

pub mod activity;
pub mod authselect;
pub mod backlight;
pub mod cameras;
pub mod compare;
pub mod config;
pub mod editor;
pub mod enroll;
pub mod fsutil;
pub mod gtk_models;
pub mod i18n;
pub mod ir_profile;
pub mod lid;
pub mod lockout;
pub mod lowlight;
pub mod management;
pub mod matcher;
pub mod models;
pub mod paths;
pub mod process;
pub mod sealed;
pub mod session;
pub mod set_option;
pub mod snapshots;
pub mod source;

pub use config::PeekinConfig;
pub use models::{FaceModel, ModelError};
pub use paths::PeekinPaths;
