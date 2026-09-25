//! gettext translations, text domain `peekin`. Use the bare names `tr`,
//! `tr_args`, `trn` and `tr_noop` so xgettext finds every message.

use std::ffi::{c_char, CStr, CString};
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};

pub const DOMAIN: &str = "peekin";
pub const LOCALE_DIR: &str = "/usr/share/locale";

extern "C" {
    fn bindtextdomain(domain: *const c_char, dir: *const c_char) -> *mut c_char;
    fn bind_textdomain_codeset(domain: *const c_char, codeset: *const c_char) -> *mut c_char;
    fn dgettext(domain: *const c_char, msgid: *const c_char) -> *mut c_char;
    fn dngettext(
        domain: *const c_char,
        singular: *const c_char,
        plural: *const c_char,
        n: std::ffi::c_ulong,
    ) -> *mut c_char;
}

static BOUND: AtomicBool = AtomicBool::new(false);

fn domain() -> CString {
    CString::new(DOMAIN).expect("no NUL in the domain name")
}

pub fn bind(dir: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(dir) = CString::new(dir.as_os_str().as_bytes()) else {
        return;
    };
    let (domain, utf8) = (domain(), c"UTF-8");
    // SAFETY: NUL-terminated strings that outlive the calls; glibc copies them.
    unsafe {
        bindtextdomain(domain.as_ptr(), dir.as_ptr());
        bind_textdomain_codeset(domain.as_ptr(), utf8.as_ptr());
    }
    BOUND.store(true, Ordering::Release);
}

pub fn tr(msgid: &str) -> String {
    if !BOUND.load(Ordering::Acquire) {
        bind(std::path::Path::new(LOCALE_DIR));
    }
    let Ok(id) = CString::new(msgid) else {
        return msgid.to_string();
    };
    let domain = domain();
    // SAFETY: dgettext returns `id` or catalogue memory, valid while copied.
    unsafe { CStr::from_ptr(dgettext(domain.as_ptr(), id.as_ptr())) }
        .to_string_lossy()
        .into_owned()
}

/// Singular or plural form for `n`, with `{n}` replaced.
pub fn trn(singular: &str, plural: &str, n: u64) -> String {
    if !BOUND.load(Ordering::Acquire) {
        bind(std::path::Path::new(LOCALE_DIR));
    }
    let (Ok(one), Ok(many)) = (CString::new(singular), CString::new(plural)) else {
        return if n == 1 { singular } else { plural }.replace("{n}", &n.to_string());
    };
    let domain = domain();
    // SAFETY: as in `tr`.
    let text = unsafe {
        CStr::from_ptr(dngettext(
            domain.as_ptr(),
            one.as_ptr(),
            many.as_ptr(),
            n as std::ffi::c_ulong,
        ))
    }
    .to_string_lossy()
    .into_owned();
    text.replace("{n}", &n.to_string())
}

/// Marks `msgid` for extraction only; it is translated where it is shown.
pub const fn tr_noop(msgid: &'static str) -> &'static str {
    msgid
}

/// [`tr`] with `{name}` placeholders filled in after translation.
pub fn tr_args(msgid: &str, args: &[(&str, &dyn Display)]) -> String {
    let mut text = tr(msgid);
    for (name, value) in args {
        text = text.replace(&format!("{{{name}}}"), &value.to_string());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untranslated_text_and_placeholders() {
        assert_eq!(
            tr("No such message in any catalogue"),
            "No such message in any catalogue"
        );
        assert_eq!(
            tr_args(
                "{n} of {total}, {n} again",
                &[("n", &2), ("total", &"five")]
            ),
            "2 of five, 2 again"
        );
        assert_eq!(tr("interior\0nul"), "interior\0nul");
        assert_eq!(trn("{n} face", "{n} faces", 1), "1 face");
        assert_eq!(trn("{n} face", "{n} faces", 3), "3 faces");
    }
}
