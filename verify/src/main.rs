// sandbox_verify_rs — same checks as sandbox_verify.c, but through the
// exact Rust FFI path runbox-helper will use — libc for confstr, manual
// extern "C" for sandbox_init_with_parameters (not in the libc crate, no
// public binding exists for it).
//
// Run:
//   cargo run

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

extern "C" {
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

fn resolve_tmpdir() -> String {
    let mut buf = vec![0u8; 1024];
    let len = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if len == 0 {
        panic!("confstr(_CS_DARWIN_USER_TEMP_DIR) failed: {}", std::io::Error::last_os_error());
    }
    buf.truncate(len - 1); // confstr's return includes the NUL terminator in the count
    let mut s = String::from_utf8(buf).expect("confstr returned non-UTF8");
    if s.ends_with('/') {
        s.pop();
    }
    s
}

fn main() {
    let tmpdir = resolve_tmpdir();
    println!("resolved TMPDIR (symlinked form): {tmpdir}");

    // /var/folders/... is a symlink to /private/var/folders/... — resolve
    // to the real path before using it as the sandbox parameter, same as
    // sandbox_verify.c.
    let real_tmpdir = std::fs::canonicalize(&tmpdir)
        .expect("realpath/canonicalize failed")
        .to_string_lossy()
        .into_owned();
    println!("resolved TMPDIR (real path):      {real_tmpdir}");

    let profile = r#"
(version 1)
(deny default)
(allow file-read-metadata (literal "/var") (literal "/tmp"))
(allow file-read* file-write* (subpath (param "TMPDIR")))
(allow file-read* (literal "/"))
(allow file-read-metadata (literal "/"))
"#;
    let c_profile = CString::new(profile).unwrap();
    let key = CString::new("TMPDIR").unwrap();
    let value = CString::new(real_tmpdir).unwrap();
    let params: [*const c_char; 3] = [key.as_ptr(), value.as_ptr(), ptr::null()];

    let mut errorbuf: *mut c_char = ptr::null_mut();
    let ret = unsafe {
        sandbox_init_with_parameters(c_profile.as_ptr(), 0, params.as_ptr(), &mut errorbuf)
    };

    if ret != 0 {
        let msg = unsafe {
            if errorbuf.is_null() {
                "(no error message)".to_string()
            } else {
                let s = CStr::from_ptr(errorbuf).to_string_lossy().into_owned();
                sandbox_free_error(errorbuf);
                s
            }
        };
        eprintln!("sandbox_init_with_parameters FAILED: {msg}");
        std::process::exit(1);
    }
    println!("sandbox_init_with_parameters: OK, profile applied");

    let inside = format!("{tmpdir}/runbox_sandbox_test.txt");
    match std::fs::write(&inside, b"ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(&inside);
            println!("write inside TMPDIR: ALLOWED (expected)");
        }
        Err(e) => println!("write inside TMPDIR: DENIED ({e}) -- UNEXPECTED, profile too strict"),
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let outside = format!("{home}/runbox_sandbox_test_should_fail.txt");
    match std::fs::write(&outside, b"should not happen") {
        Ok(_) => {
            let _ = std::fs::remove_file(&outside);
            println!("write outside TMPDIR (to $HOME): ALLOWED -- WRONG, sandbox not enforcing");
        }
        Err(e) => println!("write outside TMPDIR (to $HOME): DENIED ({e}) -- expected, sandbox working"),
    }
}
