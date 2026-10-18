// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// ONNX Runtime dylib-missing deadlock guard — fail fast instead of
// deadlocking when the shared library `ort`'s `load-dynamic` feature needs
// is absent.
//
// ROOT CAUSE (proved by strace against a minimal reproducer, 2026-07-30): on
// every host tested, `libonnxruntime.so` is not installed anywhere the
// dynamic linker's bare-name search reaches — confirmed by `ldconfig -p`
// (no onnx entry), a direct filesystem walk of every standard library
// directory, and `readelf -d` showing no RPATH/RUNPATH on
// `chariot-native.node`. `ort` 2.0.0-rc.12's lazy API-init path
// (`ort::api()` -> `setup_api()` -> `load_dylib_from_path`, vendored at
// ort-2.0.0-rc.12/src/lib.rs:183-205) calls
// `libloading::Library::new("libonnxruntime.so")` — a bare-name dlopen —
// the FIRST time any `Session::builder()` runs (splade.rs:298,
// encoder.rs's `TextEmbedding::try_new_from_user_defined` internally, both
// confirmed identically affected by independent discrimination testing).
//
// strace of the reproducer shows the calling thread correctly walk glibc's
// full glibc-hwcaps/plain-path candidate list for `libonnxruntime.so`,
// exhausting it with ENOENT on every candidate — then, instead of the
// `.expect("Failed to load ONNX Runtime dylib")` panic that should
// propagate as a clean error, that SAME thread issues one more
// `futex(FUTEX_WAIT_BITSET_PRIVATE, ...)` and never returns (reproduced
// under `timeout`, confirmed via strace, matches the previously reported 6+
// minute / futex_wait_queue / 0-CPU signature exactly). That dlopen-failure
// behavior lives below this crate — in glibc's dynamic linker and/or the
// vendored `ort` crate — neither of which this crate patches or vendors.
//
// What IS this crate's to fix: never call into that path when a pure
// filesystem check (no dlopen, no locks, cannot hang) already tells us the
// library isn't there. `ensure_ort_dylib_available` replicates the exact
// resolution `ort` uses (`ORT_DYLIB_PATH` env var if set and non-empty,
// else the platform bare name) and the exact candidate directories glibc's
// dynamic linker walked in the observed strace, so a negative result here
// carries the same evidentiary weight the real dlopen would — without ever
// invoking it. A positive result changes nothing: the caller proceeds into
// the same `Session::builder()` path that already existed.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
const BARE_DYLIB_NAME: &str = "libonnxruntime.so";

/// Candidate directories the Linux dynamic linker searched (per the strace
/// evidence above) for a bare `libonnxruntime.so`, in the same order:
/// per-arch glibc-hwcaps optimized variants first, then the plain path,
/// across both `/lib` and `/usr/lib` root prefixes.
#[cfg(target_os = "linux")]
const CANDIDATE_DIRS: &[&str] = &[
    "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3",
    "/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3",
    "/usr/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/glibc-hwcaps/x86-64-v3",
    "/lib/glibc-hwcaps/x86-64-v2",
    "/lib",
    "/usr/lib/glibc-hwcaps/x86-64-v3",
    "/usr/lib/glibc-hwcaps/x86-64-v2",
    "/usr/lib",
];

/// ORT_API_VERSION this build resolves to with the `api-24` feature enabled
/// (native/Cargo.toml:71) — `ort-sys-2.0.0-rc.12/src/version.rs` computes
/// `17 + (api-18..api-24 each contribute 1, and api-24 transitively enables
/// every prior api-N feature)` = 24. `ort` rejects any dylib whose reported
/// minor version is below this, so the guidance in the error message below
/// must match it exactly rather than a remembered/guessed number.
#[cfg(target_os = "linux")]
const REQUIRED_MINOR_VERSION: u32 = 24;

/// Directories registered with the dynamic linker through `/etc/ld.so.conf`
/// and `/etc/ld.so.conf.d/*.conf`.
///
/// CANDIDATE_DIRS above reproduces only the FIXED half of glibc's search —
/// the `/lib` and `/usr/lib` variants the 2026-07-30 strace walked, because on
/// that host nothing else was registered. That made the guard's negative
/// answer narrower than the real linker's: installing the library outside
/// `/lib`/`/usr/lib` and registering the directory in `/etc/ld.so.conf.d/` is
/// the standard way to add a search path, and the linker resolves it via the
/// `ldconfig` cache while this check did not.
///
/// That is not hypothetical. Measured 2026-08-09 on both run hosts: the
/// pinned runtime ("pin 1.24.4") is installed outside `/lib`/`/usr/lib` and
/// registered by an `/etc/ld.so.conf.d/*.conf` entry; `ldconfig -p` resolves
/// both `libonnxruntime.so` and `libonnxruntime.so.1` there. With `ORT_DYLIB_PATH`
/// unset, a fresh build of this crate still refused to load — the guard
/// reported the library missing on a host where the dynamic linker would have
/// found it. A false negative here blocks the very load the guard exists to
/// protect, so the registered directories are consulted too.
///
/// Parsing (not `ldconfig -p`): reading the config files is a pure filesystem
/// operation with no subprocess and no dlopen, preserving the "cannot hang"
/// property that is this module's whole point. `include` globs are followed
/// one level, which covers the `/etc/ld.so.conf` -> `ld.so.conf.d/*.conf`
/// layout every glibc distribution ships. Unreadable or absent files yield no
/// directories rather than an error: this function only ever WIDENS the
/// search, so failing to read a config can make the guard stricter, never
/// laxer.
#[cfg(target_os = "linux")]
fn ld_so_conf_dirs() -> Vec<PathBuf> {
    fn read_conf(path: &Path, out: &mut Vec<PathBuf>, follow_includes: bool) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("include ") {
                if !follow_includes {
                    continue;
                }
                let pattern = rest.trim();
                // Only the `<dir>/<glob>` form glibc's own configs use.
                if let Some((dir, _)) = pattern.rsplit_once('/') {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            let p = entry.path();
                            if p.extension().and_then(|e| e.to_str()) == Some("conf") {
                                read_conf(&p, out, false);
                            }
                        }
                    }
                }
                continue;
            }
            out.push(PathBuf::from(line));
        }
    }

    let mut dirs = Vec::new();
    read_conf(Path::new("/etc/ld.so.conf"), &mut dirs, true);
    if let Ok(entries) = std::fs::read_dir("/etc/ld.so.conf.d") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("conf") {
                read_conf(&p, &mut dirs, false);
            }
        }
    }
    dirs
}

/// Verify the ONNX Runtime shared library `ort`'s `load-dynamic` feature
/// would dlopen is actually present, WITHOUT calling anything that can
/// dlopen (and therefore without any chance of hitting the dlopen-failure
/// deadlock documented above). Returns `Ok(())` when found — callers
/// proceed exactly as before. Returns `Err` with an actionable message when
/// not found, so a missing dependency fails fast instead of hanging forever
/// inside `ort::Session::builder()`.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_ort_dylib_available() -> Result<(), String> {
    if let Some(explicit) = std::env::var("ORT_DYLIB_PATH").ok().filter(|s| !s.is_empty()) {
        return if Path::new(&explicit).is_file() {
            Ok(())
        } else {
            Err(format!(
                "ORT_DYLIB_PATH={explicit} does not name an existing file. Refusing to call \
                 ort::Session::builder() (a dlopen that fails to find its target is known to \
                 deadlock in a futex wait here instead of returning a clean error). Point \
                 ORT_DYLIB_PATH at a real libonnxruntime.so (ONNX Runtime API version >= \
                 1.{REQUIRED_MINOR_VERSION}.x)."
            ))
        };
    }

    // LD_LIBRARY_PATH entries take priority over the fixed system dirs,
    // same order the real dynamic linker uses.
    let ld_library_path_dirs: Vec<PathBuf> = std::env::var("LD_LIBRARY_PATH")
        .ok()
        .map(|v| std::env::split_paths(&v).collect())
        .unwrap_or_default();

    let found = ld_library_path_dirs
        .iter()
        .map(PathBuf::as_path)
        .chain(CANDIDATE_DIRS.iter().map(Path::new))
        .any(|dir| dir.join(BARE_DYLIB_NAME).is_file())
        || ld_so_conf_dirs()
            .iter()
            .any(|dir| dir.join(BARE_DYLIB_NAME).is_file());

    if found {
        Ok(())
    } else {
        Err(format!(
            "{BARE_DYLIB_NAME} was not found in LD_LIBRARY_PATH or any standard library \
             directory. ort::Session::builder() would dlopen this exact bare name and is known \
             to deadlock in a futex wait instead of failing cleanly when it is missing — \
             refusing to call it. Set ORT_DYLIB_PATH to a valid libonnxruntime.so (ONNX Runtime \
             API version >= 1.{REQUIRED_MINOR_VERSION}.x) or install the shared library the \
             deployment container is expected to ship (native/Cargo.toml:58,15)."
        ))
    }
}

/// Only Linux/x86_64 deployments are in scope for the in-process vector
/// runtime (native/Cargo.toml's seccomp wrapper is Linux/x86_64-only for the
/// same reason). On any other OS, fall through unchanged rather than
/// guessing an unverified search list — this guard exists to close a
/// PROVEN Linux dlopen-failure hang, not to speculate about other
/// platforms' dynamic-linker behavior.
#[cfg(not(target_os = "linux"))]
pub(crate) fn ensure_ort_dylib_available() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ORT_DYLIB_PATH` pointed at a file that does not exist must be
    /// rejected — this is the exact condition that, before this guard
    /// existed, led straight into the hanging `Session::builder()` call
    /// (proved by strace: the failing dlopen candidate search precedes the
    /// unbounded futex wait).
    #[test]
    fn rejects_a_nonexistent_explicit_dylib_path() {
        // SAFETY (test-only): scoped to this test's own env var name; no
        // other test in this crate reads or writes ORT_DYLIB_PATH.
        std::env::set_var(
            "ORT_DYLIB_PATH",
            "/nonexistent/ort-dylib-guard-test/libonnxruntime.so",
        );
        let err = ensure_ort_dylib_available().unwrap_err();
        assert!(err.contains("ORT_DYLIB_PATH"), "got: {err}");
        std::env::remove_var("ORT_DYLIB_PATH");
    }

    /// The positive case must also work: when `ORT_DYLIB_PATH` names a real
    /// file, the guard must not block the caller. Uses a throwaway temp file
    /// rather than a real onnxruntime binary — this function only proves
    /// existence, never opens or inspects the target (that stays entirely
    /// `ort`'s job, unchanged, inside `Session::builder()`).
    #[test]
    fn accepts_an_existing_explicit_dylib_path() {
        let path = std::env::temp_dir().join(format!(
            "ort-dylib-guard-test-fake-dylib-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a real dylib; existence-only check").unwrap();
        std::env::set_var("ORT_DYLIB_PATH", &path);

        let result = ensure_ort_dylib_available();

        std::env::remove_var("ORT_DYLIB_PATH");
        let _ = std::fs::remove_file(&path);
        assert!(result.is_ok(), "got: {result:?}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod ld_so_conf_tests {
    use super::*;

    /// The regression this closes: on both run hosts the pinned ONNX Runtime
    /// is registered ONLY through `/etc/ld.so.conf.d/`, and the guard called
    /// it missing. If `ldconfig` resolves the bare name on this machine, the
    /// guard must agree — with `ORT_DYLIB_PATH` unset.
    #[test]
    fn agrees_with_the_dynamic_linker_when_the_dylib_is_registered_via_ld_so_conf() {
        let registered = ld_so_conf_dirs()
            .iter()
            .any(|dir| dir.join(BARE_DYLIB_NAME).is_file());
        if !registered {
            // Nothing registered here; this host cannot exercise the case.
            return;
        }
        // SAFETY: single-threaded test, restores nothing because the guard
        // reads the var fresh on every call.
        let saved = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");
        let verdict = ensure_ort_dylib_available();
        if let Some(v) = saved {
            std::env::set_var("ORT_DYLIB_PATH", v);
        }
        assert!(
            verdict.is_ok(),
            "a dylib registered via /etc/ld.so.conf.d must satisfy the guard: {:?}",
            verdict.unwrap_err()
        );
    }

    #[test]
    fn ld_so_conf_dirs_never_panics_and_returns_absolute_paths() {
        for dir in ld_so_conf_dirs() {
            assert!(
                dir.is_absolute(),
                "ld.so.conf entry {dir:?} is not an absolute directory path"
            );
        }
    }
}
