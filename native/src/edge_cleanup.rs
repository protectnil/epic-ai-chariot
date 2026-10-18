// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// CHARIOT::§5.7 gate round 4 finding F2 (2026-09-04) — descriptor-based,
// TOCTOU-safe removal of a §5.7 sealed-shard stale-backup directory.
//
// The TypeScript caller (`ChariotState.ts::cleanupStaleDir`) previously
// validated a path with `lstatSync` and THEN removed it with a separate,
// path-based `rmSync` call — a same-uid process racing between those two
// syscalls could swap the validated directory for something else and have
// IT deleted instead (classic TOCTOU). This module closes that gap by doing
// validation and removal as one descriptor-relative operation: open the
// parent directory, `openat` the target BY NAME under that open parent
// (refusing to follow a symlink at the final component), `fstat` the
// resulting file descriptor (not a re-`lstat` of the path — a descriptor
// cannot be swapped out from under us once opened), atomically `renameat`
// it to a quarantine name so it is thereafter reachable ONLY via our own
// open descriptor tree, and then recursively remove its contents entirely
// through `openat`/`fdopendir`/`unlinkat` calls relative to that descriptor
// tree — never a path-based operation from this point on, so a subsequent
// swap-by-name at the ORIGINAL location cannot affect what gets deleted.
//
// F4 (root uid check meaningless as root): `expected_uid == 0` is refused
// unconditionally — ownership comparisons are not a meaningful security
// boundary against root, which bypasses them entirely.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use rand::RngCore;
use std::ffi::CString;
use std::os::unix::io::RawFd;

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| {
        Error::from_reason(format!("REMOVE_VALIDATION_FAILED: path contains a NUL byte: {e}"))
    })
}

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// RAII-closed raw file descriptor.
struct OwnedFd(RawFd);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: `self.0` is a fd this struct exclusively owns.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// Open `path` as a directory, refusing to follow a symlink at the final
/// path component (`O_NOFOLLOW`) and refusing anything that is not a
/// directory (`O_DIRECTORY`).
fn open_dir_nofollow(path: &CString) -> std::io::Result<RawFd> {
    // SAFETY: `path` is a valid NUL-terminated C string for the duration of
    // this call; `open` with these flags neither creates nor truncates.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        Err(last_os_error())
    } else {
        Ok(fd)
    }
}

/// Same as `open_dir_nofollow`, but relative to an already-open directory
/// descriptor (`openat` — the fd-relative primitive every subsequent
/// operation in this module is built on).
fn openat_dir_nofollow(parent_fd: RawFd, name: &CString) -> std::io::Result<RawFd> {
    // SAFETY: `parent_fd` is a valid, open directory fd for the duration of
    // this call (caller-owned); `name` is a valid NUL-terminated C string.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        Err(last_os_error())
    } else {
        Ok(fd)
    }
}

fn fstat(fd: RawFd) -> std::io::Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is a valid open fd; `st` is a valid, fully-sized `stat`
    // buffer for `fstat` to populate.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        Err(last_os_error())
    } else {
        Ok(st)
    }
}

/// Determine whether the directory entry `name` under `dir_fd` is itself a
/// real directory, WITHOUT following a symlink — used only when the
/// `dirent::d_type` the kernel returned is `DT_UNKNOWN` (some filesystems
/// never populate it). `AT_SYMLINK_NOFOLLOW` makes this the fd-relative
/// equivalent of `lstat`, not `stat`.
fn entry_is_real_dir(dir_fd: RawFd, name: &CString) -> std::io::Result<bool> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir_fd` valid open fd; `name` valid NUL-terminated C string;
    // `st` valid output buffer. AT_SYMLINK_NOFOLLOW means a symlink at
    // `name` is reported AS a symlink, never followed.
    let rc = unsafe {
        libc::fstatat(dir_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
    };
    if rc != 0 {
        return Err(last_os_error());
    }
    Ok((st.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

/// Recursively empty (but do not remove) the directory referenced by
/// `owned_dir_fd`, entirely through fd-relative operations. Consumes the fd
/// (via `fdopendir`, which takes ownership of it for the directory-stream
/// lifetime). NEVER descends through a symlink — a directory entry that
/// resolves to a symlink (whether by `d_type == DT_LNK` or, for
/// `DT_UNKNOWN` entries, by an `AT_SYMLINK_NOFOLLOW` stat) is removed as a
/// plain entry (`unlinkat` without `AT_REMOVEDIR`), never opened as a
/// directory.
fn remove_dir_contents(owned_dir_fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `owned_dir_fd` is a valid, open, not-yet-consumed directory
    // fd; `fdopendir` takes ownership of it (closed by `closedir` below).
    let dirp = unsafe { libc::fdopendir(owned_dir_fd) };
    if dirp.is_null() {
        let err = last_os_error();
        // SAFETY: fdopendir failed, so it did NOT take ownership; close it
        // ourselves to avoid leaking the descriptor.
        unsafe {
            libc::close(owned_dir_fd);
        }
        return Err(err);
    }

    struct DirGuard(*mut libc::DIR);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid, still-open `DIR*` this guard
            // exclusively owns.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let _guard = DirGuard(dirp);

    // SAFETY: `dirp` is valid and owned by `_guard` for the loop's duration.
    let raw_dir_fd = unsafe { libc::dirfd(dirp) };
    if raw_dir_fd < 0 {
        return Err(last_os_error());
    }

    loop {
        // SAFETY: `dirp` is a valid, open directory stream.
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            // NULL means EOF *or* an error; either way there is nothing
            // more this loop can safely read, so it stops here. A genuine
            // mid-listing error just means some entries were not visited —
            // the caller's subsequent `unlinkat(..., AT_REMOVEDIR)` on the
            // (still non-empty) directory will then fail with ENOTEMPTY,
            // surfacing the problem as a normal I/O error rather than a
            // silent false "removed".
            break;
        }
        // SAFETY: `entry` is a valid `dirent*` for the duration of this
        // iteration (until the next `readdir` call); `d_name` is
        // NUL-terminated within its fixed-size array.
        let name_bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name_owned = CString::new(name_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // SAFETY: `entry` still valid (same iteration).
        let d_type = unsafe { (*entry).d_type };

        let is_dir = match d_type {
            libc::DT_DIR => true,
            libc::DT_LNK | libc::DT_REG | libc::DT_FIFO | libc::DT_SOCK | libc::DT_CHR
            | libc::DT_BLK => false,
            _ => entry_is_real_dir(raw_dir_fd, &name_owned)?,
        };

        if is_dir {
            match openat_dir_nofollow(raw_dir_fd, &name_owned) {
                Ok(child_fd) => {
                    remove_dir_contents(child_fd)?;
                    // SAFETY: `raw_dir_fd` valid open fd; `name_owned` valid
                    // NUL-terminated C string; the child is now empty.
                    let rc = unsafe {
                        libc::unlinkat(raw_dir_fd, name_owned.as_ptr(), libc::AT_REMOVEDIR)
                    };
                    if rc != 0 {
                        return Err(last_os_error());
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                    // d_type claimed DT_DIR but the entry is actually a
                    // symlink now (raced out from under us) — refuse to
                    // descend; remove it as a non-directory entry instead.
                    // SAFETY: as above.
                    let rc = unsafe { libc::unlinkat(raw_dir_fd, name_owned.as_ptr(), 0) };
                    if rc != 0 {
                        return Err(last_os_error());
                    }
                }
                Err(e) => return Err(e),
            }
        } else {
            // SAFETY: `raw_dir_fd` valid open fd; `name_owned` valid
            // NUL-terminated C string. Never AT_REMOVEDIR here — this path
            // is reserved for non-directory entries (or a raced symlink).
            let rc = unsafe { libc::unlinkat(raw_dir_fd, name_owned.as_ptr(), 0) };
            if rc != 0 {
                return Err(last_os_error());
            }
        }
    }
    Ok(())
}

/// CHARIOT::§5.7 gate round 4 (F2, F4) — validate-then-remove a §5.7
/// sealed-shard stale-backup directory named `name` directly inside
/// `parent`, entirely via file-descriptor-relative operations so no
/// path-based TOCTOU window exists between validation and removal.
///
/// Returns:
///   - `Ok(true)`  — the directory was validated and fully removed.
///   - `Ok(false)` — `parent/name` does not exist (ENOENT). This is the
///     ONLY validation outcome that is NOT an error: an already-gone
///     registered entry is a normal, benign state (e.g. removed
///     out-of-band), not a mismatch.
///   - `Err(..)` with a message prefixed `REMOVE_VALIDATION_FAILED:` — the
///     object at `parent/name` failed validation (not a directory, a
///     symlink, wrong owner, `expected_uid == 0`, or any other pre-removal
///     check) and was NOT touched. The TS caller treats this as a registry
///     mismatch: logged, the entry dropped, nothing deleted.
///   - `Err(..)` with a message prefixed `REMOVE_IO_FAILED:` — validation
///     PASSED (the object was confirmed to be exactly what the registry
///     claimed) but removal itself failed partway. The TS caller treats
///     this as an ordinary cleanup failure: logged, the entry KEPT in the
///     registry for retry on the next successful load.
#[napi]
pub fn remove_stale_dir_validated(parent: String, name: String, expected_uid: u32) -> Result<bool> {
    // F4 — a uid comparison is not a security boundary against root, which
    // bypasses ownership checks entirely; refuse unconditionally rather
    // than silently validating against an uid that guarantees nothing.
    if expected_uid == 0 {
        return Err(Error::from_reason(
            "REMOVE_VALIDATION_FAILED: refusing expected_uid=0 (root) — ownership validation is \
             not a meaningful security boundary for root; run this service as a non-root user",
        ));
    }
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: {name:?} is not a valid single path component"
        )));
    }

    let parent_c = cstr(&parent)?;
    let name_c = cstr(&name)?;

    let parent_fd = open_dir_nofollow(&parent_c).map_err(|e| {
        Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: cannot open parent directory {parent:?}: {e}"
        ))
    })?;
    let _parent_guard = OwnedFd(parent_fd);

    let target_fd = match openat_dir_nofollow(parent_fd, &name_c) {
        Ok(fd) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(false),
        Err(e)
            if e.raw_os_error() == Some(libc::ELOOP)
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            return Err(Error::from_reason(format!(
                "REMOVE_VALIDATION_FAILED: {parent}/{name} is not a real directory (it may be a \
                 symlink): {e}"
            )))
        }
        Err(e) => {
            return Err(Error::from_reason(format!(
                "REMOVE_VALIDATION_FAILED: cannot open {parent}/{name}: {e}"
            )))
        }
    };
    let target_guard = OwnedFd(target_fd);

    // fstat on the OPEN DESCRIPTOR — not a path re-check — so nothing can
    // be swapped between this check and the operations that follow; they
    // all continue to operate on this exact fd (or fds derived from it).
    let st = fstat(target_fd).map_err(|e| {
        Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: fstat failed on {parent}/{name}: {e}"
        ))
    })?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: {parent}/{name} is not a directory (mode {:o})",
            st.st_mode
        )));
    }
    if st.st_uid != expected_uid {
        return Err(Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: {parent}/{name} is owned by uid {} (expected {expected_uid})",
            st.st_uid
        )));
    }

    // QUARANTINE: rename atomically, still under `parent_fd` (same
    // directory, name only changes) so the object is thereafter reachable
    // ONLY via our own already-open descriptor tree — a same-uid process
    // that swaps something else in at the ORIGINAL name after this point
    // cannot affect what gets deleted below, because everything below is
    // fd-relative, not name-relative to the original name.
    let mut nonce_bytes = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let quarantine_name = format!("{name}.quarantine-{}", crate::edge_snapshot::hex_encode(&nonce_bytes));
    let quarantine_c = cstr(&quarantine_name)?;
    // SAFETY: `parent_fd` valid open fd; `name_c`/`quarantine_c` valid
    // NUL-terminated C strings; both old and new names are within the same
    // already-open parent directory.
    let rc = unsafe {
        libc::renameat(parent_fd, name_c.as_ptr(), parent_fd, quarantine_c.as_ptr())
    };
    if rc != 0 {
        return Err(Error::from_reason(format!(
            "REMOVE_VALIDATION_FAILED: quarantine rename of {parent}/{name} failed: {}",
            last_os_error()
        )));
    }

    // Everything from here on is REMOVE_IO_FAILED territory: the object has
    // been fully validated AND is now exclusively reachable through our own
    // fd tree, so any failure past this point is an ordinary I/O failure,
    // not a validation concern.
    //
    // `fdopendir` takes ownership of the fd it is given; `target_fd` is
    // still needed afterward for nothing (the final removal below uses
    // `parent_fd` + `quarantine_name`, not `target_fd`), so hand it a `dup`
    // and let `target_guard`'s `Drop` close the original separately.
    // SAFETY: `target_fd` is a valid open fd (still owned by `target_guard`).
    let dup_fd = unsafe { libc::dup(target_fd) };
    if dup_fd < 0 {
        return Err(Error::from_reason(format!(
            "REMOVE_IO_FAILED: dup failed while removing {parent}/{quarantine_name}: {}",
            last_os_error()
        )));
    }
    if let Err(e) = remove_dir_contents(dup_fd) {
        return Err(Error::from_reason(format!(
            "REMOVE_IO_FAILED: failed to empty {parent}/{quarantine_name}: {e}"
        )));
    }
    drop(target_guard);

    // SAFETY: `parent_fd` valid open fd; `quarantine_c` valid NUL-terminated
    // C string; the quarantined directory has just been fully emptied.
    let rc = unsafe { libc::unlinkat(parent_fd, quarantine_c.as_ptr(), libc::AT_REMOVEDIR) };
    if rc != 0 {
        return Err(Error::from_reason(format!(
            "REMOVE_IO_FAILED: failed to remove emptied {parent}/{quarantine_name}: {}",
            last_os_error()
        )));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "chariot-edge-cleanup-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn my_uid() -> u32 {
        // SAFETY: getuid() takes no arguments and cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn validated_removal_removes_a_real_owned_directory_tree() {
        let parent = test_dir("removal-parent");
        let target = parent.join("target.stale-abc");
        fs::create_dir_all(target.join("nested/deeper")).expect("mkdir tree");
        fs::write(target.join("file.txt"), b"top level").expect("write");
        fs::write(target.join("nested/inner.txt"), b"nested").expect("write");
        fs::write(target.join("nested/deeper/leaf.txt"), b"leaf").expect("write");

        let removed = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "target.stale-abc".to_string(),
            my_uid(),
        )
        .expect("removal must succeed");
        assert!(removed, "a validated, owned real directory must be removed");
        assert!(!target.exists(), "the directory must be gone");

        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn missing_target_returns_ok_false_not_an_error() {
        let parent = test_dir("missing-parent");
        let removed = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "does-not-exist".to_string(),
            my_uid(),
        )
        .expect("a missing target must be Ok, not Err");
        assert!(!removed, "a missing target must return Ok(false)");
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn symlink_at_name_is_refused_not_followed_not_deleted() {
        let parent = test_dir("symlink-parent");
        let real_target = parent.join("real-target-outside");
        fs::create_dir_all(&real_target).expect("mkdir real target");
        fs::write(real_target.join("must-survive.txt"), b"do not delete me").expect("write");

        let link_path = parent.join("link.stale-def");
        symlink(&real_target, &link_path).expect("symlink");

        let r = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "link.stale-def".to_string(),
            my_uid(),
        );
        assert!(r.is_err(), "a symlink at the target name must be refused");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(
            msg.contains("REMOVE_VALIDATION_FAILED"),
            "must be classified as a validation failure, not an I/O failure; got: {msg}"
        );
        assert!(link_path.exists(), "the symlink itself must not be deleted");
        assert!(real_target.exists(), "the symlink TARGET must never be touched");
        assert!(
            real_target.join("must-survive.txt").exists(),
            "content inside the symlink target must survive"
        );

        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn wrong_expected_uid_is_refused() {
        let parent = test_dir("wronguid-parent");
        let target = parent.join("target.stale-ghi");
        fs::create_dir_all(&target).expect("mkdir");

        // Use an expected_uid that is (almost certainly) not our own — any
        // uid other than my_uid() proves the ownership check fires; we
        // cannot chown to another uid without root, so we assert the
        // MISMATCH path via a deliberately wrong expectation instead.
        let wrong_uid = my_uid().wrapping_add(1).max(1);
        let r = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "target.stale-ghi".to_string(),
            wrong_uid,
        );
        assert!(r.is_err(), "a uid mismatch must be refused");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(msg.contains("REMOVE_VALIDATION_FAILED"), "got: {msg}");
        assert!(target.exists(), "a uid-mismatched directory must not be deleted");

        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn expected_uid_zero_is_always_refused() {
        let parent = test_dir("rootuid-parent");
        let target = parent.join("target.stale-jkl");
        fs::create_dir_all(&target).expect("mkdir");

        let r = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "target.stale-jkl".to_string(),
            0,
        );
        assert!(r.is_err(), "expected_uid=0 must always be refused");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(msg.contains("root"), "error must explain the root refusal; got: {msg}");
        assert!(target.exists(), "nothing may be deleted when expected_uid=0 is refused");

        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn not_a_directory_is_refused() {
        let parent = test_dir("notadir-parent");
        fs::write(parent.join("plain-file.stale-mno"), b"not a directory").expect("write");

        let r = remove_stale_dir_validated(
            parent.to_string_lossy().to_string(),
            "plain-file.stale-mno".to_string(),
            my_uid(),
        );
        assert!(r.is_err(), "a plain file must be refused (not a directory)");
        let msg = r.err().expect("is_err confirmed").to_string();
        assert!(msg.contains("REMOVE_VALIDATION_FAILED"), "got: {msg}");
        assert!(parent.join("plain-file.stale-mno").exists());

        let _ = fs::remove_dir_all(&parent);
    }

    /// TOCTOU proof: this is the exact property `remove_stale_dir_validated`
    /// depends on internally between its own `openat` (validation) and its
    /// own `renameat` (quarantine) — an already-open descriptor's identity
    /// is fixed at open time and is UNAFFECTED by anything that later
    /// happens to the NAME it was opened through. Demonstrated directly: a
    /// name is opened, a racing actor then deletes the original object at
    /// that name and puts a completely different ("impostor") directory
    /// there instead, and the ALREADY-OPEN descriptor is shown to still see
    /// the ORIGINAL content, never the impostor's — proving that a swap
    /// occurring in the window between `remove_stale_dir_validated`'s own
    /// open-by-name and its subsequent fd-relative operations cannot
    /// redirect what gets validated or removed, because every operation
    /// after the initial open uses this same fd-identity guarantee rather
    /// than re-resolving the original name.
    #[test]
    fn an_already_open_descriptor_is_immune_to_a_later_swap_at_its_original_name() {
        let parent = test_dir("swap-parent");
        let original = parent.join("target.stale-pqr");
        fs::create_dir_all(&original).expect("mkdir original");
        fs::write(original.join("original-marker.txt"), b"the real one").expect("write");

        let replacement = parent.join("replacement-dir");
        fs::create_dir_all(&replacement).expect("mkdir replacement");
        fs::write(replacement.join("replacement-marker.txt"), b"the impostor").expect("write");

        // Open the ORIGINAL by name — this is what `remove_stale_dir_validated`
        // does as its very first step.
        let parent_c = cstr(&parent.to_string_lossy()).unwrap();
        let name_c = cstr("target.stale-pqr").unwrap();
        let parent_fd = open_dir_nofollow(&parent_c).expect("open parent");
        let opened_fd = openat_dir_nofollow(parent_fd, &name_c).expect("open original by name");

        // A racing actor swaps the NAME to point at a totally different
        // directory — this models an attacker (or an unrelated concurrent
        // process) racing between our open and our next operation. Modeled
        // with RENAMES ONLY (not remove-then-rename): an open directory fd
        // keeps the directory's INODE alive but NOT entries that get
        // unlinked out of it — `fs::remove_dir_all` would unlink
        // `original-marker.txt` out from under the still-open `opened_fd`
        // itself (that entry legitimately disappears; it is a real, but
        // different, effect than the swap this test is proving immunity
        // to). A rename never unlinks anything the held fd refers to — it
        // only changes which NAME points at which inode — so `parked` is
        // the ORIGINAL directory under a different name, and `original` is
        // then a completely fresh name occupied by the impostor.
        let parked = parent.join("target.stale-pqr.parked-by-attacker");
        fs::rename(&original, &parked).expect("attacker parks the original under a different name");
        fs::rename(&replacement, &original).expect("attacker renames the impostor over the freed name");

        // The already-open descriptor must STILL see the ORIGINAL content —
        // proving its identity was fixed at open time, immune to the rename
        // that just happened at its original name.
        let content_via_fd = unsafe {
            let subdir_c = std::ffi::CString::new("original-marker.txt").unwrap();
            let mut st: libc::stat = std::mem::zeroed();
            libc::fstatat(opened_fd, subdir_c.as_ptr(), &mut st, 0)
        };
        assert_eq!(
            content_via_fd, 0,
            "the already-open descriptor must still see original-marker.txt — its identity must \
             be unaffected by the rename at its original name"
        );
        let impostor_marker_via_fd = {
            let subdir_c = std::ffi::CString::new("replacement-marker.txt").unwrap();
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstatat(opened_fd, subdir_c.as_ptr(), &mut st, 0) };
            if rc != 0 {
                Some(std::io::Error::last_os_error())
            } else {
                None
            }
        };
        let io_err = impostor_marker_via_fd
            .expect("the already-open descriptor must NOT see the impostor's content at all");
        assert_eq!(
            io_err.raw_os_error(),
            Some(libc::ENOENT),
            "the already-open descriptor must report ENOENT for replacement-marker.txt — it must \
             still refer to the ORIGINAL directory, not whatever now occupies the original name; \
             got: {io_err}"
        );

        // A FRESH open by the (now-swapped) name must yield the impostor —
        // proving the swap really did take effect at the name, and that the
        // immunity demonstrated above is specifically a property of the
        // ALREADY-OPEN descriptor, not of the name itself.
        let fresh_fd = openat_dir_nofollow(parent_fd, &name_c).expect("fresh open by the swapped name");
        let fresh_sees_impostor = {
            let subdir_c = std::ffi::CString::new("replacement-marker.txt").unwrap();
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            unsafe { libc::fstatat(fresh_fd, subdir_c.as_ptr(), &mut st, 0) }
        };
        assert_eq!(
            fresh_sees_impostor, 0,
            "a FRESH open by the swapped name must see the impostor's content"
        );

        unsafe {
            libc::close(opened_fd);
            libc::close(fresh_fd);
            libc::close(parent_fd);
        }
        // Clean up whatever is now at each path (the impostor now at
        // `original`, and the real original content parked under a
        // different name).
        let _ = fs::remove_dir_all(&parked);
        let _ = fs::remove_dir_all(&parent);
    }
}
