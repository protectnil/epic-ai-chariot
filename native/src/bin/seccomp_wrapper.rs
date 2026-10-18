// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 protectNIL Inc.
//
// chariot-seccomp-wrapper — OS-level confinement for spawned adapter child
// processes on the `npx @epicai/chariot` self-hosted path (no pod, so no
// K8s NetworkPolicy / PSA applies there — see helm/chariot NetworkPolicy for
// the in-cluster equivalent). Wired in from
// src/engine/federation/sandbox/ProcessSandbox.ts, which spawns THIS binary
// instead of `node` directly when running on Linux and the binary is
// present; this binary installs a deny-list seccomp-bpf filter plus
// no_new_privs, then execve()s into the real Node child.
//
// Linux x86_64 and aarch64 (the arch check and syscall numbers are selected
// per target_arch below; any other arch fails to compile). Never
// built/shipped for non-Linux targets; the TS caller
// is also platform-gated so this binary is simply absent elsewhere.
//
// Threat model / design:
//   - This is a DENY-LIST, not an allow-list. An allow-list precise enough
//     for the full Node + napi (ONNX/tokenizers/etc.) runtime surface would
//     be enormous and brittle across Node versions; a hand-rolled allow-list
//     that's even slightly wrong fails CLOSED (adapter startup breaks) which
//     violates the "must not break normal adapter startup" requirement. The
//     deny-list instead blocks the well-known container/sandbox escape and
//     system-tampering primitives while leaving the rest of the syscall
//     surface untouched.
//   - Denied unconditionally: ptrace, mount/umount2/pivot_root/chroot,
//     unshare/setns (namespace creation/join outside of clone(2) flags),
//     kernel module load/unload, kexec, reboot, swap on/off, the keyrings
//     API (add_key/request_key/keyctl), bpf(2), perf_event_open, the
//     cross-process memory primitives (process_vm_readv/writev), the
//     handle-based filesystem escape primitives (name_to_handle_at /
//     open_by_handle_at), acct, quotactl, lookup_dcookie.
//   - Denied conditionally: clone(2) (legacy syscall, NR 56 on x86_64, 220 on aarch64) is allowed for
//     ordinary thread creation (libuv / Node worker_threads use it with
//     CLONE_VM|CLONE_THREAD|... which never sets a CLONE_NEW* bit) but
//     DENIED when the flags argument carries any CLONE_NEWNS / NEWUTS /
//     NEWIPC / NEWUSER / NEWPID / NEWNET / NEWCGROUP bit — i.e. clone() is
//     allowed to make a thread, not a namespace.
//   - NOT filtered: clone3(2) (NR 435). clone3's flags live inside a
//     `struct clone_args` passed BY POINTER, which classic BPF cannot
//     dereference (it only sees raw register values), so per-flag filtering
//     of clone3 is not possible with this mechanism. Modern glibc
//     (>= 2.34) tries clone3 first for pthread_create and falls back to
//     legacy clone() only on ENOSYS — returning EPERM from clone3 would
//     make glibc treat it as a hard error rather than falling back, which
//     would break ordinary Node threading. We therefore leave clone3
//     unfiltered rather than risk that regression. This is a known, honest
//     gap versus a hypothetical namespace-via-clone3 escape; unshare(2) and
//     setns(2) — the primary unprivileged namespace-creation/join syscalls —
//     are unconditionally denied above, which covers the common case this
//     gap calls out.
//   - Unmatched syscalls (the default branch) are ALLOWED. This is a
//     defense-in-depth layer alongside the existing path confinement
//     (confinePath), env allowlisting (allowedEnvVars), and credential
//     handshake scrubbing already in SandboxManager/ProcessSandbox — not a
//     full container replacement.
//   - Fail CLOSED: if installing no_new_privs or the seccomp filter fails
//     for any reason (unsupported kernel, disabled CONFIG_SECCOMP, etc.),
//     this binary exits nonzero WITHOUT exec'ing the target. It never
//     silently falls through to an unconfined exec.

use std::env;
use std::process::exit;

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::os::raw::c_int;

    // linux/audit.h — AUDIT_ARCH_X86_64 = EM_X86_64(62) | __AUDIT_ARCH_64BIT
    // (0x80000000) | __AUDIT_ARCH_LE (0x40000000).
    // AUDIT_ARCH_AARCH64 = EM_AARCH64(183) | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE.
    // The filter's first instruction KILLs the process on any other arch, so
    // this constant MUST match the architecture the binary is compiled for.
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("chariot-seccomp-wrapper supports linux x86_64 and aarch64 only");

    // offsetof(struct seccomp_data, arch) and offsetof(..., nr): nr is the
    // first __u32 (offset 0), arch is the second __u32 (offset 4).
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    // offsetof(struct seccomp_data, args[0]): __u32 nr; __u32 arch;
    // __u64 instruction_pointer; __u64 args[6]; — args[0] starts at byte 16
    // once the struct is naturally aligned to 8 bytes. Low 32 bits of a
    // little-endian u64 are at that same offset.
    const SECCOMP_DATA_ARGS0_LOW_OFFSET: u32 = 16;

    // x86_64 syscall numbers (asm/unistd_64.h). Verified against
    // /usr/include/x86_64-linux-gnu/asm/unistd_64.h on the build host.
    #[cfg(target_arch = "x86_64")]
    mod nr {
        pub const SYS_CLONE: u32 = 56;
        pub const SYS_PTRACE: u32 = 101;
        pub const SYS_PIVOT_ROOT: u32 = 155;
        pub const SYS_CHROOT: u32 = 161;
        pub const SYS_ACCT: u32 = 163;
        pub const SYS_MOUNT: u32 = 165;
        pub const SYS_UMOUNT2: u32 = 166;
        pub const SYS_SWAPON: u32 = 167;
        pub const SYS_SWAPOFF: u32 = 168;
        pub const SYS_REBOOT: u32 = 169;
        pub const SYS_INIT_MODULE: u32 = 175;
        pub const SYS_DELETE_MODULE: u32 = 176;
        pub const SYS_QUOTACTL: u32 = 179;
        pub const SYS_LOOKUP_DCOOKIE: u32 = 212;
        pub const SYS_KEXEC_LOAD: u32 = 246;
        pub const SYS_ADD_KEY: u32 = 248;
        pub const SYS_REQUEST_KEY: u32 = 249;
        pub const SYS_KEYCTL: u32 = 250;
        pub const SYS_UNSHARE: u32 = 272;
        pub const SYS_PERF_EVENT_OPEN: u32 = 298;
        pub const SYS_NAME_TO_HANDLE_AT: u32 = 303;
        pub const SYS_OPEN_BY_HANDLE_AT: u32 = 304;
        pub const SYS_SETNS: u32 = 308;
        pub const SYS_PROCESS_VM_READV: u32 = 310;
        pub const SYS_PROCESS_VM_WRITEV: u32 = 311;
        pub const SYS_FINIT_MODULE: u32 = 313;
        pub const SYS_KEXEC_FILE_LOAD: u32 = 320;
        pub const SYS_BPF: u32 = 321;
    }

    // aarch64 uses the asm-generic syscall table, whose numbers differ from
    // x86_64 (e.g. clone = 220, ptrace = 117). Take them from the libc crate's
    // aarch64 table (libc 0.2.186, gnu/b64/aarch64/mod.rs defines every name
    // below) instead of hand-copying numbers.
    #[cfg(target_arch = "aarch64")]
    mod nr {
        pub const SYS_CLONE: u32 = libc::SYS_clone as u32;
        pub const SYS_PTRACE: u32 = libc::SYS_ptrace as u32;
        pub const SYS_PIVOT_ROOT: u32 = libc::SYS_pivot_root as u32;
        pub const SYS_CHROOT: u32 = libc::SYS_chroot as u32;
        pub const SYS_ACCT: u32 = libc::SYS_acct as u32;
        pub const SYS_MOUNT: u32 = libc::SYS_mount as u32;
        pub const SYS_UMOUNT2: u32 = libc::SYS_umount2 as u32;
        pub const SYS_SWAPON: u32 = libc::SYS_swapon as u32;
        pub const SYS_SWAPOFF: u32 = libc::SYS_swapoff as u32;
        pub const SYS_REBOOT: u32 = libc::SYS_reboot as u32;
        pub const SYS_INIT_MODULE: u32 = libc::SYS_init_module as u32;
        pub const SYS_DELETE_MODULE: u32 = libc::SYS_delete_module as u32;
        pub const SYS_QUOTACTL: u32 = libc::SYS_quotactl as u32;
        pub const SYS_LOOKUP_DCOOKIE: u32 = libc::SYS_lookup_dcookie as u32;
        pub const SYS_KEXEC_LOAD: u32 = libc::SYS_kexec_load as u32;
        pub const SYS_ADD_KEY: u32 = libc::SYS_add_key as u32;
        pub const SYS_REQUEST_KEY: u32 = libc::SYS_request_key as u32;
        pub const SYS_KEYCTL: u32 = libc::SYS_keyctl as u32;
        pub const SYS_UNSHARE: u32 = libc::SYS_unshare as u32;
        pub const SYS_PERF_EVENT_OPEN: u32 = libc::SYS_perf_event_open as u32;
        pub const SYS_NAME_TO_HANDLE_AT: u32 = libc::SYS_name_to_handle_at as u32;
        pub const SYS_OPEN_BY_HANDLE_AT: u32 = libc::SYS_open_by_handle_at as u32;
        pub const SYS_SETNS: u32 = libc::SYS_setns as u32;
        pub const SYS_PROCESS_VM_READV: u32 = libc::SYS_process_vm_readv as u32;
        pub const SYS_PROCESS_VM_WRITEV: u32 = libc::SYS_process_vm_writev as u32;
        pub const SYS_FINIT_MODULE: u32 = libc::SYS_finit_module as u32;
        pub const SYS_KEXEC_FILE_LOAD: u32 = libc::SYS_kexec_file_load as u32;
        pub const SYS_BPF: u32 = libc::SYS_bpf as u32;
    }

    use nr::*;

    // Unconditional deny list: NR-only comparison, no argument inspection
    // needed. Every one of these is either a namespace/mount primitive, a
    // debugging/cross-process-memory primitive, or a system-tampering
    // syscall that a sandboxed adapter child has no legitimate reason to
    // call.
    const DENY_LIST: &[u32] = &[
        SYS_PTRACE,
        SYS_PIVOT_ROOT,
        SYS_CHROOT,
        SYS_ACCT,
        SYS_MOUNT,
        SYS_UMOUNT2,
        SYS_SWAPON,
        SYS_SWAPOFF,
        SYS_REBOOT,
        SYS_INIT_MODULE,
        SYS_DELETE_MODULE,
        SYS_QUOTACTL,
        SYS_LOOKUP_DCOOKIE,
        SYS_KEXEC_LOAD,
        SYS_ADD_KEY,
        SYS_REQUEST_KEY,
        SYS_KEYCTL,
        SYS_UNSHARE,
        SYS_PERF_EVENT_OPEN,
        SYS_NAME_TO_HANDLE_AT,
        SYS_OPEN_BY_HANDLE_AT,
        SYS_SETNS,
        SYS_PROCESS_VM_READV,
        SYS_PROCESS_VM_WRITEV,
        SYS_FINIT_MODULE,
        SYS_KEXEC_FILE_LOAD,
        SYS_BPF,
    ];

    // linux/sched.h CLONE_NEW* namespace flags. clone(2) is only denied when
    // one of these bits is set in the flags argument (arg0).
    const CLONE_NEWNS: u32 = 0x0002_0000;
    const CLONE_NEWCGROUP: u32 = 0x0200_0000;
    const CLONE_NEWUTS: u32 = 0x0400_0000;
    const CLONE_NEWIPC: u32 = 0x0800_0000;
    const CLONE_NEWUSER: u32 = 0x1000_0000;
    const CLONE_NEWPID: u32 = 0x2000_0000;
    const CLONE_NEWNET: u32 = 0x4000_0000;
    const CLONE_NEW_NAMESPACE_MASK: u32 = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET;

    // BPF opcodes (linux/bpf_common.h / linux/filter.h) used to hand-build
    // the classic-BPF (cBPF) seccomp program. Kept minimal and explicit
    // rather than pulling in a seccomp-compiler crate, to keep this binary's
    // dependency surface (and therefore its own attack surface / audit
    // burden) as small as possible: `libc` only.
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;
    const BPF_ALU: u16 = 0x04;
    const BPF_AND: u16 = 0x50;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// Build the cBPF program. Layout:
    ///   0: load arch
    ///   1: if arch != the compiled-for arch (x86_64 or aarch64) -> KILL_PROCESS; else fall through
    ///   2: RET KILL_PROCESS            (unreachable unless arch mismatches)
    ///   3: load nr
    ///   4..: for each DENY_LIST entry: [JEQ nr,0,1][RET ERRNO]  (2 instrs)
    ///   next: clone-flags block:
    ///     [JEQ SYS_CLONE,0,4]
    ///     [LD args[0] low32]
    ///     [AND CLONE_NEW_NAMESPACE_MASK]
    ///     [JEQ 0,1,0]
    ///     [RET ERRNO]
    ///   last: RET ALLOW                (default: allow everything else)
    fn build_program() -> Vec<libc::sock_filter> {
        let mut prog = Vec::with_capacity(8 + DENY_LIST.len() * 2 + 6);

        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH_OFFSET));
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

        prog.push(stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET));

        for &nr in DENY_LIST {
            // Equal -> fall through (jt=0) into the RET ERRNO right below.
            // Not equal -> skip that RET (jf=1) and move to the next check.
            prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
            prog.push(stmt(
                BPF_RET | BPF_K,
                SECCOMP_RET_ERRNO | (libc::EPERM as u32),
            ));
        }

        // Conditional clone() flags check. If nr != SYS_CLONE, skip the
        // whole 4-instruction block (LD, AND, JEQ, RET) and land on the
        // final RET ALLOW.
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_CLONE, 0, 4));
        prog.push(stmt(
            BPF_LD | BPF_W | BPF_ABS,
            SECCOMP_DATA_ARGS0_LOW_OFFSET,
        ));
        prog.push(stmt(BPF_ALU | BPF_AND | BPF_K, CLONE_NEW_NAMESPACE_MASK));
        // masked == 0 (no namespace bits set) -> jt=1, skip the RET ERRNO,
        // land on RET ALLOW. masked != 0 -> jf=0, fall through to RET ERRNO.
        prog.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
        prog.push(stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));

        prog.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

        prog
    }

    /// Install no_new_privs + the seccomp-bpf filter. Returns Err with a
    /// human-readable reason on any failure; the caller must NOT exec the
    /// target process if this fails (fail closed).
    pub fn install_confinement() -> Result<(), String> {
        // Required for an unprivileged process to install a seccomp filter
        // (or the kernel refuses PR_SET_SECCOMP with EACCES).
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }

        let program = build_program();
        let fprog = libc::sock_fprog {
            len: program.len() as libc::c_ushort,
            filter: program.as_ptr() as *mut libc::sock_filter,
        };

        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER as c_int,
                &fprog as *const libc::sock_fprog,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(format!(
                "prctl(PR_SET_SECCOMP) failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(())
    }

    /// execve() into `argv[0]` with `argv` and the inherited environment.
    /// Only returns on failure (execve never returns on success).
    pub fn exec_target(argv: &[String]) -> String {
        let cprogram = match CString::new(argv[0].as_bytes()) {
            Ok(c) => c,
            Err(e) => return format!("target path contains a NUL byte: {e}"),
        };
        let cargs: Vec<CString> = argv
            .iter()
            .map(|a| CString::new(a.as_bytes()).unwrap_or_default())
            .collect();
        let mut argv_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|a| a.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        unsafe {
            libc::execvp(cprogram.as_ptr(), argv_ptrs.as_ptr());
        }
        format!("execvp failed: errno={}", std::io::Error::last_os_error())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("chariot-seccomp-wrapper: usage: chariot-seccomp-wrapper <program> [args...]");
        exit(64);
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "chariot-seccomp-wrapper: this binary is Linux-only and must never be invoked on \
             this platform; refusing to run unconfined (fail closed)."
        );
        exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(reason) = linux::install_confinement() {
            eprintln!(
                "chariot-seccomp-wrapper: FAILED to install seccomp confinement: {reason}. \
                 Refusing to exec the target (fail closed) — an adapter child is NEVER run \
                 unconfined once this wrapper has been selected."
            );
            exit(1);
        }

        let target_argv = &args[1..];
        let err = linux::exec_target(target_argv);
        eprintln!("chariot-seccomp-wrapper: {err}");
        exit(126);
    }
}
