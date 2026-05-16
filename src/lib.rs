pub mod auth;
pub mod autotype;
pub mod config;
pub mod crypto;
pub mod generator;
pub mod gui;
pub mod hibp;
pub mod ipc;
pub mod native_host;
pub mod portable;
pub mod qr;
pub mod session;
pub mod storage;
pub mod typing;
pub mod vault;

#[cfg(unix)]
pub fn harden_process() {
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }

    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

#[cfg(not(unix))]
pub fn harden_process() {}
