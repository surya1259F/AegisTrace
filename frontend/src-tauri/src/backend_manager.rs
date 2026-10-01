use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    pub port: u16,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub is_running: bool,
    pub is_packaged: bool,
    pub port: u16,
    pub has_crashed: bool,
}

pub struct BackendProcess {
    pub child: Child,
    pub pid: u32,
    pub start_time: Option<u64>,
    pub port: u16,
    pub bootstrap_secret: String,
    pub is_running: bool,
    pub shutdown_requested: bool,
    pub has_crashed: bool,
    pub is_packaged: bool,
}

pub struct BackendManager {
    state: RwLock<Option<BackendProcess>>,
}

impl BackendManager {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(None),
        }
    }

    /// Generates a cryptographically secure 256-bit (32-byte) hex bootstrap secret.
    pub fn generate_bootstrap_secret() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Allocates an ephemeral TCP port on 127.0.0.1.
    pub fn get_available_port() -> Result<u16, String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to bind loopback socket: {}", e))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to resolve local address: {}", e))?
            .port();
        drop(listener);
        Ok(port)
    }

    /// Resolves process start identity on Linux via /proc/<pid>/stat field 22.
    #[cfg(target_os = "linux")]
    pub fn get_process_start_time(pid: u32) -> Option<u64> {
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = fs::read_to_string(stat_path) {
            if let Some(r_idx) = content.rfind(')') {
                let after_comm = &content[r_idx + 1..];
                let parts: Vec<&str> = after_comm.split_whitespace().collect();
                if parts.len() >= 20 {
                    if let Ok(starttime) = parts[19].parse::<u64>() {
                        return Some(starttime);
                    }
                }
            }
        }
        None
    }

    /// Resolves process start identity on Windows via GetProcessTimes API.
    #[cfg(target_os = "windows")]
    pub fn get_process_start_time(pid: u32) -> Option<u64> {
        #[repr(C)]
        struct FILETIME {
            dwLowDateTime: u32,
            dwHighDateTime: u32,
        }
        extern "system" {
            fn OpenProcess(
                dwDesiredAccess: u32,
                bInheritHandle: i32,
                dwProcessId: u32,
            ) -> *mut std::ffi::c_void;
            fn GetProcessTimes(
                hProcess: *mut std::ffi::c_void,
                lpCreationTime: *mut FILETIME,
                lpExitTime: *mut FILETIME,
                lpKernelTime: *mut FILETIME,
                lpUserTime: *mut FILETIME,
            ) -> i32;
            fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        }

        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut creation_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut exit_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut kernel_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let mut user_time = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let res = GetProcessTimes(
                handle,
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            );
            CloseHandle(handle);
            if res != 0 {
                let time_64 = ((creation_time.dwHighDateTime as u64) << 32)
                    | (creation_time.dwLowDateTime as u64);
                return Some(time_64);
            }
        }
        None
    }

    /// Resolves process start identity on macOS via libproc / proc_pidinfo.
    #[cfg(target_os = "macos")]
    pub fn get_process_start_time(pid: u32) -> Option<u64> {
        #[repr(C)]
        struct ProcBsdInfo {
            pbi_flags: u32,
            pbi_status: u32,
            pbi_xstatus: u32,
            pbi_pid: u32,
            pbi_ppid: u32,
            pbi_uid: u32,
            pbi_gid: u32,
            pbi_ruid: u32,
            pbi_rgid: u32,
            pbi_svuid: u32,
            pbi_svgid: u32,
            pbi_rfu1: u32,
            pbi_comm: [u8; 16],
            pbi_name: [u8; 32],
            pbi_nfiles: u32,
            pbi_pgid: u32,
            pbi_jobc: u32,
            pbi_euid: u32,
            pbi_egid: u32,
            pbi_svuid2: u32,
            pbi_svgid2: u32,
            pbi_start_tvsec: u64,
            pbi_start_tvusec: u64,
        }
        extern "C" {
            fn proc_pidinfo(
                pid: i32,
                flavor: i32,
                arg: u64,
                buffer: *mut ProcBsdInfo,
                buffersize: i32,
            ) -> i32;
        }
        const PROC_PIDTBSDINFO: i32 = 1;
        let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<ProcBsdInfo>() as i32;
        let res = unsafe { proc_pidinfo(pid as i32, PROC_PIDTBSDINFO, 0, &mut info, size) };
        if res == size {
            return Some(info.pbi_start_tvsec);
        }
        None
    }

    /// Fallback for other platform targets where OS process start time API is unavailable.
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    pub fn get_process_start_time(_pid: u32) -> Option<u64> {
        None
    }

    /// Resolves an external writable per-user application data directory for packaged backend execution.
    pub fn resolve_user_data_dir() -> PathBuf {
        if let Ok(data_dir) = std::env::var("ADFIR_DATA_DIR") {
            if !data_dir.trim().is_empty() {
                return PathBuf::from(data_dir);
            }
        }
        if cfg!(windows) {
            if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                return PathBuf::from(local_app_data).join("adfir");
            }
            if let Ok(user_profile) = std::env::var("USERPROFILE") {
                return PathBuf::from(user_profile)
                    .join("AppData")
                    .join("Local")
                    .join("adfir");
            }
        } else if cfg!(target_os = "macos") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("adfir");
            }
        } else {
            if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
                return PathBuf::from(xdg_data).join("adfir");
            }
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("adfir");
            }
        }
        PathBuf::from(".adfir_data")
    }

    /// Resolves PyInstaller executable location with Tauri app resource directory fallback.
    pub fn resolve_backend_executable() -> Option<PathBuf> {
        let exe_name = if cfg!(windows) {
            "adfir-backend.exe"
        } else {
            "adfir-backend"
        };

        // 1. Check relative build dist directory (development/build environment)
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_dist = manifest_dir
            .parent()
            .unwrap()
            .join("dist")
            .join("adfir-backend");
        let candidate1 = repo_dist.join(exe_name);
        if candidate1.exists() {
            return Some(candidate1);
        }

        // 2. Check current executable parent sidecar & resource locations (packaged app runtime)
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(parent) = current_exe.parent() {
                let candidates = [
                    parent.join(exe_name),
                    parent.join("adfir-backend").join(exe_name),
                    parent
                        .join("resources")
                        .join("adfir-backend")
                        .join(exe_name),
                    parent
                        .join("_up_")
                        .join("_up_")
                        .join("dist")
                        .join("adfir-backend")
                        .join(exe_name),
                    parent
                        .join("resources")
                        .join("_up_")
                        .join("_up_")
                        .join("dist")
                        .join("adfir-backend")
                        .join(exe_name),
                    parent
                        .join("resources")
                        .join("dist")
                        .join("adfir-backend")
                        .join(exe_name),
                ];
                for cand in candidates {
                    if cand.exists() {
                        return Some(cand);
                    }
                }
            }
        }

        None
    }

    /// Spawns backend process with port collision retry loop (mitigating TOCTOU races)
    /// and authenticated readiness polling.
    pub fn spawn_backend(&self) -> Result<BackendConfig, String> {
        let mut lock = self.state.write().map_err(|e| e.to_string())?;

        if let Some(ref proc) = *lock {
            if proc.is_running {
                return Ok(BackendConfig {
                    port: proc.port,
                    url: format!("http://127.0.0.1:{}/api", proc.port),
                });
            }
        }

        let exe_path = Self::resolve_backend_executable();

        if let Some(bin_path) = exe_path {
            // Production Packaged Execution with retry loop (max 5 attempts)
            const MAX_PORT_ATTEMPTS: usize = 5;
            let mut last_err = String::new();
            let user_data_dir = Self::resolve_user_data_dir();
            let _ = fs::create_dir_all(&user_data_dir);

            for attempt in 1..=MAX_PORT_ATTEMPTS {
                let port = match Self::get_available_port() {
                    Ok(p) => p,
                    Err(e) => {
                        last_err = format!("Attempt {}: {}", attempt, e);
                        continue;
                    }
                };

                let bootstrap_secret = Self::generate_bootstrap_secret();

                let mut cmd = Command::new(&bin_path);
                cmd.env("ADFIR_PORT", port.to_string());
                cmd.env("ADFIR_INTERNAL_SECRET", &bootstrap_secret);
                if std::env::var("ADFIR_DATA_DIR").is_err() {
                    cmd.env("ADFIR_DATA_DIR", &user_data_dir);
                }

                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        last_err = format!(
                            "Attempt {}: Failed to launch backend binary {}: {}",
                            attempt,
                            bin_path.display(),
                            e
                        );
                        continue;
                    }
                };

                let pid = child.id();
                let start_time = Self::get_process_start_time(pid);

                // Health / Authenticated Readiness Verification Loop
                let health_url = format!("http://127.0.0.1:{}/api/v1/system/health", port);
                let client = match reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        last_err = e.to_string();
                        continue;
                    }
                };

                let start = Instant::now();
                let mut ready = false;

                while start.elapsed() < Duration::from_secs(10) {
                    // Check if child exited early (e.g. port collision / failed bind)
                    if let Ok(Some(_status)) = child.try_wait() {
                        break;
                    }

                    let res = client
                        .get(&health_url)
                        .header("X-ADFIR-Bootstrap-Secret", &bootstrap_secret)
                        .send();

                    if let Ok(response) = res {
                        if response.status().is_success() {
                            ready = true;
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }

                if ready {
                    *lock = Some(BackendProcess {
                        child,
                        pid,
                        start_time,
                        port,
                        bootstrap_secret,
                        is_running: true,
                        shutdown_requested: false,
                        has_crashed: false,
                        is_packaged: true,
                    });

                    return Ok(BackendConfig {
                        port,
                        url: format!("http://127.0.0.1:{}/api", port),
                    });
                } else {
                    // Cleanup child if still running
                    if child.try_wait().ok().flatten().is_none() {
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                    last_err = format!(
                        "Packaged backend attempt {} failed readiness check on port {}",
                        attempt, port
                    );
                }
            }

            Err(format!(
                "Failed to launch backend after {} attempts. Last error: {}",
                MAX_PORT_ATTEMPTS, last_err
            ))
        } else {
            // Development Fallback Mode (Manually started uvicorn on port 8000)
            let dev_port = 8000;
            let health_url = format!("http://127.0.0.1:{}/api/v1/system/health", dev_port);
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .map_err(|e| e.to_string())?;

            let is_dev_online = client
                .get(&health_url)
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);

            if is_dev_online {
                Ok(BackendConfig {
                    port: dev_port,
                    url: format!("http://127.0.0.1:{}/api", dev_port),
                })
            } else {
                Err("No packaged backend binary found and no development backend is listening on http://127.0.0.1:8000".to_string())
            }
        }
    }

    /// Shuts down backend process cleanly with bootstrap authentication.
    pub fn shutdown_backend(&self) -> Result<(), String> {
        let mut lock = self.state.write().map_err(|e| e.to_string())?;

        if let Some(mut proc) = lock.take() {
            if proc.is_packaged && proc.is_running {
                proc.shutdown_requested = true;
                let shutdown_url = format!("http://127.0.0.1:{}/api/v1/system/shutdown", proc.port);
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .map_err(|e| e.to_string())?;

                let _ = client
                    .post(&shutdown_url)
                    .header("X-ADFIR-Bootstrap-Secret", &proc.bootstrap_secret)
                    .send();

                let start = Instant::now();
                let mut exited = false;

                while start.elapsed() < Duration::from_secs(3) {
                    if let Ok(Some(_)) = proc.child.try_wait() {
                        exited = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }

                if !exited {
                    // Process Identity Verification before Force Termination
                    let should_kill =
                        match (proc.start_time, Self::get_process_start_time(proc.pid)) {
                            (Some(expected), Some(actual)) => expected == actual,
                            (None, _) => proc.child.try_wait().ok().flatten().is_none(),
                            _ => false,
                        };

                    if should_kill {
                        let _ = proc.child.kill();
                        let _ = proc.child.wait();
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks status and detects unexpected backend crashes (including unexpected exit code 0).
    pub fn get_status(&self) -> BackendStatus {
        let mut lock = match self.state.write() {
            Ok(l) => l,
            Err(_) => {
                return BackendStatus {
                    is_running: false,
                    is_packaged: false,
                    port: 8000,
                    has_crashed: false,
                }
            }
        };

        if let Some(ref mut proc) = *lock {
            if proc.is_running {
                if let Ok(Some(_status)) = proc.child.try_wait() {
                    proc.is_running = false;
                    // Any unexpected process termination when shutdown was NOT requested is marked as a crash
                    if !proc.shutdown_requested {
                        proc.has_crashed = true;
                    }
                }
            }
            BackendStatus {
                is_running: proc.is_running,
                is_packaged: proc.is_packaged,
                port: proc.port,
                has_crashed: proc.has_crashed,
            }
        } else {
            BackendStatus {
                is_running: false,
                is_packaged: false,
                port: 8000,
                has_crashed: false,
            }
        }
    }
}
