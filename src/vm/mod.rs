use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub struct VmConfig<'a> {
    pub id: &'a str,
    pub jailer_path: &'a Path,
    pub firecracker_path: &'a Path,
    pub uid: u32,
    pub gid: u32,
    pub chroot_base: &'a Path,
}

pub struct JailedVm {
    pub id: String,
    pub chroot_root: PathBuf,
    pub socket_path: PathBuf,
    sudo_child: Child,
    firecracker_pid: u32,
}

#[derive(Debug)]
pub enum VmError {
    Io(std::io::Error),
    Http { status: u16, body: String },
    Timeout(&'static str),
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::Io(e)
    }
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::Io(e) => write!(f, "io error: {e}"),
            VmError::Http { status, body } => write!(f, "http error {status}: {body}"),
            VmError::Timeout(what) => write!(f, "timed out waiting for {what}"),
        }
    }
}
impl std::error::Error for VmError {}

/// Spawns firecracker under jailer (via sudo). Jailer does privileged chroot/cgroup/netns
/// setup then drops to `uid`/`gid` and execs firecracker, which never runs as root.
/// Requires an interactive sudo ticket (or a live terminal to prompt for one) --
/// this must run somewhere sudo can actually ask for a password.
pub fn spawn_jailed_firecracker(cfg: &VmConfig) -> Result<JailedVm, VmError> {
    let chroot_root = cfg.chroot_base.join("firecracker").join(cfg.id).join("root");

    let sudo_child = Command::new("sudo")
        .arg(cfg.jailer_path)
        .arg("--id")
        .arg(cfg.id)
        .arg("--exec-file")
        .arg(cfg.firecracker_path)
        .arg("--uid")
        .arg(cfg.uid.to_string())
        .arg("--gid")
        .arg(cfg.gid.to_string())
        .arg("--chroot-base-dir")
        .arg(cfg.chroot_base)
        .arg("--")
        .arg("--api-sock")
        .arg("/run/firecracker.socket")
        .spawn()?;

    let socket_path = chroot_root.join("run/firecracker.socket");
    let pid_path = chroot_root.join("firecracker.pid");

    wait_for_path(&pid_path, Duration::from_secs(5), "firecracker.pid")?;
    let firecracker_pid: u32 = std::fs::read_to_string(&pid_path)?
        .trim()
        .parse()
        .map_err(|_| VmError::Timeout("valid firecracker pid"))?;

    wait_for_path(&socket_path, Duration::from_secs(5), "API socket")?;

    Ok(JailedVm {
        id: cfg.id.to_string(),
        chroot_root,
        socket_path,
        sudo_child,
        firecracker_pid,
    })
}

fn wait_for_path(path: &Path, timeout: Duration, what: &'static str) -> Result<(), VmError> {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() > timeout {
            return Err(VmError::Timeout(what));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn wait_for_exit(pid: u32, timeout: Duration) -> Result<(), VmError> {
    let start = Instant::now();
    loop {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(VmError::Timeout("process exit"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Hand-rolled HTTP/1.1 request over a Unix domain socket. Deliberately not
/// hyper/reqwest: traffic here is one request at a time to a single well-behaved
/// local server, so raw status-line + Content-Length framing is small and bounded.
///
/// Firecracker's API server is keep-alive and its epoll loop treats a half-close
/// (`shutdown(Write)`) as an abort -- it resets the connection instead of finishing
/// the response. So: never shut down our write side, and read exactly
/// `Content-Length` bytes of body rather than reading to EOF.
fn http_request(socket: &Path, method: &str, path: &str, body: &Value) -> Result<(u16, Value), VmError> {
    let body_str = if body.is_null() { String::new() } else { body.to_string() };
    let mut stream = UnixStream::connect(socket)?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
        method = method,
        path = path,
        len = body_str.len(),
        body = body_str,
    );
    stream.write_all(request.as_bytes())?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(VmError::Timeout("HTTP response headers"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let status_line = header_text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let content_length: usize = header_text
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body_end = (body_start + content_length).min(buf.len());
    let resp_body = &buf[body_start..body_end];
    let json_body: Value = if resp_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(resp_body).unwrap_or(Value::Null)
    };
    Ok((status, json_body))
}

fn put_json(socket: &Path, path: &str, body: Value) -> Result<(), VmError> {
    let (status, resp) = http_request(socket, "PUT", path, &body)?;
    if status / 100 != 2 {
        return Err(VmError::Http { status, body: resp.to_string() });
    }
    Ok(())
}

fn patch_json(socket: &Path, path: &str, body: Value) -> Result<(), VmError> {
    let (status, resp) = http_request(socket, "PATCH", path, &body)?;
    if status / 100 != 2 {
        return Err(VmError::Http { status, body: resp.to_string() });
    }
    Ok(())
}

impl JailedVm {
    pub fn configure_machine(&self, vcpu_count: u32, mem_size_mib: u32) -> Result<(), VmError> {
        put_json(
            &self.socket_path,
            "/machine-config",
            json!({ "vcpu_count": vcpu_count, "mem_size_mib": mem_size_mib }),
        )
    }

    /// `kernel_path` is a path *inside the chroot* (e.g. "/vmlinux") -- copy the file
    /// into `self.chroot_root` before calling this.
    pub fn configure_boot_source(&self, kernel_path: &str) -> Result<(), VmError> {
        put_json(
            &self.socket_path,
            "/boot-source",
            json!({
                "kernel_image_path": kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
            }),
        )
    }

    /// `rootfs_path` is a path *inside the chroot* (e.g. "/rootfs.ext4").
    pub fn configure_rootfs(&self, rootfs_path: &str) -> Result<(), VmError> {
        put_json(
            &self.socket_path,
            "/drives/rootfs",
            json!({
                "drive_id": "rootfs",
                "path_on_host": rootfs_path,
                "is_root_device": true,
                "is_read_only": false,
            }),
        )
    }

    pub fn start(&self) -> Result<(), VmError> {
        put_json(&self.socket_path, "/actions", json!({ "action_type": "InstanceStart" }))
    }

    pub fn state(&self) -> Result<Value, VmError> {
        let (status, body) = http_request(&self.socket_path, "GET", "/", &Value::Null)?;
        if status / 100 != 2 {
            return Err(VmError::Http { status, body: body.to_string() });
        }
        Ok(body)
    }

    pub fn pause(&self) -> Result<(), VmError> {
        patch_json(&self.socket_path, "/vm", json!({ "state": "Paused" }))
    }

    pub fn resume(&self) -> Result<(), VmError> {
        patch_json(&self.socket_path, "/vm", json!({ "state": "Resumed" }))
    }

    /// Snapshot paths are inside *this* VM's chroot. This is a naive `Full`
    /// snapshot -- a flat dump of every guest memory page. That cost is exactly
    /// what a future userfaultfd-based restore is meant to remove.
    pub fn snapshot_create(&self, snapshot_path: &str, mem_file_path: &str) -> Result<(), VmError> {
        put_json(
            &self.socket_path,
            "/snapshot/create",
            json!({
                "snapshot_type": "Full",
                "snapshot_path": snapshot_path,
                "mem_file_path": mem_file_path,
            }),
        )
    }

    /// Must be called before machine-config/boot-source/drives on a *fresh* instance.
    pub fn snapshot_load(&self, snapshot_path: &str, mem_backend_path: &str) -> Result<(), VmError> {
        put_json(
            &self.socket_path,
            "/snapshot/load",
            json!({
                "snapshot_path": snapshot_path,
                "mem_backend": { "backend_path": mem_backend_path, "backend_type": "File" },
                "resume_vm": false,
            }),
        )
    }

    /// Kills the firecracker process directly -- no sudo needed, it runs as our own
    /// uid/gid once jailer drops privileges.
    fn kill(&mut self) -> Result<(), VmError> {
        let _ = Command::new("kill").arg("-9").arg(self.firecracker_pid.to_string()).status();
        wait_for_exit(self.firecracker_pid, Duration::from_secs(5))
    }

    /// Graceful shutdown: SendCtrlAltDel, wait, fall back to kill -9. Then removes the
    /// chroot instance dir (needs sudo -- its parent is root-owned).
    pub fn shutdown(mut self) -> Result<(), VmError> {
        let graceful = put_json(&self.socket_path, "/actions", json!({ "action_type": "SendCtrlAltDel" }));
        let exited = graceful.is_ok() && wait_for_exit(self.firecracker_pid, Duration::from_secs(3)).is_ok();
        if !exited {
            self.kill()?;
        }
        let instance_dir = self.chroot_root.parent().unwrap_or(&self.chroot_root).to_path_buf();
        let _ = Command::new("sudo").arg("rm").arg("-rf").arg(&instance_dir).status();
        let _ = self.sudo_child.wait();
        Ok(())
    }
}
