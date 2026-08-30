//! On-demand page-fault handler for Firecracker's `Uffd` memory backend.
//!
//! Firecracker connects to a Unix socket we listen on and sends (over one
//! `sendmsg`, SCM_RIGHTS-style) a JSON description of each guest memory
//! region plus an open userfaultfd descriptor. Registration of those regions
//! against the uffd context happens on Firecracker's side before it hands us
//! the fd; we just read fault events off the (shared-context) fd and answer
//! each one with `UFFDIO_COPY` from a read-only mmap of the flat memory
//! snapshot file. Wire format mirrors Firecracker's own reference handler
//! (`src/firecracker/examples/uffd/`) since we have to match it exactly to
//! interoperate.

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::ptr;
use userfaultfd::{Event, Uffd};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GuestRegionUffdMapping {
    base_host_virt_addr: u64,
    size: usize,
    offset: u64,
    page_size: usize,
}

impl GuestRegionUffdMapping {
    fn contains(&self, addr: usize) -> bool {
        let base = self.base_host_virt_addr as usize;
        addr >= base && addr < base + self.size
    }
}

/// Binds the handshake socket and spawns a background thread that serves
/// page faults for the lifetime of the process. Must be called (and the
/// socket must exist) before Firecracker's `snapshot/load` call, since
/// Firecracker connects out to it during that call.
pub fn spawn_handler_thread(socket_path: PathBuf, mem_file_path: PathBuf) {
    let listener_ready = std::sync::Arc::new(std::sync::Barrier::new(2));
    let ready = listener_ready.clone();
    std::thread::spawn(move || run_handler(&socket_path, &mem_file_path, ready));
    listener_ready.wait();
}

fn run_handler(socket_path: &Path, mem_file_path: &Path, ready: std::sync::Arc<std::sync::Barrier>) {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("uffd: bind handshake socket");
    ready.wait();

    let file = File::open(mem_file_path).expect("uffd: open mem file");
    let file_len = file.metadata().expect("uffd: stat mem file").len() as usize;

    // SAFETY: `file` is a valid open fd for the duration of this mapping;
    // PROT_READ/MAP_PRIVATE means we never write through it.
    let backing = unsafe {
        libc::mmap(
            ptr::null_mut(),
            file_len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(backing, libc::MAP_FAILED, "uffd: mmap backing file failed");
    let backing = backing.cast::<u8>();

    let (stream, _) = listener.accept().expect("uffd: accept firecracker connection");
    let (mappings, uffd) = receive_handshake(&stream);
    let page_size = mappings.first().expect("uffd: handshake had no regions").page_size;

    loop {
        match uffd.read_event().expect("uffd: read_event") {
            Some(Event::Pagefault { addr, .. }) => {
                serve_fault(&uffd, &mappings, page_size, backing, addr);
            }
            // No balloon device in this demo, so `Remove` shouldn't occur;
            // ignore anything else rather than panicking on it.
            Some(_) => {}
            None => continue,
        }
    }
}

fn receive_handshake(stream: &UnixStream) -> (Vec<GuestRegionUffdMapping>, Uffd) {
    let mut buf = vec![0u8; 4096];
    let (n, fd_file) = stream.recv_with_fd(&mut buf).expect("uffd: recv handshake");
    buf.truncate(n);
    let body = String::from_utf8(buf).expect("uffd: handshake body not utf-8");
    let mappings: Vec<GuestRegionUffdMapping> =
        serde_json::from_str(&body).expect("uffd: bad handshake json");
    let fd_file = fd_file.expect("uffd: handshake carried no uffd fd");

    // SAFETY: fd_file is a valid fd Firecracker created via userfaultfd(2) and
    // transferred to us over SCM_RIGHTS; it already has the guest regions
    // registered on Firecracker's side.
    let uffd = unsafe { Uffd::from_raw_fd(fd_file.into_raw_fd()) };
    (mappings, uffd)
}

fn serve_fault(
    uffd: &Uffd,
    mappings: &[GuestRegionUffdMapping],
    page_size: usize,
    backing: *const u8,
    fault_addr: *mut c_void,
) {
    let page_addr = (fault_addr as usize) & !(page_size - 1);
    let region = mappings
        .iter()
        .find(|r| r.contains(page_addr))
        .unwrap_or_else(|| panic!("uffd: fault addr {page_addr:#x} not in any guest region"));

    let region_offset = page_addr - region.base_host_virt_addr as usize;
    // SAFETY: `backing` covers the whole mem file; region.offset + region_offset
    // is within it because it was derived from Firecracker's own region mapping.
    let src = unsafe { backing.add(region.offset as usize + region_offset) };
    let dst = page_addr as *mut c_void;

    // SAFETY: dst is the faulting page inside Firecracker's registered guest
    // memory region -- valid per the uffd contract for this fd.
    unsafe {
        match uffd.copy(src.cast(), dst, page_size, true) {
            Ok(n) => assert!(n > 0, "uffd: copy reported zero bytes"),
            // Can legitimately race with a concurrent fault on the same page.
            Err(userfaultfd::Error::CopyFailed(errno))
                if std::io::Error::from(errno).raw_os_error() == Some(libc::EEXIST) => {}
            Err(e) => panic!("uffd: copy failed: {e:?}"),
        }
    }
}
