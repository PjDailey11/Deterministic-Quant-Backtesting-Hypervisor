use SandboxedAIExecutionRuntime::telemetry::Timer;
use SandboxedAIExecutionRuntime::vm::{self, JailedVm, VmConfig};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const VCPU_COUNT: u32 = 1;
const MEM_SIZE_MIB: u32 = 256;

fn main() {
    demo();
}

/// End-to-end check: cold boot a jailed VM, snapshot it, then restore that
/// snapshot two ways -- Firecracker's naive File-backend (synchronous full
/// memory copy) and our on-demand Uffd-backend handler -- and compare the
/// `snapshot/load` latency each incurs.
fn demo() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let assets = project_root.join("vm-assets");
    let kernel_host = assets.join("vmlinux");
    let rootfs_host = assets.join("rootfs.ext4");

    // ponytail: hardcoded to this dev machine's uid/gid/binary locations,
    // add real lookup (nix::unistd, `which`) if this ever runs elsewhere.
    let cfg = |id: &'static str| VmConfig {
        id,
        jailer_path: Path::new("/home/pj/.local/bin/jailer"),
        firecracker_path: Path::new("/home/pj/.local/bin/firecracker"),
        uid: 1000,
        gid: 1000,
        chroot_base: Path::new("/srv/jailer"),
    };

    println!("== [1] cold boot ==");
    let vmi = vm::spawn_jailed_firecracker(&cfg("backtest-demo")).expect("spawn failed");
    std::fs::copy(&kernel_host, vmi.chroot_root.join("vmlinux")).expect("copy kernel");
    std::fs::copy(&rootfs_host, vmi.chroot_root.join("rootfs.ext4")).expect("copy rootfs");
    vmi.configure_machine(VCPU_COUNT, MEM_SIZE_MIB).expect("machine-config");
    vmi.configure_boot_source("/vmlinux").expect("boot-source");
    vmi.configure_rootfs("/rootfs.ext4").expect("drives/rootfs");

    let cold_boot_timer = Timer::start("cold boot");
    vmi.start().expect("InstanceStart");
    wait_until_running(&vmi);
    let cold_boot_latency = cold_boot_timer.stop();
    println!("state after boot: {:?}", vmi.state().unwrap());

    println!("== [2] naive full-memory snapshot ==");
    vmi.pause().expect("pause");
    std::fs::create_dir_all(vmi.chroot_root.join("snap")).expect("mkdir snap");
    vmi.snapshot_create("/snap/state.snap", "/snap/mem.snap")
        .expect("snapshot create");

    // Copy the snapshot out of the original chroot *before* shutdown, which
    // rm -rf's the whole instance dir (snapshot files included).
    let snap_scratch = assets.join("snap-scratch");
    std::fs::create_dir_all(&snap_scratch).expect("mkdir snap-scratch");
    let snap_state_src = snap_scratch.join("state.snap");
    let snap_mem_src = snap_scratch.join("mem.snap");
    std::fs::copy(vmi.chroot_root.join("snap/state.snap"), &snap_state_src)
        .expect("copy snapshot state out of chroot");
    std::fs::copy(vmi.chroot_root.join("snap/mem.snap"), &snap_mem_src)
        .expect("copy snapshot mem out of chroot");

    println!("== killing original instance ==");
    vmi.shutdown().expect("shutdown original");

    println!("== [3] naive restore (File backend, synchronous full copy) ==");
    let naive = vm::spawn_jailed_firecracker(&cfg("backtest-demo-restore")).expect("spawn restore");
    std::fs::create_dir_all(naive.chroot_root.join("snap")).expect("mkdir snap (naive restore)");
    std::fs::copy(&snap_state_src, naive.chroot_root.join("snap/state.snap")).expect("copy snapshot state");
    std::fs::copy(&snap_mem_src, naive.chroot_root.join("snap/mem.snap")).expect("copy snapshot mem");
    // The snapshot references its block device by the path it was opened at
    // ("/rootfs.ext4") -- that backing file must exist at the same path in the
    // new chroot before snapshot/load can reopen it.
    std::fs::copy(&rootfs_host, naive.chroot_root.join("rootfs.ext4")).expect("copy rootfs (naive restore)");

    let naive_load_timer = Timer::start("naive snapshot_load (File backend)");
    naive
        .snapshot_load("/snap/state.snap", "/snap/mem.snap")
        .expect("snapshot load");
    let naive_load_latency = naive_load_timer.stop();
    naive.resume().expect("resume");
    wait_until_running(&naive);
    println!("naive restore responsive, state: {:?}", naive.state().unwrap());
    naive.shutdown().expect("shutdown naive restore");

    println!("== [4] uffd restore (on-demand paging, lazy copy) ==");
    let uffd_vm = vm::spawn_jailed_firecracker(&cfg("backtest-demo-uffd")).expect("spawn uffd restore");
    std::fs::create_dir_all(uffd_vm.chroot_root.join("snap")).expect("mkdir snap (uffd restore)");
    std::fs::copy(&snap_state_src, uffd_vm.chroot_root.join("snap/state.snap")).expect("copy snapshot state");
    std::fs::copy(&rootfs_host, uffd_vm.chroot_root.join("rootfs.ext4")).expect("copy rootfs (uffd restore)");
    // mem.snap is served on demand straight from snap_mem_src by our handler
    // thread, which runs outside the jail -- no copy into the chroot needed.

    let uffd_load_timer = Timer::start("uffd snapshot_load (on-demand)");
    uffd_vm
        .snapshot_load_uffd("/snap/state.snap", "/uffd.sock", &snap_mem_src)
        .expect("snapshot load (uffd)");
    let uffd_load_latency = uffd_load_timer.stop();
    uffd_vm.resume().expect("resume");
    wait_until_running(&uffd_vm);
    println!("uffd restore responsive, state: {:?}", uffd_vm.state().unwrap());

    println!(
        "\ncold boot:           {:.2}ms\nnaive snapshot_load: {:.2}ms\nuffd snapshot_load:  {:.2}ms  ({:.1}x faster than naive)\n",
        cold_boot_latency.as_secs_f64() * 1000.0,
        naive_load_latency.as_secs_f64() * 1000.0,
        uffd_load_latency.as_secs_f64() * 1000.0,
        naive_load_latency.as_secs_f64() / uffd_load_latency.as_secs_f64().max(0.0001),
    );

    println!("== tearing down ==");
    uffd_vm.shutdown().expect("shutdown uffd restore");
    let _ = std::fs::remove_dir_all(&snap_scratch);

    for id in ["backtest-demo", "backtest-demo-restore", "backtest-demo-uffd"] {
        assert!(
            !Path::new("/srv/jailer/firecracker").join(id).exists(),
            "chroot dir for {id} should be gone"
        );
    }
    println!("== demo complete, no orphaned instances ==");
}

fn wait_until_running(vmi: &JailedVm) {
    let start = Instant::now();
    loop {
        if let Ok(state) = vmi.state() {
            if state.get("state").and_then(|s| s.as_str()) == Some("Running") {
                return;
            }
        }
        if start.elapsed() > Duration::from_secs(10) {
            panic!("VM did not reach Running state in time");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
