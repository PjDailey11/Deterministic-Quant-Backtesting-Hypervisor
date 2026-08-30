use SandboxedAIExecutionRuntime::telemetry::Timer;
use SandboxedAIExecutionRuntime::vm::{self, JailedVm, VmConfig};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const VCPU_COUNT: u32 = 1;
const MEM_SIZE_MIB: u32 = 256;

fn main() {
    demo();
}

/// End-to-end check: cold boot a jailed VM, snapshot it, kill it, restore from the
/// snapshot into a fresh jailed VM, and log both latencies. This is milestones 1-6
/// of the Phase 1 plan chained together.
fn demo() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let assets = project_root.join("vm-assets");
    let kernel_host = assets.join("vmlinux");
    let rootfs_host = assets.join("rootfs.ext4");

    // ponytail: hardcoded to this dev machine's uid/gid/binary locations,
    // add real lookup (nix::unistd, `which`) if this ever runs elsewhere.
    let cfg = VmConfig {
        id: "backtest-demo",
        jailer_path: Path::new("/home/pj/.local/bin/jailer"),
        firecracker_path: Path::new("/home/pj/.local/bin/firecracker"),
        uid: 1000,
        gid: 1000,
        chroot_base: Path::new("/srv/jailer"),
    };

    println!("== spawning jailed firecracker ({}) ==", cfg.id);
    let vmi = vm::spawn_jailed_firecracker(&cfg).expect("spawn failed");

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

    // Naive snapshot/restore baseline -- correctness only, not optimized.
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

    println!("== killing original instance to simulate a real cold restore ==");
    vmi.shutdown().expect("shutdown original");

    let restore_cfg = VmConfig {
        id: "backtest-demo-restore",
        jailer_path: cfg.jailer_path,
        firecracker_path: cfg.firecracker_path,
        uid: cfg.uid,
        gid: cfg.gid,
        chroot_base: cfg.chroot_base,
    };
    let restored = vm::spawn_jailed_firecracker(&restore_cfg).expect("spawn restore");

    std::fs::create_dir_all(restored.chroot_root.join("snap")).expect("mkdir snap (restore)");
    std::fs::copy(&snap_state_src, restored.chroot_root.join("snap/state.snap"))
        .expect("copy snapshot state");
    std::fs::copy(&snap_mem_src, restored.chroot_root.join("snap/mem.snap"))
        .expect("copy snapshot mem");
    // The snapshot references its block device by the path it was opened at
    // ("/rootfs.ext4") -- that backing file must exist at the same path in the
    // new chroot before snapshot/load can reopen it.
    std::fs::copy(&rootfs_host, restored.chroot_root.join("rootfs.ext4"))
        .expect("copy rootfs (restore)");

    let restore_timer = Timer::start("snapshot restore");
    restored
        .snapshot_load("/snap/state.snap", "/snap/mem.snap")
        .expect("snapshot load");
    restored.resume().expect("resume");
    wait_until_running(&restored);
    let restore_latency = restore_timer.stop();

    println!(
        "cold boot: {:.2}ms | restore: {:.2}ms | restore is {:.1}x faster",
        cold_boot_latency.as_secs_f64() * 1000.0,
        restore_latency.as_secs_f64() * 1000.0,
        cold_boot_latency.as_secs_f64() / restore_latency.as_secs_f64().max(0.0001),
    );

    println!("== tearing down ==");
    restored.shutdown().expect("shutdown restored");

    assert!(
        !Path::new("/srv/jailer/firecracker/backtest-demo").exists(),
        "original chroot dir should be gone"
    );
    assert!(
        !Path::new("/srv/jailer/firecracker/backtest-demo-restore").exists(),
        "restored chroot dir should be gone"
    );
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
