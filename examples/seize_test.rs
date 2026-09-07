use std::{collections::HashMap, sync::Arc, time::Duration};

use async_debugger::Result;
use nix::{
    sys::{
        mman::{MapFlags, ProtFlags},
        ptrace,
    },
    unistd::Pid,
};
use tracing::level_filters::LevelFilter;

fn main() -> Result<()> {
    setup_logging();
    let (pid, addr) = get_prog_info();
    println!("Attaching to {pid} and watching {addr:x}");

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .name("my-runtime")
        .build()
        .unwrap()
        .block_on(async {
            let found_map = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
            let found = found_map.clone();

            println!("Quick setup happening");
            let (debugger, mut spawner, thread) =
                async_debugger::Debugger::quick_setup(pid).await?;
            println!("Performed quick_setup");
            let mut task = spawner.task().await.unwrap();

            std::thread::spawn(move || {
                let out = thread.event_loop();
                if let Err(e) = out {
                    tracing::error!("Proc Thread terminated: {e:#?}");
                }
            });

            tokio::spawn(async move {
                debugger.event_loop().await;
            });

            println!("Spawned all events");
            task.handle().seize(ptrace::Options::empty()).await?;
            println!("Tracee seized");

            task.interrupt().await.unwrap();
            println!("Tracee interrupted");

            let mut mmap_task = task.fork().await?;

            tokio::spawn(async move {
                println!("creating breakpoint");
                let mut hw_bk = task.create_hw_bkpt().await.unwrap();
                hw_bk
                    .modify(|bk| {
                        bk.set_enable(true)
                            .location(addr)
                            .condition(async_debugger::HwBreakpointCond::Write)
                            .size(async_debugger::HwBreakpointSize::Bytes4)
                    })
                    .await
                    .unwrap();
                println!("Hw bkpt now set");

                task.cont().await.unwrap();
                loop {
                    let regs = hw_bk.wait_break().await.unwrap();
                    *found.lock().await.entry(regs.rip).or_insert(0) += 1;
                    let res = task.cont().await;
                    if let Err(_) = res {
                        break;
                    }
                }
            });

            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                println!("Mmapping region");
                let addr = mmap_task
                    .call_mmap(None, 0x1000, ProtFlags::all(), MapFlags::MAP_PRIVATE)
                    .await
                    .unwrap();
                println!("Region allocated: {addr:x}");
                let _ = mmap_task.cont().await;
                println!("Task resumed");
                tokio::time::sleep(Duration::from_secs(9)).await;
                // mmap_task.complete().await;
                // println!("Task complete");
                println!("Attempting shutdown");
                let _ = mmap_task.interrupt().await;
                mmap_task.req_shutdown().await;
            });

            let lock = found_map.lock().await;
            println!("Lock: {:x?}", *lock);
            drop(lock);

            for _i in 0..10 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let lock = found_map.lock().await;
                println!("Lock: {:x?}", *lock);
                drop(lock);
            }
            Ok(())
        })
}

fn get_prog_info() -> (Pid, i64) {
    let (pid, addr_str) = get_prog_info_from_cmd()
        .or_else(get_prog_info_from_file)
        .unwrap();
    let pid = Pid::from_raw(pid);
    let addr = i64::from_str_radix(addr_str.strip_prefix("0x").unwrap_or(&addr_str), 16).unwrap();
    (pid, addr)
}

fn get_prog_info_from_cmd() -> Option<(i32, String)> {
    let pid: i32 = std::env::args().nth(1)?.parse().ok()?;
    let addr = std::env::args().nth(2)?;
    Some((pid, addr))
}

fn get_prog_info_from_file() -> Option<(i32, String)> {
    let filename = std::env::args().nth(1)?;
    let string = std::fs::read_to_string(filename).ok()?;

    let (pid_str, addr_str) = string.split_once(' ')?;
    let pid = pid_str.trim().parse().ok()?;
    let addr = addr_str.trim().to_string();

    Some((pid, addr))
}

fn setup_logging() {
    // console_subscriber::init();
    let level = LevelFilter::INFO.into();

    let env_filter = tracing_subscriber::filter::EnvFilter::builder()
        .with_default_directive(level)
        .from_env_lossy();

    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
