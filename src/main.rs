mod comms;
mod debug_thread;
mod err;
mod handle;

pub use err::Result;

use std::{
    collections::HashMap,
    mem::offset_of,
    sync::{Arc, Mutex},
};

use nix::{
    libc::user_regs_struct,
    sys::{
        ptrace,
        wait::{WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

use crate::handle::DebugHandle;

pub async fn mvp_debugger(
    pid: Pid,
    data_loc: i64,
    found: Arc<Mutex<HashMap<u64, (usize, Option<user_regs_struct>)>>>,
) {
    tracing::trace!("Starting Debugger");

    let (mut handle, thread) = DebugHandle::setup_debugger(pid).unwrap();
    let join_handle = std::thread::spawn(move || {
        thread.event_loop();
    });

    let debug_offset = offset_of!(nix::libc::user, u_debugreg);
    let d0o = debug_offset;
    let d6o = debug_offset + 6 * 8;
    let d7o = debug_offset + 7 * 8;

    handle.seize(ptrace::Options::empty()).await.unwrap();
    tracing::trace!("Process seized");
    handle.raw_interrupt().await.unwrap();
    handle.wait_event(None).await.unwrap();
    tracing::trace!("Process interrupted");

    let d7set = 0b10 << (0 * 4 + 18) // Size byte 8
        | 0x0100 // recommended to have this local exact breakpoint
        | 0b01 << (0 * 4 + 16) // Write
        | 0b01 << (0 * 2);

    tracing::trace!("d7: {d7set:x}");
    handle.write_user(d0o, data_loc).await.unwrap();
    handle.write_user(d7o, d7set).await.unwrap();
    let _o = handle.read_user(d6o).await.unwrap();
    handle.cont(None).await.unwrap();
    tracing::trace!("Starting loop");

    loop {
        let (event, was_interrupt) = handle.wait_event(Some(WaitPidFlag::WNOHANG)).await.unwrap();
        if was_interrupt {
            break;
        }

        let mut event = Ok(event);
        'pidloop: loop {
            match event {
                Ok(WaitStatus::StillAlive) => break 'pidloop,
                Ok(WaitStatus::Stopped(_, _)) => {
                    let regs = ptrace::getregs(pid).unwrap();
                    let loc = regs.rip;
                    let regs = handle.getregs().await.unwrap();

                    let mut map = found.lock().unwrap();
                    let count = map.entry(loc).or_default();
                    (*count).0 += 1;
                    (*count).1 = Some(regs);
                    // tracing::trace!(loc, count.0, "Stored location");
                    handle.write_user(d6o, 0).await.unwrap();
                }
                ref e => {
                    tracing::warn!("Unhandled event: {e:?}");
                }
            };
            event = handle.wait_pid(Some(WaitPidFlag::WNOHANG)).await;
        }
    }

    tracing::trace!("Finishing loop");

    handle.raw_interrupt().await.unwrap();
    handle.wait_pid(None).await.unwrap();

    handle.write_user(d7o, 0).await.unwrap();
    handle.write_user(d0o, 0).await.unwrap();
    handle.write_user(d6o, 0).await.unwrap();

    loop {
        let e = handle.wait_pid(Some(WaitPidFlag::WNOHANG)).await.unwrap();
        if matches!(e, nix::sys::wait::WaitStatus::StillAlive) {
            break;
        }
        tracing::trace!("Oops backed up event");
    }

    handle.detach(None).await.unwrap();
    join_handle.join().unwrap();
}

fn main() {
    println!("Hello, world!");
}
