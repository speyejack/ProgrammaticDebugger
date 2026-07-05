use std::{
    os::fd::AsFd,
    sync::{Arc, mpsc},
};

use crate::{Result, comms::ProcCmd};

use nix::{
    poll::{self, PollFd, PollFlags, PollTimeout},
    sys::{
        eventfd::EventFd,
        ptrace::{self},
        signal::{SigSet, SigmaskHow, Signal, sigprocmask},
        signalfd::{SfdFlags, SignalFd},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};

pub struct ProcThread {
    pid: Pid,
    alert_fd: Arc<EventFd>,
    sigfd: SignalFd,
    cmds: mpsc::Receiver<ProcCmd>,
}

impl ProcThread {
    pub fn new(pid: Pid, cmds: mpsc::Receiver<ProcCmd>, alert_fd: Arc<EventFd>) -> Self {
        let sigfd = create_sigchld_fd().unwrap();

        ProcThread {
            pid,
            alert_fd,
            sigfd,
            cmds,
        }
    }

    pub fn event_loop(mut self) {
        use ProcCmd::*;

        loop {
            let recv_cmd = self.cmds.recv();
            if let Ok(cmd) = recv_cmd {
                match cmd {
                    WaitEvent(flags, sender) => {
                        let res = self.wait_event(flags);
                        let _ = sender.send(res);
                    }
                    WaitPid(flags, sender) => {
                        let res = self.wait_pid(flags);
                        let _ = sender.send(res);
                    }

                    Cmd(func) => func(self.pid),
                }
            } else {
                break;
            }
        }
    }

    fn wait_event(&mut self, flags: Option<WaitPidFlag>) -> Result<(WaitStatus, bool)> {
        let mut fds = [
            PollFd::new(self.sigfd.as_fd(), PollFlags::POLLIN),
            PollFd::new(self.alert_fd.as_fd(), PollFlags::POLLIN),
        ];
        // let _poll_event = poll::poll(&mut fds, PollTimeout::NONE);
        let _poll_event = poll::poll(&mut fds, PollTimeout::from(10u16));

        let has_sigfd_event = fds[0]
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN);

        let has_alert = fds[1]
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN);

        if has_alert {
            let _event = self.alert_fd.read();
            let _ = ptrace::interrupt(self.pid);
        }

        if has_sigfd_event {
            let _sig = self.sigfd.read_signal();
        }

        // tracing::trace!("Debug waitpid event");
        let res = self.wait_pid(flags)?;

        // let mut flags = None;
        // flags = Some(WaitPidFlag::WNOHANG);
        // let mut hit_count = 0;
        // 'pidloop: loop {
        //     let event = waitpid(pid, flags);
        //     flags = Some(WaitPidFlag::WNOHANG);
        //     match event {
        //         Ok(WaitStatus::StillAlive) => break 'pidloop,
        //         Ok(WaitStatus::Stopped(_, _)) => {}
        //         e => {
        //             tracing::warn!("Unhandled event: {event:?}");
        //         }
        //     }
        //     hit_count += 1;
        // }
        //
        // tracing::trace!("Debug event looped {hit_count} times");
        // Drain read signal
        loop {
            if let Ok(None) = self.sigfd.read_signal() {
                break;
            }
        }

        Ok((res, has_alert))
        // tracing::trace!("Event: {event:?}");
    }

    fn wait_pid(&mut self, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        waitpid(self.pid, flags).map_err(Into::into)
    }
}

pub fn create_sigchld_fd() -> nix::Result<SignalFd> {
    // Block SIGCHLD so it doesn't get delivered normally
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)?;

    // Now create an fd that will become readable when SIGCHLD fires
    SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
}
