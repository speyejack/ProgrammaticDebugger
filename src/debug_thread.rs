use std::{
    os::fd::AsFd,
    sync::{Arc, Mutex, mpsc},
};

use crate::{Result, comms::ProcCmd, err::FromPtraceExt};

use nix::{
    libc::siginfo_t,
    sys::{
        ptrace::{self},
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};

pub const INTERRUPT_SIGNAL: Signal = Signal::SIGUSR1;

pub struct ProcThread {
    pid: Pid,
    tracee_running: bool,

    interrupting: Arc<Mutex<bool>>,
    cmds: mpsc::Receiver<ProcCmd>,
    event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
}

pub struct StopBatch {
    pub events: Vec<(WaitStatus, Option<siginfo_t>)>,
    pub was_interrupt: bool,
}

impl ProcThread {
    pub fn new(
        pid: Pid,
        interrupting: Arc<Mutex<bool>>,
        cmds: mpsc::Receiver<ProcCmd>,
        event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
    ) -> Self {
        ProcThread {
            pid,
            tracee_running: false,
            interrupting,
            cmds,
            event_watch,
        }
    }

    pub fn event_loop(mut self) -> Result<()> {
        use ProcCmd::*;
        'event_loop: loop {
            if self.tracee_running {
                tracing::debug!("ProcThread waiting for tracee stop");
                let batch = self.wait_stop();
                if let Err(e) = self.event_watch.try_send(batch) {
                    tracing::debug!("ProcThread closing due to event watch: {e}");
                    break;
                }

                self.tracee_running = false;
            }

            'cmd_loop: loop {
                let recv_cmd = self.cmds.recv();
                if let Ok(cmd) = recv_cmd {
                    match cmd {
                        Cmd(func) => func(self.pid),
                        Seize(options, sender) => {
                            let out = ptrace::seize(self.pid, options).with_err("seize", self.pid);
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                        Attach(sender) => {
                            let out = ptrace::attach(self.pid).with_err("attach", self.pid);
                            let _ = sender.send(out);
                        }
                        Continue(signal, sender) => {
                            let out = ptrace::cont(self.pid, signal).with_err("continue", self.pid);
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                        Step(signal, sender) => {
                            let out = ptrace::step(self.pid, signal).with_err("step", self.pid);
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                    }
                } else {
                    break 'event_loop;
                }
            }
            self.tracee_running = true;
        }

        tracing::info!("Proc Thread terminating");
        Ok(())
    }

    pub fn wait_stop(&mut self) -> Result<StopBatch> {
        let mut events = Vec::new();

        let mut event = self.wait_pid(Some(WaitPidFlag::empty()))?;

        let mut lock = self.interrupting.lock().expect("Poisoned Interrupt Lock");
        let was_interrupt = *lock;
        *lock = false;
        drop(lock);

        tracing::trace!("Got event, stopping tracee");
        let mut unhandled_interrupt = was_interrupt;
        loop {
            match event {
                WaitStatus::StillAlive => break,
                WaitStatus::Stopped(_, sig) if unhandled_interrupt && sig == INTERRUPT_SIGNAL => {
                    unhandled_interrupt = true;
                }

                status => {
                    events.push((status, None));
                }
            }

            event = self.wait_pid(Some(WaitPidFlag::WNOHANG))?;
        }
        tracing::trace!("Tracee stopped");

        Ok(StopBatch {
            events,
            was_interrupt,
        })
    }

    fn wait_pid(&mut self, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        waitpid(self.pid, flags).with_err("waitpid", self.pid)
    }
}
