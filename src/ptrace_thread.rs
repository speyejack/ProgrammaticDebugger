use std::sync::{Arc, Mutex, mpsc};

use crate::{
    Result,
    comms::{PtraceRequest, StopBatch},
    err::FromPtraceExt,
};

use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};

pub const INTERRUPT_SIGNAL: Signal = Signal::SIGUSR1;

pub struct PtraceThread {
    tracee_running: bool,

    interrupting: Arc<Mutex<bool>>,
    cmds: mpsc::Receiver<PtraceRequest>,
    event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
}

impl PtraceThread {
    pub fn new(
        interrupting: Arc<Mutex<bool>>,
        cmds: mpsc::Receiver<PtraceRequest>,
        event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
    ) -> Self {
        PtraceThread {
            tracee_running: false,
            interrupting,
            cmds,
            event_watch,
        }
    }

    pub fn event_loop(mut self) -> Result<()> {
        use PtraceRequest::*;
        'event_loop: loop {
            if self.tracee_running {
                tracing::debug!("PtraceThread waiting for tracee stop");
                let batch = self.wait_stop(None);
                if let Err(e) = self.event_watch.try_send(batch) {
                    tracing::debug!("PtraceThread closing due to event watch: {e}");
                    break;
                }

                self.tracee_running = false;
            }

            'cmd_loop: loop {
                let recv_cmd = self.cmds.recv();
                if let Ok(cmd) = recv_cmd {
                    match cmd {
                        Cmd(func) => func(),
                        Seize(pid, options, sender) => {
                            let out = ptrace::seize(pid, options).with_err("seize", pid);
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                        Attach(pid, sender) => {
                            let out = ptrace::attach(pid).with_err("attach", pid);
                            let _ = sender.send(out);
                        }
                        Continue(pid, signal, sender) => {
                            let out = ptrace::cont(pid, signal).with_err("continue", pid);
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                        Step(pid, signal, sender) => {
                            let out = ptrace::step(pid, signal).with_err("step", pid);
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

        tracing::info!("Ptrace Thread terminating");
        Ok(())
    }

    pub fn wait_stop(&mut self, pid: Option<Pid>) -> Result<StopBatch> {
        let mut events = Vec::new();

        let mut event = self.wait_pid(pid, Some(WaitPidFlag::empty()))?;

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

            event = self.wait_pid(pid, Some(WaitPidFlag::WNOHANG))?;
        }
        tracing::trace!("Tracee stopped");

        Ok(StopBatch {
            events,
            was_interrupt,
        })
    }

    fn wait_pid(&mut self, pid: Option<Pid>, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        waitpid(pid, flags).with_err("waitpid", pid)
    }
}
