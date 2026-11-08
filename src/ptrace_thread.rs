use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering::Relaxed},
        mpsc,
    },
};

use crate::{
    DebuggerError, Result,
    comms::{PtraceRunningRequest, PtraceStoppedRequest, StopBatch},
    err::FromPtraceExt,
};

use nix::{
    sys::{
        ptrace,
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};

pub const INTERRUPT_SIGNAL: Signal = Signal::SIGUSR2;

pub struct PtraceThread {
    tracee_running: bool,
    attached: HashSet<Pid>,
    thread_pid: Arc<AtomicI32>,

    interrupting: bool,
    stopped_cmds: mpsc::Receiver<PtraceStoppedRequest>,
    running_cmds: mpsc::Receiver<PtraceRunningRequest>,
    event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
}

impl PtraceThread {
    pub fn new(
        running_cmds: mpsc::Receiver<PtraceRunningRequest>,
        stopped_cmds: mpsc::Receiver<PtraceStoppedRequest>,
        event_watch: futures::channel::mpsc::Sender<Result<StopBatch>>,
    ) -> Self {
        install_sig_handler();
        PtraceThread {
            tracee_running: false,
            attached: HashSet::new(),
            interrupting: false,
            event_watch,
            running_cmds,
            stopped_cmds,
            thread_pid: Arc::new(AtomicI32::new(0)),
        }
    }

    pub fn event_loop(mut self) -> Result<()> {
        self.thread_pid
            .store(nix::unistd::gettid().as_raw(), Relaxed);
        use PtraceStoppedRequest::*;
        'event_loop: loop {
            if self.tracee_running {
                // tracing::debug!("PtraceThread waiting for tracee stop");
                let batch = self.wait_stop(None);

                // Handle non-interrupting command
                if let Err(DebuggerError::Ptrace {
                    code: nix::errno::Errno::EINTR,
                    ..
                }) = batch
                {
                    let recv_cmd = self.running_cmds.recv();
                    if let Ok(cmd) = recv_cmd {
                        match cmd {
                            PtraceRunningRequest::RunCommand(fn_once) => fn_once(),
                            PtraceRunningRequest::Interrupt(pid, sender) => {
                                let out = ptrace::interrupt(pid).with_err("interrupt", pid);
                                if out.is_ok() {
                                    self.interrupting = true;
                                }

                                let _ = sender.send(out);
                            }
                        }
                    }
                    continue;
                }

                if let Err(e) = self.event_watch.try_send(batch) {
                    tracing::debug!("PtraceThread closing due to event watch: {e}");
                    break;
                }

                self.tracee_running = false;
            }

            'cmd_loop: loop {
                let recv_cmd = self.stopped_cmds.recv();
                if let Ok(cmd) = recv_cmd {
                    match cmd {
                        IntCommand(func) => func(),
                        Seize(pid, options, sender) => {
                            let out = ptrace::seize(pid, options).with_err("seize", pid);
                            if out.is_ok() {
                                self.attached.insert(pid);
                            }
                            let _ = sender.send(out);
                            break 'cmd_loop;
                        }
                        Attach(pid, sender) => {
                            let out = ptrace::attach(pid).with_err("attach", pid);
                            if out.is_ok() {
                                self.attached.insert(pid);
                            }
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
                        Detach(pid, signal, sender) => {
                            let out = ptrace::detach(pid, signal).with_err("detach", pid);
                            if out.is_ok() {
                                self.attached.remove(&pid);
                            }
                            let _ = sender.send(out);
                            break 'event_loop;
                        }
                    }
                } else {
                    break 'event_loop;
                }
            }
            self.tracee_running = true;
        }

        self.thread_pid.store(0, Relaxed);
        tracing::info!("Ptrace Thread terminating");
        Ok(())
    }

    // TODO: Allow stop to handle an error and a partial stop batch
    pub fn wait_stop(&mut self, pid: Option<Pid>) -> Result<StopBatch> {
        let mut events = Vec::new();

        let mut event = self.wait_pid(pid, Some(WaitPidFlag::empty()))?;

        let mut was_interrupt = false;

        // tracing::trace!("Got event, stopping tracee");
        loop {
            match event {
                WaitStatus::StillAlive => break,
                WaitStatus::PtraceEvent(_, Signal::SIGINT, _) if self.interrupting => {
                    self.interrupting = false;
                    was_interrupt = true;
                }

                status => {
                    events.push((status, None));
                }
            }

            event = self.wait_pid(pid, Some(WaitPidFlag::WNOHANG))?;
        }
        // tracing::trace!("Tracee stopped");

        Ok(StopBatch {
            events,
            was_interrupt,
        })
    }

    fn wait_pid(&mut self, pid: Option<Pid>, flags: Option<WaitPidFlag>) -> Result<WaitStatus> {
        waitpid(pid, flags).with_err("waitpid", pid)
    }

    pub fn get_tracee_pid(&self) -> Arc<AtomicI32> {
        self.thread_pid.clone()
    }
}

extern "C" fn handle_sig(_signal: nix::libc::c_int) {
    // Noop, just to cause interrupt
}
pub fn install_sig_handler() {
    let signal = INTERRUPT_SIGNAL;

    let handler = SigHandler::Handler(handle_sig);
    let action = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    unsafe { nix::sys::signal::sigaction(signal, &action) }.unwrap();
}

impl Drop for PtraceThread {
    fn drop(&mut self) {
        for attach_pid in &self.attached {
            let _ = ptrace::detach(*attach_pid, None);
        }
    }
}
