use nix::{
    libc::siginfo_t,
    sys::{ptrace, signal::Signal, wait::WaitStatus},
    unistd::Pid,
};

use crate::Result;

pub enum PtraceRequest {
    Attach(Pid, oneshot::Sender<Result<()>>),
    Seize(Pid, ptrace::Options, oneshot::Sender<Result<()>>),
    Continue(Pid, Option<Signal>, oneshot::Sender<Result<()>>),
    Step(Pid, Option<Signal>, oneshot::Sender<Result<()>>),
    Cmd(Box<dyn FnOnce() + Send>),
}

#[derive(Debug, Clone)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
}

impl From<siginfo_t> for SigInfo {
    fn from(value: siginfo_t) -> Self {
        Self {
            si_signo: value.si_signo,
            si_errno: value.si_errno,
            si_code: value.si_code,
        }
    }
}

pub struct StopBatch {
    pub events: Vec<(WaitStatus, Option<SigInfo>)>,
    pub was_interrupt: bool,
}
