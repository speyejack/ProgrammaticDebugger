use nix::{
    poll::PollTimeout,
    sys::{
        ptrace,
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};

use crate::Result;

pub enum ProcCmd {
    Attach(oneshot::Sender<Result<()>>),
    Seize(ptrace::Options, oneshot::Sender<Result<()>>),
    Continue(Option<Signal>, oneshot::Sender<Result<()>>),
    Step(Option<Signal>, oneshot::Sender<Result<()>>),
    Cmd(Box<dyn FnOnce(Pid) + Send>),
}
