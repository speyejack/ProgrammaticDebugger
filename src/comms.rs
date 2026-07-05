use nix::{
    sys::wait::{WaitPidFlag, WaitStatus},
    unistd::Pid,
};

use crate::Result;

pub enum ProcCmd {
    WaitEvent(
        Option<WaitPidFlag>,
        oneshot::Sender<Result<(WaitStatus, bool)>>,
    ),
    WaitPid(Option<WaitPidFlag>, oneshot::Sender<Result<WaitStatus>>),
    Cmd(Box<dyn FnOnce(Pid) + Send>),
    // CmdBatch,
}
