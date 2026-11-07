use std::{
    ffi::c_long,
    fs::OpenOptions,
    os::unix::fs::FileExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI32, AtomicU32, Ordering::Relaxed},
        mpsc,
    },
};

use nix::{
    errno::Errno,
    libc::{ptrace_syscall_info, siginfo_t, user_regs_struct},
    sys::{
        ptrace::{self, AddressType, RegisterSet},
        signal::Signal,
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{Pid, getpid},
};

use crate::{
    DebuggerError, Result,
    comms::{PtraceRunningRequest, PtraceStoppedRequest, SigInfo, StopBatch},
    err::{FromOneshotRecv, FromPtraceExt, FromStdMpscSend},
    ptrace_thread::{INTERRUPT_SIGNAL, PtraceThread},
};

#[derive(Debug, Clone)]
pub struct TraceeHandle {
    pub tracee_pid: Pid,
    pub tracer_tid: Arc<AtomicI32>,
    pub stopped_cmds: mpsc::Sender<PtraceStoppedRequest>,
    pub running_cmds: mpsc::Sender<PtraceRunningRequest>,
}

impl TraceeHandle {
    pub fn setup_debugger(
        pid: Pid,
    ) -> Result<(
        TraceeHandle,
        PtraceThread,
        futures::channel::mpsc::Receiver<Result<StopBatch>>,
    )> {
        let (run_send, run_recv) = mpsc::channel();
        let (stop_send, stop_recv) = mpsc::channel();
        let (event_send, event_recv) = futures::channel::mpsc::channel(10);
        let thread = PtraceThread::new(run_recv, stop_recv, event_send);

        let handle = TraceeHandle {
            tracer_tid: thread.get_tracee_pid(),
            tracee_pid: pid,
            stopped_cmds: stop_send,
            running_cmds: run_send,
        };

        Ok((handle, thread, event_recv))
    }

    pub async fn send_interrupt(&self) -> Result<()> {
        let (send, recv) = oneshot::async_channel();

        self.running_cmds
            .send(PtraceRunningRequest::Interrupt(self.tracee_pid, send))
            .with_err("handle interrupt cmd")?;

        self.wake_ptrace_thread()?;

        recv.await.with_err("handle interrupt cmd")?
    }

    // Taken from ptrace
    pub async fn attach(&self) -> Result<()> {
        let (send, recv) = oneshot::async_channel();
        self.stopped_cmds
            .send(PtraceStoppedRequest::Attach(self.tracee_pid, send))
            .with_err("handle attach cmd")?;

        recv.await.with_err("handle attach cmd")?
    }

    pub async fn seize(&self, options: ptrace::Options) -> Result<()> {
        let (send, recv) = oneshot::async_channel();
        self.stopped_cmds
            .send(PtraceStoppedRequest::Seize(self.tracee_pid, options, send))
            .with_err("handle seize cmd")?;

        recv.await.with_err("handle seize cmd")?
    }

    pub async fn cont<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let (send, recv) = oneshot::async_channel();
        self.stopped_cmds
            .send(PtraceStoppedRequest::Continue(
                self.tracee_pid,
                sig.into(),
                send,
            ))
            .with_err("handle continue cmd")?;

        recv.await.with_err("handle continue cmd")?
    }

    pub async fn step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let (send, recv) = oneshot::async_channel();
        self.stopped_cmds
            .send(PtraceStoppedRequest::Step(
                self.tracee_pid,
                sig.into(),
                send,
            ))
            .with_err("handle step cmd")?;

        recv.await.with_err("handle step cmd")?
    }

    pub async fn detach<T>(self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let (send, recv) = oneshot::async_channel();
        self.stopped_cmds
            .send(PtraceStoppedRequest::Continue(
                self.tracee_pid,
                sig.into(),
                send,
            ))
            .with_err("handle detach cmd")?;

        recv.await.with_err("handle detach cmd")?
    }

    pub async fn raw_attach(&self) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::attach(pid), "attach")
            .await
    }

    pub async fn raw_cont<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::cont(pid, t), "continue")
            .await
    }

    pub async fn raw_waitpid<T>(&self, flags: T) -> Result<WaitStatus>
    where
        T: Into<Option<WaitPidFlag>>,
    {
        let options = flags.into();

        self.send_stopped_cmd(move |pid| waitpid(pid, options), "waitpid")
            .await
    }

    pub async fn raw_detach<T>(self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let t = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::detach(pid, t), "detach")
            .await
    }

    pub async fn getevent(&self) -> Result<i64> {
        self.send_stopped_cmd(move |pid| ptrace::getevent(pid), "getevent")
            .await
    }

    pub async fn getregs(&self) -> Result<user_regs_struct> {
        self.send_stopped_cmd(move |pid| ptrace::getregs(pid), "getregs")
            .await
    }

    pub async fn getregset<S: RegisterSet>(&self) -> Result<S::Regs>
    where
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_stopped_cmd(move |pid| ptrace::getregset::<S>(pid), "getregset")
            .await
    }

    pub async fn getsiginfo(&self) -> Result<SigInfo> {
        self.send_stopped_cmd(
            move |pid| ptrace::getsiginfo(pid).map(|x| SigInfo::from(x)),
            "getsiginfo",
        )
        .await
    }

    pub async fn raw_interrupt(&self) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::interrupt(pid), "interrupt")
            .await
    }

    pub async fn kill(self) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::kill(pid), "kill")
            .await
    }

    pub async fn read(&self, addr: u64) -> Result<c_long> {
        self.send_stopped_cmd(move |pid| ptrace::read(pid, addr as AddressType), "read")
            .await
    }

    pub async fn read_user(&self, offset: usize) -> Result<c_long> {
        self.send_stopped_cmd(
            move |pid| ptrace::read_user(pid, offset as AddressType),
            "read_user",
        )
        .await
    }

    pub async fn raw_seize(&self, options: ptrace::Options) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::seize(pid, options), "seize")
            .await
    }

    pub async fn setoptions(&self, options: ptrace::Options) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::setoptions(pid, options), "setoptions")
            .await
    }

    pub async fn setregs(&self, regs: user_regs_struct) -> Result<()> {
        self.send_stopped_cmd(move |pid| ptrace::setregs(pid, regs), "setregs")
            .await
    }

    pub async fn setregset<S>(&self, regs: S::Regs) -> Result<()>
    where
        S: RegisterSet + Send + 'static,
        <S as RegisterSet>::Regs: Send + 'static,
    {
        self.send_stopped_cmd(move |pid| ptrace::setregset::<S>(pid, regs), "setregset")
            .await
    }

    pub async fn raw_step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::step(pid, sig), "step")
            .await
    }

    pub async fn syscall<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::syscall(pid, sig), "syscall")
            .await
    }

    pub async fn syscall_info(&self) -> Result<ptrace_syscall_info> {
        self.send_stopped_cmd(move |pid| ptrace::syscall_info(pid), "syscall_info")
            .await
    }

    pub async fn sysemu<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::sysemu(pid, sig), "sysemu")
            .await
    }
    pub async fn sysemu_step<T>(&self, sig: T) -> Result<()>
    where
        T: Into<Option<Signal>>,
    {
        let sig = sig.into();
        self.send_stopped_cmd(move |pid| ptrace::sysemu_step(pid, sig), "sysemu_step")
            .await
    }

    pub async fn write(&self, addr: u64, data: c_long) -> Result<()> {
        self.send_stopped_cmd(
            move |pid| ptrace::write(pid, addr as AddressType, data),
            "write",
        )
        .await
    }

    pub async fn write_user(&self, offset: usize, data: c_long) -> Result<()> {
        self.send_stopped_cmd(
            move |pid| ptrace::write_user(pid, offset as AddressType, data),
            "write_user",
        )
        .await
    }

    pub async fn write_vec_memory(&self, addr: usize, data: Vec<u8>) -> Result<()> {
        self.send_running_cmd(move |pid| {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{}/mem", pid.as_raw()))
                .map_err(|_| DebuggerError::Ptrace {
                    op: "write_memory",
                    pid,
                    code: Errno::EPERM,
                })?;

            file.write_all_at(&data, addr as u64)
                .map_err(|_| DebuggerError::Ptrace {
                    op: "write_memory",
                    pid,
                    code: Errno::EPERM,
                })
        })
        .await
    }

    fn wake_ptrace_thread(&self) -> Result<()> {
        let pid = getpid();
        let tracer_tid = Pid::from_raw(self.tracer_tid.load(Relaxed));
        tgkill(pid, tracer_tid, INTERRUPT_SIGNAL).with_err("wake thread", pid)
    }

    async fn send_stopped_cmd<T, F>(&self, func: F, op: &'static str) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Pid) -> std::result::Result<T, Errno> + Send + 'static,
    {
        let (send, recv) = oneshot::async_channel();

        let pid = self.tracee_pid;
        let wrapper = move || {
            let res = func(pid).with_err(op, pid);
            let _ = send.send(res);
        };

        self.stopped_cmds
            .send(PtraceStoppedRequest::IntCommand(Box::new(wrapper)))
            .with_err("handle cmd")?;

        self.wake_ptrace_thread()?;

        let data = recv.await.with_err("handle cmd")?;

        data
    }

    async fn send_running_cmd<T, F>(&self, func: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Pid) -> std::result::Result<T, DebuggerError> + Send + 'static,
    {
        let (send, recv) = oneshot::async_channel();

        let pid = self.tracee_pid;
        let wrapper = move || {
            let res = func(pid);
            let _ = send.send(res);
        };

        self.running_cmds
            .send(PtraceRunningRequest::RunCommand(Box::new(wrapper)))
            .with_err("handle cmd")?;
        self.wake_ptrace_thread()?;

        let data = recv.await.with_err("handle cmd")?;

        data
    }
}

fn tgkill(pid: Pid, tid: Pid, signal: Signal) -> std::result::Result<(), Errno> {
    let result =
        unsafe { nix::libc::syscall(nix::libc::SYS_tgkill, pid, tid, signal as nix::libc::c_int) };

    if result == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}
