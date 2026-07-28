use std::sync::Arc;

use nix::libc::user_regs_struct;
use tokio::sync::mpsc;

use crate::{
    DebugHandle, Result,
    breakpoint::HardwareBreakpoint,
    debugger::{DebuggerMessage, TaskID},
    err::{FromMpscSend, FromOneshotRecv},
};

pub struct DebugTask {
    pub(crate) id: TaskID,
    pub(crate) sender: mpsc::Sender<DebuggerMessage>,
    pub(crate) debug_handle: Arc<DebugHandle>,
}

pub struct TaskBkPt {
    bk_pt: HardwareBreakpoint,
    sender: mpsc::Sender<DebuggerMessage>,
    recv: mpsc::Receiver<user_regs_struct>,
}

impl TaskBkPt {
    pub fn current(&self) -> HardwareBreakpoint {
        self.bk_pt
    }

    pub async fn modify<F>(&mut self, func: F) -> Result<()>
    where
        F: FnOnce(HardwareBreakpoint) -> HardwareBreakpoint,
    {
        let bp = func(self.bk_pt);
        self.bk_pt = bp;

        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::ModifyHwBreakpoint((bp, send)))
            .await
            .with_err("breakpoint modify")?;
        println!("Send msg");
        Ok(reply.await.with_err("breakpoint modify")?)
    }

    pub async fn delete(&mut self, bp: HardwareBreakpoint) -> Result<()> {
        self.bk_pt = bp;
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::DeleteHwBreakpoint((bp, Some(send))))
            .await
            .with_err("breakpoint delete")?;
        Ok(reply.await.with_err("breakpoint delete")?)
    }

    pub async fn wait_break(&mut self) -> Option<user_regs_struct> {
        self.recv.recv().await
    }
}

impl Drop for TaskBkPt {
    fn drop(&mut self) {
        let _ = self
            .sender
            .try_send(DebuggerMessage::DeleteHwBreakpoint((self.bk_pt, None)));
    }
}

impl DebugTask {
    pub async fn create_task(&self) -> Result<Self> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::CreateNewTask(send))
            .await
            .with_err("task creation")?;
        let id = reply.await.with_err("task creation")?;

        Ok(DebugTask {
            id,
            sender: self.sender.clone(),
            debug_handle: self.debug_handle.clone(),
        })
    }

    pub async fn complete(self) {
        let (send, reply) = oneshot::channel();
        let _ = self.sender.send(DebuggerMessage::RemoveTask((self.id, send))).await;
        let _ = reply.await;
    }


    pub fn handle(&self) -> &DebugHandle {
        &self.debug_handle
    }

    pub async fn cont(&self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Continue((self.id, send)))
            .await
            .with_err("task continue")?;
        Ok(reply.await.with_err("task continue")?)
    }

    pub async fn step(&self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Step((self.id, send)))
            .await
            .with_err("task step")?;
        Ok(reply.await.with_err("task continue")?)
    }

    pub async fn req_control(&self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::ReqControl((self.id, send)))
            .await
            .with_err("task req control")?;
        Ok(reply.await.with_err("task req control")?)
    }

    pub async fn interrupt(&self) -> Result<()> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::Interrupt((self.id, send)))
            .await
            .with_err("task interrupt")?;
        reply.await.with_err("task interrupt")??;
        Ok(())
    }

    pub async fn create_hw_bkpt(&self) -> Option<TaskBkPt> {
        let (send, reply) = oneshot::channel();
        self.sender
            .send(DebuggerMessage::CreateHwBreakpoint((self.id, send)))
            .await
            .ok()?;
        let out = reply.await.unwrap();
        if let Some((bk, channel)) = out {
            Some(TaskBkPt {
                bk_pt: bk,
                sender: self.sender.clone(),
                recv: channel,
            })
        } else {
            None
        }
    }

    fn force_syscall(&self, mut sys_regs: user_regs_struct) -> Result<()> {
        self.handle()
        let regs = self.handle().getregs()?;
        sys_regs.rip = regs.rip;

        let prev_data = self.handle().read(regs.rip)?;
        self.handle().write(regs.rip, 0x9090050F)?;
        self.handle().step(sig)

        let prev_data = ptrace::read(self.pid, regs.rip)?;
        ptrace::write(self.pid, regs.rip, 0x9090050F)?;
        ptrace::step(self.pid, 0);
        waitpid(self.pid, None);
        let new_regs = ptrace::getregs(self.pid)?;
        ptrace::setregs(self.pid, regs)?;
        ptrace::write(self.pid, regs.rip, prev_data)?;
    }

    fn call_func(&self, mut regs: user_regs_struct) -> Result<user_regs_struct> {
        let orig_regs = ptrace::getregs(self.pid).unwrap();
        regs.rip = orig_regs.rip;

        let prev_data = ptrace::read(self.pid, orig_regs.rip)?;
        ptrace::write(self.pid, orig_regs.rip, 0x90ccd0ff)?;
        ptrace::cont(self.pid, 0);
        waitpid(self.pid, None);
        let new_regs = ptrace::getregs(self.pid)?;
        ptrace::setregs(self.pid, orig_regs)?;
        ptrace::write(self.pid, orig_regs.rip, prev_data)?;
    }

    pub async fn run_syscall(&self, regs: user_regs_struct) -> Result<()> {
        let old_regs = self.handle().getregs().await?;
        self.handle().setregs(regs).await?;

        Ok(())
    }
}
