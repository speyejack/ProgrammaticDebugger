use std::{
    collections::{HashMap, VecDeque},
    mem::offset_of,
    sync::Arc,
};

use nix::{
    libc::user_regs_struct,
    poll::PollTimeout,
    sys::wait::{WaitPidFlag, WaitStatus},
    unistd::Pid,
};
use tokio::sync::mpsc;

use crate::{
    DebugHandle, DebugTask, Result,
    breakpoint::HardwareBreakpoint,
    debug_thread::{ProcThread, StopBatch},
    err::{FromMpscSend, FromOneshotSend},
};

pub type TaskID = usize;

pub struct Debugger {
    handle: Arc<DebugHandle>,
    recv: mpsc::Receiver<DebuggerMessage>,
    event_recv: mpsc::Receiver<Result<StopBatch>>,

    tstatus: HashMap<TaskID, TaskStatus>,
    next_id: usize,

    is_stopped: bool,
    is_stepping: bool,
    on_interrupt: Vec<(TaskID, oneshot::Sender<Result<()>>)>,
    on_step: Vec<(TaskID, oneshot::Sender<()>)>,
    on_continue: Vec<(TaskID, oneshot::Sender<()>)>,
    req_control: VecDeque<(TaskID, oneshot::Sender<()>)>,

    hw_bps: [Option<(TaskID, HardwareBreakpoint, mpsc::Sender<user_regs_struct>)>; 4],
}

#[derive(Debug, Clone, Copy)]
enum TaskStatus {
    Running,
    Waiting,
}

pub(crate) enum DebuggerMessage {
    // TaskWaiting(TaskID),
    // TODO: Need some way to delete tasks
    CreateNewTask(oneshot::Sender<TaskID>),
    RemoveTask((TaskID, oneshot::Sender<()>)),

    Continue((TaskID, oneshot::Sender<()>)),
    Step((TaskID, oneshot::Sender<()>)),

    Interrupt((TaskID, oneshot::Sender<Result<()>>)),
    ReqControl((TaskID, oneshot::Sender<()>)),
    // CreateBreakpoint,
    // DeleteBreakpoint(oneshot::Sender<()>),
    //
    CreateHwBreakpoint(
        (
            TaskID,
            oneshot::Sender<Option<(HardwareBreakpoint, mpsc::Receiver<user_regs_struct>)>>,
        ),
    ),
    ModifyHwBreakpoint((HardwareBreakpoint, oneshot::Sender<()>)),
    DeleteHwBreakpoint((HardwareBreakpoint, Option<oneshot::Sender<()>>)),
}

impl Debugger {
    pub async fn quick_setup(pid: Pid) -> Result<(Self, DebugTask, ProcThread)> {
        let (handle, thread, event_recv) = DebugHandle::setup_debugger(pid)?;
        let (send, recv) = mpsc::channel(10);
        let handle = Arc::new(handle);

        let task = DebugTask {
            id: 0,
            debug_handle: handle.clone(),
            sender: send.clone(),
        };

        Ok((
            Self {
                handle,
                recv,
                event_recv,
                tstatus: Default::default(),
                next_id: 1,
                is_stopped: false,
                is_stepping: false,
                on_interrupt: Default::default(),
                on_step: Default::default(),
                on_continue: Default::default(),
                req_control: Default::default(),
                hw_bps: [const { None }; 4],
            },
            task,
            thread,
        ))
    }

    pub async fn event_loop(mut self) {
        loop {
            tokio::select! {
                event = self.event_recv.recv() => {
                    if let Some(Ok(batch)) = event {
                        tracing::debug!("Debugger got stop batch from proc thread");

                        let e = self.handle_stopping(batch).await;

                        if let Err(e) = e {
                            tracing::warn!("Error in event recv: {e}");
                        }

                    }
                }
                event = self.recv.recv() => {
                    tracing::debug!("Debugger got event from tasks");
                    match event {
                        Some(event) => {
                            let e = self.handle_ext_event(event).await;

                            if let Err(e) = e {
                                tracing::warn!("Error in ext event: {e}");
                            }

                        },
                        None => {
                            tracing::info!("Shutting down debugger");
                            break
                        },
                    }
                }
            };
        }
    }

    // This function needs to be refactored to handle each event better, likely queuing them up
    async fn handle_stopping(&mut self, batch: StopBatch) -> Result<()> {
        let debug_offset = offset_of!(nix::libc::user, u_debugreg);
        let d6o = debug_offset + 6 * 8;

        let mut stepped = false;
        let mut hw_d6 = None;
        for (event, _) in batch.events {
            match event {
                WaitStatus::PtraceEvent(_pid, signal, _) => match signal {
                    nix::sys::signal::Signal::SIGTRAP if self.is_stepping => {
                        stepped = true;
                    }
                    nix::sys::signal::Signal::SIGTRAP => {
                        let d6 = self.handle.read_user(d6o).await? & 0xF;
                        if d6 > 0 {
                            hw_d6 = Some(d6);
                        }
                    }
                    sig => tracing::warn!("Unhandled ptrace event status signal: {sig}"),
                },
                WaitStatus::Stopped(_pid, signal) => match signal {
                    nix::sys::signal::Signal::SIGTRAP if self.is_stepping => {
                        stepped = true;
                    }
                    nix::sys::signal::Signal::SIGTRAP => {
                        let d6 = self.handle.read_user(d6o).await? & 0xF;
                        if d6 > 0 {
                            hw_d6 = Some(d6);
                        }
                    }
                    sig => tracing::warn!("Unhandled stop event status signal: {sig}"),
                },
                status => {
                    let info = self.handle.getsiginfo().await;
                    tracing::warn!("Unhandled event: {status:?} with info {info:?}");
                }
            }
        }

        tracing::debug!("Handled all wait_pids");
        self.is_stopped = true;

        // Handle hardware breakpoint
        if let Some(mut d6) = hw_d6 {
            let regs = self.handle.getregs().await?;
            while d6 > 0 {
                let idx = d6.trailing_zeros() as usize;
                tracing::debug!("Hw breakpoint {} being triggered", idx);
                let (task_id, _hw_bk, sender) = self.hw_bps[idx]
                    .as_ref()
                    .expect("Hw breakpoint accessed without being setup");
                if let Some(task_status) = self.tstatus.get_mut(task_id) {
                    *task_status = TaskStatus::Running;
                    sender
                        .send(regs)
                        .await
                        .with_err("debugger resuming task on hw bp")?;
                } else {
                    // TODO: Reset & disable hw breakpoint. Replace with None in list
                    todo!("Handle unlinked breakpoint")
                }
                d6 >>= 1;
            }
            self.handle.write_user(d6o, 0x0).await?;

            if !self.on_interrupt.is_empty() {
                self.send_interrupts().await;
            }
        }

        tracing::debug!("Handled hardware breakpoints");
        // Handle Stepping
        if stepped {
            self.is_stepping = false;
            self.is_stopped = true;
            self.send_steps().await;
        }
        tracing::debug!("Handled steps");

        self.attempt_resume().await;
        Ok(())
    }

    fn is_stopped(&self) -> bool {
        self.is_stopped
    }

    fn handle_task_send<T>(
        &mut self,
        res: std::result::Result<(), oneshot::SendError<T>>,
        id: TaskID,
        status: TaskStatus,
    ) {
        match res {
            Ok(_) => {
                self.tstatus.insert(id, status);
            }
            Err(_) => {
                self.tstatus.remove(&id);
            }
        }
    }

    async fn handle_ext_event(&mut self, event: DebuggerMessage) -> Result<()> {
        // Likely this will be called during handling of running until waitpid & during waiting for tasks, continue & step shouldnt happen during waitpid/running.
        // during running.
        match event {
            DebuggerMessage::CreateNewTask(sender) => {
                tracing::debug!("Debugger created task");
                let id = self.next_id;
                self.next_id += 1;

                self.handle_task_send(sender.send(id), id, TaskStatus::Running);
                return Ok(());
            }
            DebuggerMessage::RemoveTask((id, sender)) => {
                tracing::debug!("Debugger removing task");

                self.tstatus.remove(&id);
                let _ = sender.send(());
                return Ok(());
            }
            DebuggerMessage::Continue((id, sender)) => {
                tracing::debug!("Debugger got {id} wants continue");
                self.on_continue.push((id, sender));
                self.tstatus.insert(id, TaskStatus::Waiting);
            }
            // DebuggerMessage::TaskWaiting(id) => {
            //     self.tstatus.insert(id, TaskStatus::Waiting);
            // }
            DebuggerMessage::Step((id, sender)) => {
                tracing::debug!("Debugger got {id} wants step");
                self.on_step.push((id, sender));
                self.tstatus.insert(id, TaskStatus::Waiting);
            }
            DebuggerMessage::Interrupt((id, sender)) => {
                tracing::debug!("Debugger got {id} wants interrupt");
                if !self.is_stopped {
                    tracing::debug!("Debugger sending interrupt");

                    self.handle.send_interrupt().await?
                }

                self.tstatus.insert(id, TaskStatus::Waiting);
                self.on_interrupt.push((id, sender));

                return Ok(());
            }
            DebuggerMessage::ReqControl((id, sender)) => {
                tracing::debug!("Task {id} requested control from debugger");
                self.req_control.push_back((id, sender));
                self.tstatus.insert(id, TaskStatus::Waiting);
            }
            DebuggerMessage::CreateHwBreakpoint((task_id, sender)) => {
                tracing::debug!("Debugger got {task_id} created hw breakpoint");
                let idx = self.hw_bps.iter().position(|v| v.is_none());
                if let Some(idx) = idx {
                    let bk = HardwareBreakpoint::new(idx);
                    let (esend, erecv) = mpsc::channel(10);
                    self.hw_bps[idx] = Some((task_id, bk, esend));
                    sender
                        .send(Some((bk, erecv)))
                        .with_err("debugger create hw bp reply")?;
                } else {
                    sender.send(None).with_err("debugger create hw bp reply")?
                }
            }
            DebuggerMessage::ModifyHwBreakpoint((hw_bk, sender)) => {
                tracing::debug!("Debugger modified hw breakpoint");
                let mut d7 = self.handle.read_user(HardwareBreakpoint::d7_addr()).await?;
                // There may be a race condition if the program is still running or struct is run in
                // concurrently

                let mut local_bk = self.hw_bps[hw_bk.id]
                    .take()
                    .expect("Modified unset breakpoint");

                d7 &= hw_bk.d7_mask();
                d7 |= hw_bk.d7_set();
                let _ = self
                    .handle
                    .write_user(HardwareBreakpoint::d7_addr(), d7)
                    .await;
                let _ = self.handle.write_user(hw_bk.dx_addr(), hw_bk.loc).await;

                local_bk.1 = hw_bk;
                let _ = self.hw_bps[hw_bk.id].insert(local_bk);
                println!("Modified breakpoint");

                let _ = sender.send(()).with_err("debugger modify hw bp reply");
            }
            DebuggerMessage::DeleteHwBreakpoint((mut hw_bk, sender)) => {
                tracing::debug!("Debugger deleted hw breakpoint");
                let _local_bk = self.hw_bps[hw_bk.id]
                    .take()
                    .expect("Modified unset breakpoint");

                hw_bk.is_enabled = false;
                let mut d7 = self.handle.read_user(HardwareBreakpoint::d7_addr()).await?;
                d7 &= hw_bk.d7_mask();
                d7 |= hw_bk.d7_set();
                let _ = self
                    .handle
                    .write_user(HardwareBreakpoint::d7_addr(), d7)
                    .await;

                sender.map(|s| s.send(()));
            }
        }

        self.attempt_resume().await?;
        Ok(())
    }

    async fn attempt_resume(&mut self) -> Result<()> {
        if !self.is_stopped() {
            return Ok(());
        }

        // Handle any pending interrupts
        if !self.on_interrupt.is_empty() {
            self.send_interrupts().await;
            tracing::debug!("Handled interrupts");
            return Ok(());
        }

        // Prevent resuming if any tasks not waiting
        if self
            .tstatus
            .iter()
            .any(|(_, s)| !matches!(s, TaskStatus::Waiting))
        {
            tracing::debug!("Cannot resume, waiting on tasks: {:?}", self.tstatus);
            return Ok(());
        }

        // Handle any special control requests one at a time
        if !self.req_control.is_empty() {
            let (id, sender) = self.req_control.pop_front().unwrap();

            match sender.send(()) {
                Ok(_) => {
                    self.tstatus.insert(id, TaskStatus::Running);
                }
                Err(_) => {
                    self.tstatus.remove(&id);
                }
            }
            self.tstatus.insert(id, TaskStatus::Running);
            return Ok(());
        }

        // Handle any step requests
        if !self.on_step.is_empty() {
            self.is_stepping = true;
            self.handle.step(None).await?;
            // Step requests handled after step
            self.is_stopped = false;
            tracing::debug!("Resuming step");
            return Ok(());
        }

        tracing::debug!("Resuming cont");
        // Handle any step requests
        self.handle.cont(None).await?;
        self.send_continues().await;
        self.is_stopped = false;
        Ok(())
    }

    async fn send_interrupts(&mut self) {
        let on_interrupt = std::mem::replace(&mut self.on_interrupt, Vec::new());
        for (id, sender) in on_interrupt {
            match sender.send(Ok(())) {
                Ok(_) => {
                    self.tstatus.insert(id, TaskStatus::Running);
                }
                Err(_) => {
                    self.tstatus.remove(&id);
                }
            }
        }
    }

    async fn send_continues(&mut self) {
        let on_continue = std::mem::replace(&mut self.on_continue, Vec::new());
        for (id, sender) in on_continue {
            // May need to want to track this
            // self.tstatus.insert(id, TaskStatus::Running);
            let o = sender.send(());
            if let Err(e) = o {
                self.tstatus.remove(&id);
            }
        }
    }

    async fn send_steps(&mut self) {
        let on_step = std::mem::replace(&mut self.on_step, Vec::new());
        for (id, sender) in on_step {
            match sender.send(()) {
                Ok(_) => {
                    self.tstatus.insert(id, TaskStatus::Running);
                }
                Err(_) => {
                    self.tstatus.remove(&id);
                }
            }
        }
    }
}
