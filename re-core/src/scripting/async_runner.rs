//! Background-thread runner for Rhai plugin scripts.
//!
//! Long-running scripts must not block the UI thread. Rhai's `Engine` is
//! `!Send` (it stores closures that capture environment), so the runner owns
//! its own engine on the worker side and communicates with callers through
//! channels.
//!
//! The trade-off: scripts running here see a *snapshot* of the project —
//! `functions`, `strings`, `comments`, `arch` — rather than a live mutable
//! reference. Mutations are returned as [`ScriptAction`]s for the main thread
//! to apply. Most plugin workflows fit this model: enumerate candidates,
//! decide what to rename or annotate, return the list.
//!
//! Submit jobs with [`AsyncPluginRunner::submit`]; drain results without
//! blocking with [`AsyncPluginRunner::poll`].

use crate::scripting::ScriptAction;
use rhai::{Dynamic, Engine, Scope};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

/// Snapshot of project state passed into a worker job. Cloned per job so the
/// worker can reference it without locks.
#[derive(Debug, Clone, Default)]
pub struct ProjectSnapshot {
    pub functions: Vec<(u64, String, usize)>,
    pub strings: Vec<(u64, String)>,
    pub comments: Vec<(u64, String)>,
    pub arch: String,
}

/// One job for the worker.
#[derive(Debug, Clone)]
pub struct ScriptJob {
    pub id: u64,
    pub source: String,
    pub snapshot: ProjectSnapshot,
}

/// Outcome of one worker job.
#[derive(Debug, Clone)]
pub struct ScriptResultMsg {
    pub id: u64,
    pub output: String,
    pub actions: Vec<ScriptAction>,
    pub error: Option<String>,
}

/// Handle to the worker thread.
pub struct AsyncPluginRunner {
    job_tx: Mutex<Sender<Option<ScriptJob>>>,
    result_rx: Mutex<Receiver<ScriptResultMsg>>,
    next_id: AtomicU64,
    worker: Option<JoinHandle<()>>,
}

impl AsyncPluginRunner {
    /// Spawn the worker thread. The caller keeps the returned handle alive
    /// for as long as plugins should be runnable.
    pub fn new() -> Self {
        let (job_tx, job_rx) = channel::<Option<ScriptJob>>();
        let (result_tx, result_rx) = channel::<ScriptResultMsg>();
        let worker = std::thread::spawn(move || worker_loop(job_rx, result_tx));
        Self {
            job_tx: Mutex::new(job_tx),
            result_rx: Mutex::new(result_rx),
            next_id: AtomicU64::new(1),
            worker: Some(worker),
        }
    }

    /// Submit a script for background execution. Returns the job id so the
    /// caller can correlate the eventual result.
    pub fn submit(&self, source: String, snapshot: ProjectSnapshot) -> Result<u64, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let job = ScriptJob {
            id,
            source,
            snapshot,
        };
        self.job_tx
            .lock()
            .map_err(|_| "plugin runner mutex poisoned".to_string())?
            .send(Some(job))
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// Drain any completed results without blocking. Returns an empty vec if
    /// nothing has finished yet.
    pub fn poll(&self) -> Vec<ScriptResultMsg> {
        let mut out = Vec::new();
        let Ok(rx) = self.result_rx.lock() else {
            return out;
        };
        while let Ok(msg) = rx.try_recv() {
            out.push(msg);
        }
        out
    }
}

impl Default for AsyncPluginRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AsyncPluginRunner {
    fn drop(&mut self) {
        // Send the shutdown sentinel and join.
        if let Ok(tx) = self.job_tx.lock() {
            let _ = tx.send(None);
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

fn worker_loop(job_rx: Receiver<Option<ScriptJob>>, result_tx: Sender<ScriptResultMsg>) {
    use std::cell::RefCell;
    use std::rc::Rc;

    while let Ok(Some(job)) = job_rx.recv() {
        let actions: Rc<RefCell<Vec<ScriptAction>>> = Rc::new(RefCell::new(Vec::new()));
        let mut engine = Engine::new();

        // Capture closures that push into a local actions list.
        {
            let actions = actions.clone();
            engine.register_fn("rename", move |addr: i64, name: String| {
                actions.borrow_mut().push(ScriptAction::Rename {
                    address: addr as u64,
                    new_name: name,
                });
            });
        }
        {
            let actions = actions.clone();
            engine.register_fn("set_comment", move |addr: i64, text: String| {
                actions.borrow_mut().push(ScriptAction::Comment {
                    address: addr as u64,
                    text,
                });
            });
        }
        {
            let actions = actions.clone();
            engine.register_fn("println", move |msg: String| {
                actions.borrow_mut().push(ScriptAction::Print(msg));
            });
        }
        engine.register_fn("hex", |n: i64| format!("0x{:x}", n));

        // Push snapshot data into scope so scripts can iterate.
        let mut scope = Scope::new();
        let func_list: Vec<Dynamic> = job
            .snapshot
            .functions
            .iter()
            .map(|(addr, name, size)| {
                let mut m = rhai::Map::new();
                m.insert("address".into(), Dynamic::from(*addr as i64));
                m.insert("name".into(), Dynamic::from(name.clone()));
                m.insert("size".into(), Dynamic::from(*size as i64));
                Dynamic::from(m)
            })
            .collect();
        scope.push("functions", func_list);
        scope.push(
            "num_functions",
            Dynamic::from(job.snapshot.functions.len() as i64),
        );
        scope.push("arch", Dynamic::from(job.snapshot.arch.clone()));

        let eval = engine.eval_with_scope::<Dynamic>(&mut scope, &job.source);
        let collected_actions = actions.borrow().clone();
        let msg = match eval {
            Ok(value) => ScriptResultMsg {
                id: job.id,
                output: if value.is_unit() {
                    String::new()
                } else {
                    format!("{}", value)
                },
                actions: collected_actions,
                error: None,
            },
            Err(e) => ScriptResultMsg {
                id: job.id,
                output: String::new(),
                actions: collected_actions,
                error: Some(e.to_string()),
            },
        };
        if result_tx.send(msg).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_and_drain_simple_script() {
        let runner = AsyncPluginRunner::new();
        let id = runner
            .submit("println(\"hi\"); 42".into(), ProjectSnapshot::default())
            .unwrap();

        // Wait briefly for the worker to finish.
        let mut results = Vec::new();
        for _ in 0..50 {
            results = runner.poll();
            if !results.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(results.len(), 1, "expected one result");
        let msg = &results[0];
        assert_eq!(msg.id, id);
        assert_eq!(msg.output, "42");
        assert!(msg.error.is_none());
        assert_eq!(msg.actions.len(), 1);
        match &msg.actions[0] {
            ScriptAction::Print(text) => assert_eq!(text, "hi"),
            other => panic!("unexpected action: {:?}", other),
        }
    }

    #[test]
    fn iterate_function_snapshot() {
        let runner = AsyncPluginRunner::new();
        let snapshot = ProjectSnapshot {
            functions: vec![(0x1000, "main".into(), 32), (0x2000, "helper".into(), 16)],
            ..Default::default()
        };
        let source = r#"
            let count = 0;
            for f in functions {
                if f.name.starts_with("helper") {
                    rename(f.address, "renamed");
                    count += 1;
                }
            }
            count
        "#;
        let id = runner.submit(source.into(), snapshot).unwrap();
        let mut results = Vec::new();
        for _ in 0..50 {
            results = runner.poll();
            if !results.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(results.len(), 1);
        let msg = &results[0];
        assert_eq!(msg.id, id);
        assert!(msg.error.is_none(), "script error: {:?}", msg.error);
        assert_eq!(msg.actions.len(), 1);
        match &msg.actions[0] {
            ScriptAction::Rename { address, new_name } => {
                assert_eq!(*address, 0x2000);
                assert_eq!(new_name, "renamed");
            }
            other => panic!("unexpected action: {:?}", other),
        }
    }
}
