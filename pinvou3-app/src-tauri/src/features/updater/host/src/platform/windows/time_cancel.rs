//! Cooperative stop for synchronous work on the dedicated time worker thread.
use super::pipe::Event;
use crate::error::{Error, Result};
use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

thread_local! {
    static CANCEL: RefCell<Option<(Arc<AtomicBool>, Arc<Event>)>> = const { RefCell::new(None) };
}

pub(super) fn check() -> Result<()> {
    CANCEL.with(|slot| {
        if let Some((flag, stop)) = slot.borrow().as_ref() {
            if flag.load(Ordering::Acquire) || stop.is_set()? {
                return Err(Error::TimeCanceled);
            }
        }
        Ok(())
    })
}

pub(super) struct WorkerCancelScope;
impl WorkerCancelScope {
    pub(super) fn enter(cancel: Arc<AtomicBool>, stop: Arc<Event>) -> Result<Self> {
        CANCEL.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(Error::ScopeConflict);
            }
            *slot = Some((cancel, stop));
            Ok(Self)
        })
    }
}
impl Drop for WorkerCancelScope {
    fn drop(&mut self) {
        CANCEL.with(|slot| *slot.borrow_mut() = None);
    }
}
