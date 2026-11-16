//! In-app presence gate for passkey assertions.
//!
//! Windows owns the system dialog, but this build has no user-verification
//! channel: nothing in the protocol proves that the person at the keyboard
//! asked for the signature. Without a gate, any process running as the same
//! user could open `\\.\pipe\kestrel-passkeys` and obtain an ES256 signature
//! for any stored credential while the vault is unlocked, and the
//! `authenticatorData` would claim user presence that never happened.
//!
//! So every assertion waits for an explicit approval in the app window, and
//! [`super::service`] sets the user-presence flag only after that approval.
//! A denial, a timeout, or no window to ask in refuses the signature.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Emitter};

/// Event the renderer listens on. The payload is the request, never a key.
pub const APPROVAL_EVENT: &str = "passkeys://approval";

/// How long a signature waits for a human. Long enough to read the prompt,
/// short enough that a stuck pipe client cannot pin the observer thread.
const TIMEOUT: Duration = Duration::from_secs(60);

struct Pending {
    id: u64,
    reply: Sender<bool>,
}

/// One approval at a time: a second request replaces the first (which is
/// answered `false`), so the window never shows two prompts that could be
/// confused for each other.
#[derive(Default)]
pub struct Approval {
    pending: Mutex<Option<Pending>>,
    next: AtomicU64,
}

impl Approval {
    /// Ask the person whether this signature may happen. Blocks the caller.
    pub fn request(&self, app: &AppHandle, rp_id: &str, account: &str) -> bool {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let (reply, answer): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        {
            let mut slot = self.pending.lock().expect("passkey approval mutex");
            if let Some(previous) = slot.take() {
                let _ = previous.reply.send(false);
            }
            *slot = Some(Pending { id, reply });
        }

        let payload = serde_json::json!({ "id": id, "rpId": rp_id, "account": account });
        if app.emit(APPROVAL_EVENT, payload).is_err() {
            self.cancel(id);
            return false;
        }

        let allowed = answer.recv_timeout(TIMEOUT).unwrap_or(false);
        if !allowed {
            self.cancel(id);
        }
        allowed
    }

    /// Answer a pending request. Returns whether `id` was the one waiting, so
    /// a late click cannot approve a request it never saw.
    pub fn answer(&self, id: u64, allow: bool) -> bool {
        let mut slot = self.pending.lock().expect("passkey approval mutex");
        let Some(pending) = slot.as_ref() else {
            return false;
        };
        if pending.id != id {
            return false;
        }
        let pending = slot.take().expect("pending approval");
        let _ = pending.reply.send(allow);
        true
    }

    /// Drop a request nobody answered, so the slot does not keep a dead sender.
    fn cancel(&self, id: u64) {
        let mut slot = self.pending.lock().expect("passkey approval mutex");
        if slot.as_ref().is_some_and(|pending| pending.id == id) {
            *slot = None;
        }
    }

    /// Refuse whatever is waiting: called when the vault locks, so a prompt
    /// cannot outlive the session it was asked in.
    pub fn cancel_all(&self) {
        let mut slot = self.pending.lock().expect("passkey approval mutex");
        if let Some(pending) = slot.take() {
            let _ = pending.reply.send(false);
        }
    }
}

/// The process-wide gate.
static APPROVAL: LazyLock<Approval> = LazyLock::new(Approval::default);

pub fn approval() -> &'static Approval {
    &APPROVAL
}
