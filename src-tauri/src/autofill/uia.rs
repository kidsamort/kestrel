//! The UI Automation side of the picker: one observer thread that turns
//! `EVENT_OBJECT_FOCUS` into a described target, and fills through
//! `IUIAutomationValuePattern`.
//!
//! # Threading
//!
//! `SetWinEventHook` with `WINEVENT_OUTOFCONTEXT` delivers callbacks on the
//! thread that registered the hook, when that thread pumps messages. So this
//! module owns exactly one thread: it initialises COM (STA), creates the
//! `IUIAutomation` object, registers the focus and foreground hooks, and then
//! sits in a `GetMessageW` loop. The focused `IUIAutomationElement` is kept on
//! that thread's stack (thread-local context); commands arrive through a
//! channel and a posted `WM_APP` message wakes the loop. No COM pointer ever
//! crosses a thread boundary.
//!
//! Out-of-context hooks call back once per event — there is no polling. A
//! duplicate `(hwnd, idObject, idChild)` inside [`DEBOUNCE`] is ignored, so a
//! provider that fires the same focus twice cannot flicker the overlay.
//!
//! # Filling
//!
//! Only `IUIAutomationValuePattern::SetValue` is used. There is deliberately no
//! `SendInput` fallback: synthesising keystrokes into an arbitrary process is
//! indistinguishable from a keylogger, and it would bypass the integrity check
//! below. When the pattern is missing or read-only, the fill is refused with a
//! reason.
//!
//! # Integrity
//!
//! A target whose token integrity level is above ours is refused before any
//! UIA call that could be used to write. `OpenProcess` itself fails for many
//! elevated or protected processes; that failure is treated as a refusal too.
//! The pure comparison lives in [`super::integrity_allows`] and is unit-tested
//! there.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows::core::BSTR;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationValuePattern, SetWinEventHook,
    UIA_ValuePatternId, UnhookWinEvent, HWINEVENTHOOK,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetAncestor, GetForegroundWindow, GetMessageW,
    GetWindowThreadProcessId, PeekMessageW, PostThreadMessageW, SetWindowsHookExW,
    TranslateMessage, UnhookWindowsHookEx, EVENT_OBJECT_FOCUS, EVENT_SYSTEM_FOREGROUND, GA_ROOT,
    KBDLLHOOKSTRUCT, MSG, PM_NOREMOVE, WH_KEYBOARD_LL, WINEVENT_OUTOFCONTEXT,
    WINEVENT_SKIPOWNPROCESS, WM_APP, WM_KEYDOWN,
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Wake-up message for the observer thread. `WM_APP` is the first value the
/// platform reserves for applications.
const WAKE_MESSAGE: u32 = WM_APP + 0x41;
/// Same-focus events inside this window are one focus change.
const DEBOUNCE: Duration = Duration::from_millis(350);
/// Virtual-key code for Escape. `VK_ESCAPE` lives in a feature this build does
/// not enable; the value is fixed by WinUser.h.
const VK_ESCAPE: u32 = 0x1B;

/// One resolved field. Plain data: it can cross threads, unlike the COM
/// element it was read from.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Identity of the element a fill is allowed to touch. The overlay says "fill
/// this item"; the observer verifies the field is still the one it inspected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElementKey {
    pub pid: u32,
    pub hwnd: isize,
    pub automation_id: String,
    pub class_name: String,
    pub control_type: i32,
}

/// Everything the overlay and the rules care about, with no secret in it.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// Lower-case image name, e.g. `notepad.exe`.
    pub exe: String,
    pub pid: u32,
    /// Owning top-level window (the field may live in a child window).
    pub hwnd: isize,
    pub is_password: bool,
    pub control_type: &'static str,
    pub control_type_id: i32,
    pub automation_id: String,
    pub class_name: String,
    pub rect: Rect,
    /// False when the target runs above our integrity level or its token could
    /// not be read at all.
    pub integrity_ok: bool,
    pub key: ElementKey,
}

/// What the observer tells the shell about. `None` in [`Event::Focus`] means
/// the new focused element could not be described (no UIA provider, or the
/// event belonged to a window that vanished).
pub enum Event {
    Focus {
        inspection: Option<Inspection>,
    },
    Foreground {
        hwnd: isize,
    },
    /// Escape was pressed while the overlay was visible. The key is swallowed
    /// only in that state.
    Escape,
}

enum Command {
    Inspect(Sender<Option<Inspection>>),
    Fill {
        value: String,
        expect: ElementKey,
        reply: Sender<Result<(), String>>,
    },
    Gate(bool),
    Stop,
}

/// Handle to the observer thread. Cheap to hold in managed state and safe to
/// call from any thread.
pub struct Worker {
    thread_id: u32,
    /// Behind a mutex only so `Worker` is `Sync`; every send is a quick
    /// enqueue, never a wait for the observer.
    commands: Mutex<Sender<Command>>,
    gate: AtomicBool,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Worker {
    pub fn start(ours: u32, sink: impl Fn(Event) + Send + 'static) -> Result<Worker, String> {
        let (commands, inbox) = mpsc::channel::<Command>();
        let (ready, ready_rx) = mpsc::channel::<Result<u32, String>>();

        let join = std::thread::Builder::new()
            .name("autofill-uia".to_string())
            .spawn(move || observer_thread(ours, sink, inbox, ready))
            .map_err(|e| format!("could not start the UI Automation observer: {e}"))?;

        // The thread reports its id only after COM is up and the hooks are in
        // place, so a command posted after `start` is never lost.
        let thread_id = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "the UI Automation observer did not start in time".to_string())??;

        Ok(Worker {
            thread_id,
            commands: Mutex::new(commands),
            gate: AtomicBool::new(false),
            join: Mutex::new(Some(join)),
        })
    }

    /// Ask the observer for the field that has focus right now. Used by the
    /// explicit shortcut, never by a timer.
    pub fn inspect(&self) -> Option<Inspection> {
        let (tx, rx) = mpsc::channel();
        if self.send(Command::Inspect(tx)).is_err() {
            return None;
        }
        rx.recv_timeout(Duration::from_secs(2)).ok().flatten()
    }

    /// Write `value` into the element that was inspected, provided it is still
    /// the same element. The value stays in this process.
    pub fn fill(&self, value: String, expect: ElementKey) -> Result<(), String> {
        let (tx, rx) = mpsc::channel();
        self.send(Command::Fill {
            value,
            expect,
            reply: tx,
        })?;
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(result) => result,
            Err(_) => Err("the target field did not respond in time".to_string()),
        }
    }

    /// Install or remove the Escape-only keyboard hook. The hook exists only
    /// while the overlay is visible.
    pub fn set_gate(&self, open: bool) {
        if self.gate.swap(open, Ordering::SeqCst) == open {
            return;
        }
        let _ = self.send(Command::Gate(open));
    }

    fn send(&self, command: Command) -> Result<(), String> {
        self.commands
            .lock()
            .expect("autofill command mutex")
            .send(command)
            .map_err(|_| "the UI Automation observer is stopped".to_string())?;
        self.wake();
        Ok(())
    }

    fn wake(&self) {
        unsafe {
            let _ = PostThreadMessageW(self.thread_id, WAKE_MESSAGE, WPARAM(0), LPARAM(0));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.send(Command::Stop);
        if let Some(join) = self.join.lock().expect("autofill join mutex").take() {
            for _ in 0..200 {
                if join.is_finished() {
                    let _ = join.join();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            // A provider that never answers must not hang process shutdown.
            // Dropping the handle detaches the thread; the process is ending.
        }
    }
}

struct Context {
    sink: Box<dyn Fn(Event) + Send>,
    automation: IUIAutomation,
    ours: u32,
    focused: Option<IUIAutomationElement>,
    focused_key: Option<ElementKey>,
    keyboard: Option<windows::Win32::UI::WindowsAndMessaging::HHOOK>,
    last: Option<(isize, i32, i32, Instant)>,
}

thread_local! {
    /// Only the observer thread ever stores a value; the callback is invoked on
    /// that same thread, so no lock is needed and no COM pointer escapes it.
    static CONTEXT: RefCell<Option<Context>> = const { RefCell::new(None) };
}

fn observer_thread(
    ours: u32,
    sink: impl Fn(Event) + Send + 'static,
    inbox: Receiver<Command>,
    ready: Sender<Result<u32, String>>,
) {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if hr.is_err() {
            let _ = ready.send(Err(format!(
                "COM could not start on the observer thread: {hr:?}"
            )));
            return;
        }

        let automation: IUIAutomation = match CoCreateInstance(
            &CUIAutomation,
            None::<&windows::core::IUnknown>,
            CLSCTX_INPROC_SERVER,
        ) {
            Ok(value) => value,
            Err(error) => {
                CoUninitialize();
                let _ = ready.send(Err(format!("UI Automation is unavailable: {error}")));
                return;
            }
        };

        CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(Context {
                sink: Box::new(sink),
                automation,
                ours,
                focused: None,
                focused_key: None,
                keyboard: None,
                last: None,
            });
        });

        // Force the message queue into existence before returning the thread
        // id, so `PostThreadMessageW` from `start` cannot race it.
        let mut msg = MSG::default();
        let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
        let thread_id = GetCurrentThreadId();

        let focus_hook = SetWinEventHook(
            EVENT_OBJECT_FOCUS,
            EVENT_OBJECT_FOCUS,
            None,
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );
        let foreground_hook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            None,
            Some(win_event_proc),
            0,
            0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
        );

        if focus_hook.0.is_null() {
            CONTEXT.with(|cell| *cell.borrow_mut() = None);
            CoUninitialize();
            let _ = ready.send(Err(
                "Windows refused the focus hook; the picker cannot observe fields".to_string(),
            ));
            return;
        }

        if ready.send(Ok(thread_id)).is_err() {
            // Nobody is listening; clean up rather than run forever.
            let _ = UnhookWinEvent(focus_hook);
            if !foreground_hook.0.is_null() {
                let _ = UnhookWinEvent(foreground_hook);
            }
            CONTEXT.with(|cell| *cell.borrow_mut() = None);
            CoUninitialize();
            return;
        }

        'pump: loop {
            let got = GetMessageW(&mut msg, None, 0, 0);
            if got.0 == 0 || got.0 == -1 {
                break;
            }
            if msg.message == WAKE_MESSAGE {
                loop {
                    match inbox.try_recv() {
                        Ok(Command::Stop) | Err(TryRecvError::Disconnected) => break 'pump,
                        Ok(Command::Inspect(reply)) => {
                            let found = CONTEXT
                                .with(|cell| cell.borrow_mut().as_mut().and_then(inspect_locked));
                            let _ = reply.send(found);
                        }
                        Ok(Command::Fill {
                            value,
                            expect,
                            reply,
                        }) => {
                            let result = CONTEXT.with(|cell| {
                                cell.borrow_mut()
                                    .as_mut()
                                    .map(|ctx| fill_locked(ctx, value, expect))
                                    .unwrap_or_else(|| Err("the observer is not ready".to_string()))
                            });
                            let _ = reply.send(result);
                        }
                        Ok(Command::Gate(open)) => {
                            ESCAPE_GATE.with(|gate| gate.set(open));
                            CONTEXT.with(|cell| {
                                if let Some(ctx) = cell.borrow_mut().as_mut() {
                                    set_keyboard_hook(ctx, open);
                                }
                            });
                        }
                        Err(TryRecvError::Empty) => break,
                    }
                }
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = UnhookWinEvent(focus_hook);
        if !foreground_hook.0.is_null() {
            let _ = UnhookWinEvent(foreground_hook);
        }
        CONTEXT.with(|cell| {
            if let Some(mut ctx) = cell.borrow_mut().take() {
                if let Some(hook) = ctx.keyboard.take() {
                    let _ = UnhookWindowsHookEx(hook);
                }
            }
        });
        CoUninitialize();
    }
}

fn set_keyboard_hook(ctx: &mut Context, open: bool) {
    unsafe {
        match (open, ctx.keyboard) {
            (true, None) => {
                // On failure the webview still sees Escape when it has input
                // focus; the picker stays usable.
                if let Ok(hook) = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), None, 0) {
                    ctx.keyboard = Some(hook);
                }
            }
            (false, Some(hook)) => {
                let _ = UnhookWindowsHookEx(hook);
                ctx.keyboard = None;
            }
            _ => {}
        }
    }
}

unsafe extern "system" fn win_event_proc(
    _hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    id_object: i32,
    id_child: i32,
    _thread: u32,
    _time: u32,
) {
    let _ = CONTEXT.try_with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return;
        };
        let Some(ctx) = slot.as_mut() else {
            return;
        };

        if event == EVENT_SYSTEM_FOREGROUND {
            (ctx.sink)(Event::Foreground {
                hwnd: hwnd.0 as isize,
            });
            return;
        }
        if event != EVENT_OBJECT_FOCUS {
            return;
        }

        let hwnd_value = hwnd.0 as isize;
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
        if pid == 0 || pid == ctx.ours {
            // Our own overlay taking focus is not a change of target.
            return;
        }

        let signature = (hwnd_value, id_object, id_child);
        if let Some((last_hwnd, last_object, last_child, at)) = ctx.last {
            if (last_hwnd, last_object, last_child) == signature && at.elapsed() < DEBOUNCE {
                return;
            }
        }
        ctx.last = Some((hwnd_value, id_object, id_child, Instant::now()));

        let inspection = inspect_element(ctx, hwnd);
        (ctx.sink)(Event::Focus { inspection });
    });
}

unsafe extern "system" fn keyboard_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 as u32 == WM_KEYDOWN {
        let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        if info.vkCode == VK_ESCAPE && ESCAPE_GATE.with(|gate| gate.get()) {
            let _ = CONTEXT.try_with(|cell| {
                if let Ok(slot) = cell.try_borrow() {
                    if let Some(ctx) = slot.as_ref() {
                        (ctx.sink)(Event::Escape);
                    }
                }
            });
            // Swallow only Escape, only while the overlay is visible.
            return LRESULT(1);
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

thread_local! {
    /// Mirrors [`Worker::gate`] on the observer thread so the keyboard hook can
    /// decide without a lock.
    static ESCAPE_GATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Read the focused element. Keeps the element for a later fill.
fn inspect_locked(ctx: &mut Context) -> Option<Inspection> {
    unsafe {
        let element = ctx.automation.GetFocusedElement().ok()?;
        let foreground = GetForegroundWindow();
        let inspection = read_element(&element, foreground.0 as isize)?;
        if inspection.pid == ctx.ours {
            return None;
        }
        ctx.focused_key = Some(inspection.key.clone());
        ctx.focused = Some(element);
        Some(inspection)
    }
}

/// Read the focused element after an event. Falls back to the event window when
/// the element exposes no native handle.
fn inspect_element(ctx: &mut Context, event_hwnd: HWND) -> Option<Inspection> {
    unsafe {
        let element = ctx.automation.GetFocusedElement().ok()?;
        let inspection = read_element(&element, event_hwnd.0 as isize)?;
        if inspection.pid == ctx.ours {
            return None;
        }
        ctx.focused_key = Some(inspection.key.clone());
        ctx.focused = Some(element);
        Some(inspection)
    }
}

fn read_element(element: &IUIAutomationElement, event_hwnd: isize) -> Option<Inspection> {
    unsafe {
        let pid = u32::try_from(element.CurrentProcessId().ok()?).ok()?;

        let rect: RECT = element.CurrentBoundingRectangle().ok()?;
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        if width <= 0 || height <= 0 {
            // An off-screen or collapsed provider has nothing to anchor to.
            return None;
        }

        let native = element
            .CurrentNativeWindowHandle()
            .map(|handle| handle.0 as isize)
            .unwrap_or(0);
        let window = if native != 0 {
            let root = GetAncestor(HWND(native as *mut _), GA_ROOT);
            if root.0.is_null() {
                native
            } else {
                root.0 as isize
            }
        } else if event_hwnd != 0 {
            let root = GetAncestor(HWND(event_hwnd as *mut _), GA_ROOT);
            if root.0.is_null() {
                event_hwnd
            } else {
                root.0 as isize
            }
        } else {
            return None;
        };

        let control_type_id = element
            .CurrentControlType()
            .map(|kind| kind.0)
            .unwrap_or_default();
        let automation_id = element
            .CurrentAutomationId()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let class_name = element
            .CurrentClassName()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let is_password: bool = element.CurrentIsPassword().map(bool::from).unwrap_or(false);

        let exe = process_image_name(pid).unwrap_or_default();
        let integrity_ok =
            super::integrity_allows(token_integrity(pid), token_integrity(std::process::id()));

        Some(Inspection {
            exe,
            pid,
            hwnd: window,
            is_password,
            control_type: control_type_name(control_type_id),
            control_type_id,
            automation_id: automation_id.clone(),
            class_name: class_name.clone(),
            rect: Rect {
                x: rect.left,
                y: rect.top,
                width,
                height,
            },
            integrity_ok,
            key: ElementKey {
                pid,
                hwnd: window,
                automation_id,
                class_name,
                control_type: control_type_id,
            },
        })
    }
}

/// Write through the value pattern. Refusals are sentences the overlay shows;
/// they never include the value.
fn fill_locked(ctx: &mut Context, value: String, expect: ElementKey) -> Result<(), String> {
    let Some(element) = ctx.focused.as_ref() else {
        return Err("No field is selected any more.".to_string());
    };
    let Some(current_key) = ctx.focused_key.as_ref() else {
        return Err("No field is selected any more.".to_string());
    };
    if current_key != &expect {
        return Err("The focused field changed; open the picker again.".to_string());
    }

    if !super::integrity_allows(
        token_integrity(expect.pid),
        token_integrity(std::process::id()),
    ) {
        return Err(super::ELEVATED_REFUSAL.to_string());
    }

    unsafe {
        let pattern: IUIAutomationValuePattern = element
            .GetCurrentPatternAs(UIA_ValuePatternId)
            .map_err(|_| {
                "This field does not expose a value Kestrel can write; copy the item instead."
                    .to_string()
            })?;

        if pattern.CurrentIsReadOnly().map(bool::from).unwrap_or(false) {
            return Err("The field is read-only.".to_string());
        }

        let text = BSTR::from(value.as_str());
        pattern.SetValue(&text).map_err(|error| {
            format!(
                "Windows rejected the value for this field ({}). Copy the item instead.",
                error.code().0
            )
        })
    }
}

/// Lower-case image name for `pid`, or `None` when the process cannot be
/// queried (an elevated or protected target).
fn process_image_name(pid: u32) -> Option<String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let ok =
            QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size);
        let _ = CloseHandle(process);
        if ok == 0 || size == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..size as usize]);
        Some(super::normalise_exe(&path))
    }
}

/// Integrity RID from the process token (e.g. 0x2000 medium, 0x3000 high).
fn token_integrity(pid: u32) -> Option<u32> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            let _ = CloseHandle(process);
            return None;
        }

        let mut needed = 0u32;
        let _ = GetTokenInformation(
            token,
            windows_sys::Win32::Security::TokenIntegrityLevel,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            let _ = CloseHandle(token);
            let _ = CloseHandle(process);
            return None;
        }

        // `TOKEN_MANDATORY_LABEL` needs pointer alignment; a byte buffer would
        // be UB to cast. `usize` words are enough alignment for every field.
        let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0usize; words];
        let ok = GetTokenInformation(
            token,
            windows_sys::Win32::Security::TokenIntegrityLevel,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        let result = if ok == 0 {
            None
        } else {
            let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            if sid.is_null() {
                None
            } else {
                let count = *GetSidSubAuthorityCount(sid);
                if count == 0 {
                    None
                } else {
                    Some(*GetSidSubAuthority(sid, u32::from(count - 1)))
                }
            }
        };

        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
        result
    }
}

fn control_type_name(id: i32) -> &'static str {
    use windows::Win32::UI::Accessibility as uia;
    let kind = windows::Win32::UI::Accessibility::UIA_CONTROLTYPE_ID(id);
    match kind {
        uia::UIA_EditControlTypeId => "edit",
        uia::UIA_TextControlTypeId => "text",
        uia::UIA_DocumentControlTypeId => "document",
        uia::UIA_ComboBoxControlTypeId => "combo-box",
        uia::UIA_PaneControlTypeId => "pane",
        uia::UIA_ButtonControlTypeId => "button",
        uia::UIA_CustomControlTypeId => "custom",
        _ => "other",
    }
}

/// True when an element is a field the picker can write into. Password fields
/// qualify even when a provider reports a custom control type, because
/// `IsPassword` is the strongest signal available.
pub fn is_fillable(control_type_id: i32, is_password: bool) -> bool {
    use windows::Win32::UI::Accessibility as uia;
    if is_password {
        return true;
    }
    let kind = uia::UIA_CONTROLTYPE_ID(control_type_id);
    matches!(
        kind,
        uia::UIA_EditControlTypeId
            | uia::UIA_DocumentControlTypeId
            | uia::UIA_ComboBoxControlTypeId
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_fields_are_fillable_whatever_the_provider_says() {
        assert!(is_fillable(0, true));
    }

    #[test]
    fn plain_text_is_not_a_fill_target() {
        use windows::Win32::UI::Accessibility as uia;
        assert!(!is_fillable(uia::UIA_TextControlTypeId.0, false));
        assert!(is_fillable(uia::UIA_EditControlTypeId.0, false));
    }

    /// Live check, not part of the suite: launches the Win32 dialog named by
    /// `KESTREL_AUTOFILL_PROBE`, waits for the real `EVENT_OBJECT_FOCUS` hook to
    /// describe its password field, and prints what the picker received.
    ///
    /// The overlay itself is a Tauri webview and needs a running app with an
    /// unlocked vault, which a unit-test harness does not have. This test ends
    /// at the target description and the computed anchor.
    #[test]
    #[ignore = "needs KESTREL_AUTOFILL_PROBE=<path to a Win32 dialog with a password Edit>"]
    fn live_focus_probe() {
        use std::process::Command;
        use windows::Win32::UI::WindowsAndMessaging::{
            SystemParametersInfoW, SPI_GETWORKAREA, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
        };

        let probe = std::env::var("KESTREL_AUTOFILL_PROBE")
            .expect("set KESTREL_AUTOFILL_PROBE to the dialog executable");
        let mut child = Command::new(&probe)
            .spawn()
            .expect("the probe dialog starts");

        let (events, received) = mpsc::channel();
        let worker = Worker::start(std::process::id(), move |event| {
            if let Event::Focus {
                inspection: Some(inspection),
            } = event
            {
                let _ = events.send(inspection);
            }
        })
        .expect("the observer starts");

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found = None;
        while Instant::now() < deadline {
            // A console-run test may not own the foreground; ask for it so the
            // dialog's password field really receives focus.
            use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
            unsafe {
                if let Ok(dialog) = FindWindowW(
                    windows::core::w!("KestrelAutofillProbe"),
                    windows::core::w!("Kestrel autofill probe"),
                ) {
                    if !dialog.0.is_null() {
                        let _ = SetForegroundWindow(dialog);
                    }
                }
            }
            match received.recv_timeout(Duration::from_millis(250)) {
                Ok(inspection)
                    if inspection.exe == "autofilprobe.exe" && inspection.is_password =>
                {
                    found = Some(inspection);
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }

        let inspection = found
            .or_else(|| worker.inspect())
            .expect("the probe dialog's password field must be observed");

        let mut work = RECT::default();
        let work_ok = unsafe {
            SystemParametersInfoW(
                SPI_GETWORKAREA,
                0,
                Some(&mut work as *mut RECT as *mut core::ffi::c_void),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
            .is_ok()
        };

        let area = if work_ok {
            Some(Rect {
                x: work.left,
                y: work.top,
                width: work.right - work.left,
                height: work.bottom - work.top,
            })
        } else {
            None
        };
        let overlay = (super::super::WIDTH as i32, super::super::HEIGHT as i32);
        let origin = super::super::anchored_origin(inspection.rect.clone(), overlay, area.clone());

        println!(
            "LIVE target exe={} pid={} password={} control={} automation={:?} class={:?} rect={{x:{},y:{},w:{},h:{}}} integrity_ok={} work_area={:?} anchor={origin:?}",
            inspection.exe,
            inspection.pid,
            inspection.is_password,
            inspection.control_type,
            inspection.automation_id,
            inspection.class_name,
            inspection.rect.x,
            inspection.rect.y,
            inspection.rect.width,
            inspection.rect.height,
            inspection.integrity_ok,
            area,
        );

        assert_eq!(inspection.exe, "autofilprobe.exe");
        assert!(
            inspection.is_password,
            "an ES_PASSWORD Edit is a password field"
        );
        assert_eq!(inspection.control_type, "edit");
        assert!(inspection.integrity_ok, "same user, same integrity");
        assert!(inspection.rect.width > 0 && inspection.rect.height > 0);

        if let Some(area) = area {
            assert!(
                origin.0 >= area.x
                    && origin.1 >= area.y
                    && origin.0 + overlay.0 <= area.x + area.width
                    && origin.1 + overlay.1 <= area.y + area.height,
                "the overlay anchor must stay inside the work area"
            );
        }

        let _ = child.kill();
        let _ = child.wait();
    }
}
