//! The shell dialogs: pick a folder, pick a file, choose where to save.
//!
//! A vault lives in a folder the user picks, and typing that path by hand is
//! both hostile and error-prone — the same is true of the vault file itself and
//! of the recovery kit. The shell's own dialogs are the right answer, so this
//! module drives `IFileOpenDialog` and `IFileSaveDialog` through the generated
//! `windows` bindings. No dialog crate is involved, and no hand-written vtable.
//!
//! A Tauri command runs on a pool thread, which has never touched COM, so the
//! apartment is entered here and left again through a guard: every return path
//! — success, cancel, failure — balances its `CoInitializeEx`.

use std::path::{Path, PathBuf};

/// A start directory only counts when it still exists as a directory.
///
/// `SetFolder` fails on a file or a vanished folder, and a dialog that opens at
/// its default location is a better outcome than an error the user cannot act
/// on. Keeping the rule in one small function also makes it testable without
/// showing anything.
pub fn usable_start(start: Option<&Path>) -> Option<&Path> {
    start.filter(|path| path.is_dir())
}

#[cfg(windows)]
use windows::core::{HRESULT, HSTRING, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_CANCELLED, RPC_E_CHANGED_MODE};
#[cfg(windows)]
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IBindCtx,
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName, FOS_FILEMUSTEXIST,
    FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST, FOS_PICKFOLDERS,
    SIGDN_FILESYSPATH,
};

/// Balances one successful `CoInitializeEx`, however `pick_folder` returns.
///
/// The flag is false when another library had already put the thread in an
/// apartment: COM is then usable, but the balancing call belongs to that
/// library, not to this one.
#[cfg(windows)]
struct ComApartment(bool);

#[cfg(windows)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: the pairing call for the successful `CoInitializeEx` in
            // `enter_com`; the guard runs exactly once.
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(windows)]
fn enter_com() -> Result<ComApartment, String> {
    // SAFETY: no reserved value, apartment-threaded because the dialog is a
    // modal window owned by this thread.
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if hr == RPC_E_CHANGED_MODE {
        // Somebody else initialised this thread in the other mode. The picker
        // works there too, so carry on without claiming the uninitialise.
        return Ok(ComApartment(false));
    }
    if hr.is_err() {
        return Err(format!("COM could not start on this thread: {hr:?}"));
    }
    Ok(ComApartment(true))
}

/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`, 0x800704C7: the one failure that means
/// the user pressed Cancel rather than that the dialog broke.
#[cfg(windows)]
fn cancelled() -> HRESULT {
    HRESULT::from_win32(ERROR_CANCELLED.0)
}

/// One directory as a shell item, so the dialog can open there.
#[cfg(windows)]
fn folder_item(path: &Path) -> windows::core::Result<IShellItem> {
    // SAFETY: the path outlives the call as a temporary `HSTRING`, and a bind
    // context is optional.
    unsafe { SHCreateItemFromParsingName(&HSTRING::from(path), None::<&IBindCtx>) }
}

/// Show the Windows folder picker. `Ok(None)` means the user cancelled.
/// `start` is where the dialog opens, when it is an existing directory.
#[cfg(windows)]
pub fn pick_folder(title: &str, start: Option<&Path>) -> Result<Option<PathBuf>, String> {
    let _apartment = enter_com()?;

    // SAFETY: COM is initialised above, and `FileOpenDialog` is a system CLSID
    // with no aggregation.
    let dialog: IFileOpenDialog = unsafe {
        CoCreateInstance(
            &FileOpenDialog,
            None::<&windows::core::IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|error| format!("the folder picker could not be created: {error}"))?;

    let options = FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST;
    // SAFETY: a live dialog owned by this thread.
    unsafe { dialog.SetOptions(options) }
        .map_err(|error| format!("the folder picker refused its options: {error}"))?;
    // SAFETY: a live dialog; the title is copied by the shell during the call.
    unsafe { dialog.SetTitle(&HSTRING::from(title)) }
        .map_err(|error| format!("the folder picker refused its title: {error}"))?;

    if let Some(folder) = usable_start(start).and_then(|path| folder_item(path).ok()) {
        // A folder that does not resolve is not fatal: the dialog simply opens
        // at its default location instead.
        let _ = unsafe { dialog.SetFolder(&folder) };
    }

    // SAFETY: a live dialog shown on its own apartment; `None` lets the shell
    // parent it to the foreground window.
    match unsafe { dialog.Show(None) } {
        Ok(()) => {}
        Err(error) if error.code() == cancelled() => return Ok(None),
        Err(error) => return Err(format!("the folder picker failed: {error}")),
    }

    // SAFETY: a live dialog whose modal loop just returned success.
    let item: IShellItem = unsafe { dialog.GetResult() }
        .map_err(|error| format!("the folder picker returned no selection: {error}"))?;
    // SAFETY: a live shell item. `FOS_FORCEFILESYSTEM` is set, so a filesystem
    // path is expected; anything else fails here instead of panicking.
    let name: PWSTR = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.map_err(|error| {
        format!("the folder picker returned an item with no filesystem path: {error}")
    })?;
    if name.is_null() {
        return Err("the folder picker returned an empty path".to_string());
    }

    // SAFETY: `GetDisplayName` returned a NUL-terminated string allocated by the
    // shell; copying it out is the only way to own it.
    let text = unsafe { name.to_string() };
    // SAFETY: the same shell allocation, freed exactly once and no longer used.
    unsafe { CoTaskMemFree(Some(name.as_ptr() as *const core::ffi::c_void)) };
    let text = text.map_err(|_| "the folder picker returned a path that is not valid text")?;
    Ok(Some(PathBuf::from(text)))
}

/// Show the Windows open dialog for one file type. `Ok(None)` is Cancel.
#[cfg(windows)]
pub fn pick_file(
    title: &str,
    filter_name: &str,
    filter_pattern: &str,
) -> Result<Option<PathBuf>, String> {
    use windows::Win32::UI::Shell::{
        FileOpenDialog, IFileOpenDialog, IShellItem, SIGDN_FILESYSPATH,
    };

    let _apartment = enter_com()?;
    // SAFETY: COM is initialised above; `FileOpenDialog` is a system CLSID.
    let dialog: IFileOpenDialog = unsafe {
        CoCreateInstance(
            &FileOpenDialog,
            None::<&windows::core::IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|error| format!("the file picker could not be created: {error}"))?;

    let (name, pattern) = (HSTRING::from(filter_name), HSTRING::from(filter_pattern));
    let spec = windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC {
        pszName: windows::core::PCWSTR(name.as_ptr()),
        pszSpec: windows::core::PCWSTR(pattern.as_ptr()),
    };
    // SAFETY: a live dialog; the filter strings outlive the call.
    unsafe { dialog.SetFileTypes(&[spec]) }
        .map_err(|error| format!("the file picker refused its filter: {error}"))?;
    // SAFETY: a live dialog; the title is copied during the call.
    unsafe { dialog.SetTitle(&HSTRING::from(title)) }
        .map_err(|error| format!("the file picker refused its title: {error}"))?;
    // SAFETY: a live dialog; no forced options — a file is what we want.
    unsafe { dialog.SetOptions(FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_FILEMUSTEXIST) }
        .map_err(|error| format!("the file picker refused its options: {error}"))?;

    // SAFETY: a live dialog shown on its own apartment.
    match unsafe { dialog.Show(None) } {
        Ok(()) => {}
        Err(error) if error.code() == cancelled() => return Ok(None),
        Err(error) => return Err(format!("the file picker failed: {error}")),
    }
    // SAFETY: a live dialog whose modal loop returned success.
    let item: IShellItem = unsafe { dialog.GetResult() }
        .map_err(|error| format!("the file picker returned no selection: {error}"))?;
    // SAFETY: a live shell item; a filesystem path is expected.
    let name: PWSTR = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }
        .map_err(|error| format!("the file picker returned no path: {error}"))?;
    if name.is_null() {
        return Err("the file picker returned an empty path".to_string());
    }
    // SAFETY: a NUL-terminated shell allocation; copied, then freed once.
    let text = unsafe { name.to_string() };
    // SAFETY: the same allocation, no longer used.
    unsafe { CoTaskMemFree(Some(name.as_ptr() as *const core::ffi::c_void)) };
    let text = text.map_err(|_| "the file picker returned text that is not valid")?;
    Ok(Some(PathBuf::from(text)))
}

/// Show the Windows save dialog. `Ok(None)` is Cancel.
#[cfg(windows)]
pub fn save_file(
    title: &str,
    suggested_name: &str,
    filter_name: &str,
    filter_pattern: &str,
) -> Result<Option<PathBuf>, String> {
    use windows::Win32::UI::Shell::{FileSaveDialog, IFileSaveDialog, SIGDN_FILESYSPATH};

    let _apartment = enter_com()?;
    // SAFETY: COM is initialised above; `FileSaveDialog` is a system CLSID.
    let dialog: IFileSaveDialog = unsafe {
        CoCreateInstance(
            &FileSaveDialog,
            None::<&windows::core::IUnknown>,
            CLSCTX_INPROC_SERVER,
        )
    }
    .map_err(|error| format!("the save dialog could not be created: {error}"))?;

    let (name, pattern) = (HSTRING::from(filter_name), HSTRING::from(filter_pattern));
    let spec = windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC {
        pszName: windows::core::PCWSTR(name.as_ptr()),
        pszSpec: windows::core::PCWSTR(pattern.as_ptr()),
    };
    // SAFETY: a live dialog; the filter strings outlive the call.
    unsafe { dialog.SetFileTypes(&[spec]) }
        .map_err(|error| format!("the save dialog refused its filter: {error}"))?;
    // SAFETY: a live dialog; the title and file name are copied during the call.
    unsafe { dialog.SetTitle(&HSTRING::from(title)) }
        .map_err(|error| format!("the save dialog refused its title: {error}"))?;
    unsafe { dialog.SetFileName(&HSTRING::from(suggested_name)) }
        .map_err(|error| format!("the save dialog refused its file name: {error}"))?;
    // SAFETY: a live dialog; the overwrite prompt is the shell's, not ours.
    unsafe { dialog.SetDefaultExtension(&HSTRING::from("pdf")) }
        .map_err(|error| format!("the save dialog refused its extension: {error}"))?;
    unsafe { dialog.SetOptions(FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_OVERWRITEPROMPT) }
        .map_err(|error| format!("the save dialog refused its options: {error}"))?;

    // SAFETY: a live dialog shown on its own apartment.
    match unsafe { dialog.Show(None) } {
        Ok(()) => {}
        Err(error) if error.code() == cancelled() => return Ok(None),
        Err(error) => return Err(format!("the save dialog failed: {error}")),
    }
    // SAFETY: a live dialog whose modal loop returned success.
    let item = unsafe { dialog.GetResult() }
        .map_err(|error| format!("the save dialog returned no selection: {error}"))?;
    // SAFETY: a live shell item; a filesystem path is expected.
    let name: PWSTR = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }
        .map_err(|error| format!("the save dialog returned no path: {error}"))?;
    if name.is_null() {
        return Err("the save dialog returned an empty path".to_string());
    }
    // SAFETY: a NUL-terminated shell allocation; copied, then freed once.
    let text = unsafe { name.to_string() };
    // SAFETY: the same allocation, no longer used.
    unsafe { CoTaskMemFree(Some(name.as_ptr() as *const core::ffi::c_void)) };
    let text = text.map_err(|_| "the save dialog returned text that is not valid")?;
    Ok(Some(PathBuf::from(text)))
}

/// The picker is a shell dialog, so there is nothing to show on another OS.
#[cfg(not(windows))]
pub fn pick_folder(_title: &str, _start: Option<&Path>) -> Result<Option<PathBuf>, String> {
    Err("the folder picker is Windows only".to_string())
}

#[cfg(not(windows))]
pub fn pick_file(
    _title: &str,
    _filter_name: &str,
    _filter_pattern: &str,
) -> Result<Option<PathBuf>, String> {
    Err("the file picker is Windows only".to_string())
}

#[cfg(not(windows))]
pub fn save_file(
    _title: &str,
    _suggested_name: &str,
    _filter_name: &str,
    _filter_pattern: &str,
) -> Result<Option<PathBuf>, String> {
    Err("the save dialog is Windows only".to_string())
}

#[cfg(test)]
mod tests {
    use super::usable_start;
    use std::path::{Path, PathBuf};

    /// A private tree under the system temp directory, removed on drop so a
    /// failing assertion cannot leave anything behind.
    struct Tree(PathBuf);

    impl Tree {
        fn new(name: &str) -> Tree {
            let root = std::env::temp_dir().join(format!(
                "kestrel-folder-picker-{}-{name}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            Tree(root)
        }

        fn dir(&self, relative: &str) -> PathBuf {
            let path = self.0.join(relative);
            std::fs::create_dir_all(&path).expect("test tree should be creatable");
            path
        }

        fn file(&self, relative: &str) -> PathBuf {
            let path = self.0.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("test tree should be creatable");
            }
            std::fs::write(&path, b"not a folder").expect("test file should be writable");
            path
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_existing_directory_is_a_usable_start() {
        let tree = Tree::new("dir");
        let folder = tree.dir("vaults");
        assert_eq!(usable_start(Some(&folder)), Some(folder.as_path()));
    }

    #[test]
    fn a_file_is_not_a_usable_start() {
        let tree = Tree::new("file");
        let file = tree.file("vault.db");
        assert_eq!(usable_start(Some(&file)), None);
    }

    #[test]
    fn a_missing_path_is_not_a_usable_start() {
        let tree = Tree::new("missing");
        let missing: &Path = &tree.0.join("never-created");
        assert!(!missing.exists());
        assert_eq!(usable_start(Some(missing)), None);
    }

    #[test]
    fn no_start_at_all_is_not_a_usable_start() {
        assert_eq!(usable_start(None), None);
    }
}
