//! The Windows in-process COM server.
//!
//! Windows resolves the registered CLSID to this DLL and asks for
//! `IPluginAuthenticator`; the methods below forward the CTAP2 bytes to the
//! Kestrel process over [`crate::ipc`] and copy the answer into a COM task
//! allocation. Nothing in this module reads a credential or a key: the DLL is
//! loaded into the WebAuthn broker's process, which has no vault.
//!
//! The vtables are written by hand because the `windows` crate does not carry
//! `pluginauthenticator.h`. Their layout matches the C declarations in
//! `pluginauthenticator.idl` and `webauthnplugin.h`.

use crate::ipc;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

const S_OK: i32 = 0;
const S_FALSE: i32 = 1;
const E_POINTER: i32 = 0x8000_4003u32 as i32;
const E_NOINTERFACE: i32 = 0x8000_4002u32 as i32;
const E_FAIL: i32 = 0x8000_4005u32 as i32;
const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
const E_OUTOFMEMORY: i32 = 0x8007_000Eu32 as i32;
const CLASS_E_CLASSNOTAVAILABLE: i32 = 0x8004_0111u32 as i32;

// COM's task allocator; the caller (Windows) frees these buffers with
// `CoTaskMemFree` after the method returns.
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemAlloc(size: usize) -> *mut c_void;
}

/// A GUID in its in-memory Win32 layout (little-endian first three fields).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const IID_UNKNOWN: Guid = Guid {
    data1: 0x0000_0000,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_CLASS_FACTORY: Guid = Guid {
    data1: 0x0000_0001,
    data2: 0x0000,
    data3: 0x0000,
    data4: [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
};

const IID_PLUGIN_AUTHENTICATOR: Guid = Guid {
    data1: 0xd26b_cf6f,
    data2: 0xb54c,
    data3: 0x43ff,
    data4: [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7],
};

const CLSID_KESTREL: Guid = Guid {
    data1: 0x6b9a_7c4e,
    data2: 0x1f2d,
    data3: 0x4e83,
    data4: [0x9b, 0x6a, 0x3c, 0x5d, 0x7e, 0x8f, 0x9a, 0x01],
};

#[repr(C)]
struct OperationRequest {
    hwnd: *mut c_void,
    transaction_id: Guid,
    cb_request_signature: u32,
    pb_request_signature: *mut u8,
    request_type: u32,
    cb_encoded_request: u32,
    pb_encoded_request: *mut u8,
}

#[repr(C)]
struct OperationResponse {
    cb_encoded_response: u32,
    pb_encoded_response: *mut u8,
}

#[repr(C)]
struct CancelOperationRequest {
    transaction_id: Guid,
    cb_request_signature: u32,
    pb_request_signature: *mut u8,
}

#[repr(C)]
struct AuthenticatorVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    make_credential: unsafe extern "system" fn(
        *mut c_void,
        *const OperationRequest,
        *mut OperationResponse,
    ) -> i32,
    get_assertion: unsafe extern "system" fn(
        *mut c_void,
        *const OperationRequest,
        *mut OperationResponse,
    ) -> i32,
    cancel_operation:
        unsafe extern "system" fn(*mut c_void, *const CancelOperationRequest) -> i32,
    get_lock_status: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
}

#[repr(C)]
struct Authenticator {
    // The vtable pointer must be the first field: COM hands the address of the
    // whole struct back as the interface pointer.
    vtbl: *const AuthenticatorVtbl,
    refs: AtomicU32,
}

static AUTHENTICATOR_VTBL: AuthenticatorVtbl = AuthenticatorVtbl {
    query_interface: authenticator_query_interface,
    add_ref: authenticator_add_ref,
    release: authenticator_release,
    make_credential: authenticator_make_credential,
    get_assertion: authenticator_get_assertion,
    cancel_operation: authenticator_cancel_operation,
    get_lock_status: authenticator_get_lock_status,
};

#[repr(C)]
struct ClassFactoryVtbl {
    query_interface:
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> i32,
    add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    release: unsafe extern "system" fn(*mut c_void) -> u32,
    create_instance:
        unsafe extern "system" fn(*mut c_void, *mut c_void, *const Guid, *mut *mut c_void) -> i32,
    lock_server: unsafe extern "system" fn(*mut c_void, i32) -> i32,
}

#[repr(C)]
struct ClassFactory {
    vtbl: *const ClassFactoryVtbl,
    refs: AtomicU32,
}

static CLASS_FACTORY_VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
    query_interface: factory_query_interface,
    add_ref: factory_add_ref,
    release: factory_release,
    create_instance: factory_create_instance,
    lock_server: factory_lock_server,
};

/* ------------------------------------------------------------- authenticator */

unsafe extern "system" fn authenticator_query_interface(
    this: *mut c_void,
    riid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() || riid.is_null() {
        return E_POINTER;
    }
    let iid = &*riid;
    if iid != &IID_UNKNOWN && iid != &IID_PLUGIN_AUTHENTICATOR {
        *out = ptr::null_mut();
        return E_NOINTERFACE;
    }
    authenticator_add_ref(this);
    *out = this;
    S_OK
}

unsafe extern "system" fn authenticator_add_ref(this: *mut c_void) -> u32 {
    let object = &*(this as *const Authenticator);
    object.refs.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn authenticator_release(this: *mut c_void) -> u32 {
    let object = &*(this as *const Authenticator);
    let remaining = object.refs.fetch_sub(1, Ordering::SeqCst) - 1;
    if remaining == 0 {
        drop(Box::from_raw(this as *mut Authenticator));
    }
    remaining
}

/// Forward one CTAP2 operation and copy the reply into task memory.
unsafe fn forward(
    request: *const OperationRequest,
    response: *mut OperationResponse,
    op: u8,
) -> i32 {
    if request.is_null() || response.is_null() {
        return E_POINTER;
    }
    let request = &*request;
    // `WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR` is the only encoding this ABI
    // defines, and the only one this engine speaks.
    if request.request_type != 1 {
        return E_INVALIDARG;
    }
    if request.cb_encoded_request as usize > ipc::MAX_FRAME {
        return E_INVALIDARG;
    }
    if request.pb_encoded_request.is_null() && request.cb_encoded_request != 0 {
        return E_POINTER;
    }
    let payload: &[u8] = if request.cb_encoded_request == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(
            request.pb_encoded_request,
            request.cb_encoded_request as usize,
        )
    };

    // A panic must not unwind into the WebAuthn broker's COM call.
    let answer = catch_unwind(AssertUnwindSafe(|| ipc::call(op, payload)));
    let (status, body) = match answer {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) | Err(_) => return E_FAIL,
    };
    if status != ipc::STATUS_OK {
        // The shell maps a locked vault to STATUS_LOCKED; both are failures at
        // the COM boundary, and Windows will surface the ceremony error.
        return E_FAIL;
    }

    (*response).cb_encoded_response = body.len() as u32;
    if body.is_empty() {
        (*response).pb_encoded_response = ptr::null_mut();
        return S_OK;
    }
    let buffer = CoTaskMemAlloc(body.len());
    if buffer.is_null() {
        (*response).cb_encoded_response = 0;
        (*response).pb_encoded_response = ptr::null_mut();
        return E_OUTOFMEMORY;
    }
    ptr::copy_nonoverlapping(body.as_ptr(), buffer as *mut u8, body.len());
    (*response).pb_encoded_response = buffer as *mut u8;
    S_OK
}

unsafe extern "system" fn authenticator_make_credential(
    _this: *mut c_void,
    request: *const OperationRequest,
    response: *mut OperationResponse,
) -> i32 {
    forward(request, response, ipc::OP_MAKE_CREDENTIAL)
}

unsafe extern "system" fn authenticator_get_assertion(
    _this: *mut c_void,
    request: *const OperationRequest,
    response: *mut OperationResponse,
) -> i32 {
    forward(request, response, ipc::OP_GET_ASSERTION)
}

unsafe extern "system" fn authenticator_cancel_operation(
    _this: *mut c_void,
    _request: *const CancelOperationRequest,
) -> i32 {
    // Calls are synchronous: by the time Windows can ask to cancel, there is no
    // in-flight operation this DLL owns. Answering S_OK is the honest reply.
    S_OK
}

unsafe extern "system" fn authenticator_get_lock_status(
    _this: *mut c_void,
    status: *mut u32,
) -> i32 {
    if status.is_null() {
        return E_POINTER;
    }
    *status = if ipc::query_locked() { 0 } else { 1 };
    S_OK
}

/* ------------------------------------------------------------- class factory */

unsafe extern "system" fn factory_query_interface(
    this: *mut c_void,
    riid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() || riid.is_null() {
        return E_POINTER;
    }
    let iid = &*riid;
    if iid != &IID_UNKNOWN && iid != &IID_CLASS_FACTORY {
        *out = ptr::null_mut();
        return E_NOINTERFACE;
    }
    factory_add_ref(this);
    *out = this;
    S_OK
}

unsafe extern "system" fn factory_add_ref(this: *mut c_void) -> u32 {
    let object = &*(this as *const ClassFactory);
    object.refs.fetch_add(1, Ordering::SeqCst) + 1
}

unsafe extern "system" fn factory_release(this: *mut c_void) -> u32 {
    let object = &*(this as *const ClassFactory);
    let remaining = object.refs.fetch_sub(1, Ordering::SeqCst) - 1;
    if remaining == 0 {
        drop(Box::from_raw(this as *mut ClassFactory));
    }
    remaining
}

unsafe extern "system" fn factory_create_instance(
    _this: *mut c_void,
    outer: *mut c_void,
    riid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() || riid.is_null() {
        return E_POINTER;
    }
    // Aggregation is not supported by this server; the contract allows a plain
    // refusal when the caller asks for it.
    if !outer.is_null() {
        return CLASS_E_NOAGGREGATION;
    }
    let iid = &*riid;
    if iid != &IID_UNKNOWN && iid != &IID_PLUGIN_AUTHENTICATOR {
        *out = ptr::null_mut();
        return E_NOINTERFACE;
    }
    let object = Box::new(Authenticator {
        vtbl: &AUTHENTICATOR_VTBL,
        refs: AtomicU32::new(1),
    });
    *out = Box::into_raw(object) as *mut c_void;
    S_OK
}

const CLASS_E_NOAGGREGATION: i32 = 0x8004_0110u32 as i32;

unsafe extern "system" fn factory_lock_server(_this: *mut c_void, _lock: i32) -> i32 {
    S_OK
}

/* ------------------------------------------------------------------- exports */

/// `DllGetClassObject`: the only entry point Windows needs from an in-process
/// COM server. `DllRegisterServer` is deliberately absent — the app writes the
/// HKCU registration behind an explicit command, never at install time.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const Guid,
    riid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    if clsid.is_null() || riid.is_null() || out.is_null() {
        return E_POINTER;
    }
    if *clsid != CLSID_KESTREL {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let iid = &*riid;
    if iid != &IID_UNKNOWN && iid != &IID_CLASS_FACTORY {
        *out = ptr::null_mut();
        return E_NOINTERFACE;
    }
    let factory = Box::new(ClassFactory {
        vtbl: &CLASS_FACTORY_VTBL,
        refs: AtomicU32::new(1),
    });
    *out = Box::into_raw(factory) as *mut c_void;
    S_OK
}

/// Staying loaded is always valid. Returning `S_OK` while a client still holds
/// an interface would let COM unload code that is about to run.
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> i32 {
    S_FALSE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_have_the_documented_memory_layout() {
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        let bytes = CLSID_KESTREL.data4;
        assert_eq!(bytes[0], 0x9b);
        assert_eq!(IID_PLUGIN_AUTHENTICATOR.data1, 0xd26b_cf6f);
    }

    #[test]
    fn struct_layouts_match_the_c_headers() {
        // x64 sizes from pluginauthenticator.idl. A change here would silently
        // misread the request Windows hands us.
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        assert_eq!(std::mem::size_of::<OperationResponse>(), 16);
        assert_eq!(std::mem::size_of::<CancelOperationRequest>(), 32);
        assert_eq!(std::mem::size_of::<OperationRequest>(), 56);
    }
}
