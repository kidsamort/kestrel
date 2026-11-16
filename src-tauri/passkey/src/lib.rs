//! WebAuthn credential engine.
//!
//! CBOR/COSE encoding, credential creation and assertion live here, away from
//! the COM surface, so they can be tested against published vectors. The vault
//! owns the key material; this crate never sees a master key.
//!
//! The crate has two consumers:
//!
//! * the Kestrel shell, which parses CTAP2 requests, resolves the credential
//!   through the core and writes the CTAP2 response back down the pipe;
//! * `kestrel_passkey.dll`, the in-process COM server Windows loads when the
//!   user has registered the plugin. The DLL contains no vault code: it trades
//!   CBOR frames with the shell over `\\.\pipe\kestrel-passkeys` and returns the
//!   result to WebAuthn.

pub mod cbor;
pub mod cose;
pub mod ipc;
pub mod webauthn;
#[cfg(windows)]
pub mod registry;

#[cfg(windows)]
mod com;

/// Stable AAGUID for Kestrel credentials. It is an identifier, not a secret;
/// the value is the canonical big-endian form of
/// `6b9a7c4e-1f2d-4e83-9b6a-3c5d7e8f9a01`, the same UUID used as the COM CLSID
/// so a credential and its COM registration are recognisably the same product.
pub const AAGUID: [u8; 16] = [
    0x6b, 0x9a, 0x7c, 0x4e, 0x1f, 0x2d, 0x4e, 0x83, 0x9b, 0x6a, 0x3c, 0x5d, 0x7e, 0x8f, 0x9a, 0x01,
];

/// The COM class id the registration command writes under
/// `HKCU\Software\Classes\CLSID`. Windows resolves this to the DLL.
pub const PLUGIN_CLSID_TEXT: &str = "6b9a7c4e-1f2d-4e83-9b6a-3c5d7e8f9a01";

/// `IID_IPluginAuthenticator` from `pluginauthenticator.idl`.
pub const IID_PLUGIN_AUTHENTICATOR_TEXT: &str = "d26bcf6f-b54c-43ff-9f06-d5bf148625f7";

/// The authenticator's display name in the Windows WebAuthn UI.
pub const PLUGIN_DISPLAY_NAME: &str = "Kestrel";

/// The named pipe the COM server uses to reach the running vault.
pub const PIPE_PATH: &str = ipc::PIPE_PATH;
