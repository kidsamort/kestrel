//! WebAuthn / CTAP2 byte assembly: authenticator data, attestation `none`,
//! assertions, and credential identifiers.
//!
//! Every layout here is pinned by a test with exact bytes. The functions take
//! the private key only where a signature is produced; nothing in this module
//! keeps key material or touches a vault.

use crate::cbor::{self, Value};
use crate::cose::{CoseError, CoseKey, SigningMaterial};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// User presence: the person approved this operation.
pub const FLAG_UP: u8 = 0x01;
/// User verification: a PIN or biometric actually verified the person. Kestrel
/// does not claim this from an unlocked vault alone, so it stays clear unless a
/// caller has a real verification result to report.
pub const FLAG_UV: u8 = 0x04;
/// Attested credential data follows the fixed header.
pub const FLAG_AT: u8 = 0x40;
/// Extension data follows. This engine emits none.
pub const FLAG_ED: u8 = 0x80;

/// Length of the relying-party id hash and the AAGUID.
pub const RP_ID_HASH_LEN: usize = 32;
pub const AAGUID_LEN: usize = 16;
/// A credential id is opaque to the relying party, which only echoes it back.
/// WebAuthn allows 16..=1024 bytes; 32 random bytes is our choice: far past
/// collision, still small enough to travel in every request.
pub const CREDENTIAL_ID_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    Cbor(crate::cbor::CborError),
    Cose(CoseError),
    /// Every credential id in the request was excluded, so a new one was not
    /// created. Mirrors CTAP2 `CTAP2_ERR_CREDENTIAL_EXCLUDED`.
    CredentialExcluded,
    /// The requested algorithm is not ES256.
    UnsupportedAlgorithm(i64),
    /// A required CTAP2 member is absent or has the wrong type.
    BadRequest(&'static str),
    /// No credential id was supplied to an assertion.
    MissingCredential,
    /// The signature does not verify against the credential's public key.
    BadSignature,
    /// A signature blob is not a canonical DER ECDSA signature.
    MalformedSignature,
}

impl From<crate::cbor::CborError> for WebAuthnError {
    fn from(value: crate::cbor::CborError) -> Self {
        WebAuthnError::Cbor(value)
    }
}

impl From<CoseError> for WebAuthnError {
    fn from(value: CoseError) -> Self {
        WebAuthnError::Cose(value)
    }
}

impl std::fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebAuthnError::Cbor(error) => write!(f, "{error}"),
            WebAuthnError::Cose(error) => write!(f, "{error}"),
            WebAuthnError::CredentialExcluded => f.write_str("credential is excluded"),
            WebAuthnError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported credential algorithm {alg}")
            }
            WebAuthnError::BadRequest(what) => write!(f, "malformed CTAP2 request: {what}"),
            WebAuthnError::MissingCredential => f.write_str("assertion names no credential"),
            WebAuthnError::BadSignature => f.write_str("assertion signature does not verify"),
            WebAuthnError::MalformedSignature => f.write_str("malformed ECDSA signature"),
        }
    }
}

impl std::error::Error for WebAuthnError {}

/// The fixed part of `authenticatorData` plus optional attested data.
#[derive(Debug, Clone)]
pub struct AuthenticatorData<'a> {
    pub rp_id_hash: [u8; RP_ID_HASH_LEN],
    pub flags: u8,
    /// Monotonic per credential. Starts at 0 for a newly created credential.
    pub sign_count: u32,
    /// Present exactly when [`FLAG_AT`] is set.
    pub attested: Option<(&'a [u8], &'a CoseKey)>,
    /// Raw extension CBOR, present exactly when [`FLAG_ED`] is set.
    pub extensions: Option<&'a [u8]>,
}

impl AuthenticatorData<'_> {
    /// Serialise the exact byte layout the relying party hashes and parses.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            RP_ID_HASH_LEN
                + 1
                + 4
                + self
                    .attested
                    .map_or(0, |(id, _)| AAGUID_LEN + 2 + id.len() + 77)
                + self.extensions.map_or(0, <[u8]>::len),
        );
        out.extend_from_slice(&self.rp_id_hash);
        out.push(self.flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());
        if let Some((credential_id, key)) = self.attested {
            debug_assert!(self.flags & FLAG_AT != 0);
            debug_assert!(credential_id.len() <= u16::MAX as usize);
            out.extend_from_slice(&crate::AAGUID);
            out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
            out.extend_from_slice(credential_id);
            out.extend_from_slice(&key.to_bytes());
        }
        if let Some(extensions) = self.extensions {
            debug_assert!(self.flags & FLAG_ED != 0);
            out.extend_from_slice(extensions);
        }
        out
    }
}

/// SHA-256 over the RP id, as `authenticatorData` stores it.
pub fn rp_id_hash(rp_id: &str) -> [u8; RP_ID_HASH_LEN] {
    let digest = Sha256::digest(rp_id.as_bytes());
    let mut out = [0u8; RP_ID_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Generate a fresh credential identifier. Random and opaque; it is the lookup
/// key in the vault, not a secret.
pub fn generate_credential_id() -> [u8; CREDENTIAL_ID_LEN] {
    use rand::RngCore;
    let mut id = [0u8; CREDENTIAL_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

/// `attestationObject` with `fmt: "none"` and an empty `attStmt`.
pub fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(Vec::new())),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]))
}

/// The DER-encoded ES256 signature over `authenticatorData || clientDataHash`.
///
/// WebAuthn assertion signatures cover exactly that concatenation; hashing
/// happens inside the ECDSA signer (SHA-256).
pub fn sign_assertion(
    key: &SigningMaterial,
    auth_data: &[u8],
    client_data_hash: &[u8],
) -> Result<Vec<u8>, WebAuthnError> {
    let mut message = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    message.extend_from_slice(auth_data);
    message.extend_from_slice(client_data_hash);
    let signature: Signature = key.signing_key().sign(&message);
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Verify an assertion signature against the credential's public key. Used by
/// the tests and by the host before it accepts a stored credential response.
pub fn verify_assertion(
    key: &CoseKey,
    auth_data: &[u8],
    client_data_hash: &[u8],
    signature: &[u8],
) -> Result<(), WebAuthnError> {
    let signature =
        Signature::from_der(signature).map_err(|_| WebAuthnError::MalformedSignature)?;
    let mut message = Vec::with_capacity(auth_data.len() + client_data_hash.len());
    message.extend_from_slice(auth_data);
    message.extend_from_slice(client_data_hash);
    let verifying: VerifyingKey = key.verifying_key()?;
    verifying
        .verify(&message, &signature)
        .map_err(|_| WebAuthnError::BadSignature)
}

/* ------------------------------------------------------------- CTAP2 request */

/// The subset of `authenticatorMakeCredential` Kestrel needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// Algorithm ids from `pubKeyCredParams`, in request order.
    pub algorithms: Vec<i64>,
    /// Credential ids the platform refuses to duplicate.
    pub exclude_list: Vec<Vec<u8>>,
    /// `rk`: the credential should be discoverable.
    pub require_resident_key: bool,
    /// `uv`: the relying party requires user verification.
    pub require_uv: bool,
}

/// The subset of `authenticatorGetAssertion` Kestrel needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Vec<Vec<u8>>,
    pub require_uv: bool,
}

/// Parse `authenticatorMakeCredential`.
pub fn parse_make_credential(bytes: &[u8]) -> Result<MakeCredentialRequest, WebAuthnError> {
    let request = cbor::decode(bytes)?;
    let client_data_hash = request
        .get(1)
        .and_then(Value::as_bytes)
        .ok_or(WebAuthnError::BadRequest("clientDataHash"))?
        .to_vec();
    if client_data_hash.len() != 32 {
        return Err(WebAuthnError::BadRequest("clientDataHash"));
    }
    let rp = request.get(2).ok_or(WebAuthnError::BadRequest("rp"))?;
    // The outer request map is integer-keyed (CTAP2 section 6.1), but every
    // nested WebAuthn entity is a map with the spec's *text* member names:
    // rp is {"id","name"}, user is {"id","name","displayName"}, a credential
    // descriptor is {"type","id"} and a parameter is {"type","alg"}.
    let rp_id = rp
        .get_text("id")
        .and_then(Value::as_text)
        .ok_or(WebAuthnError::BadRequest("rp.id"))?
        .to_string();
    if rp_id.is_empty() {
        return Err(WebAuthnError::BadRequest("rp.id"));
    }
    let rp_name = rp
        .get_text("name")
        .and_then(Value::as_text)
        .unwrap_or(&rp_id)
        .to_string();
    let user = request.get(3).ok_or(WebAuthnError::BadRequest("user"))?;
    let user_id = user
        .get_text("id")
        .and_then(Value::as_bytes)
        .ok_or(WebAuthnError::BadRequest("user.id"))?
        .to_vec();
    let user_name = user
        .get_text("name")
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_string();
    let user_display_name = user
        .get_text("displayName")
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_string();
    let algorithms = request
        .get(4)
        .and_then(Value::as_array)
        .ok_or(WebAuthnError::BadRequest("pubKeyCredParams"))?
        .iter()
        .filter(|parameter| {
            parameter
                .get_text("type")
                .and_then(Value::as_text)
                .is_none_or(|kind| kind == "public-key")
        })
        .filter_map(|parameter| parameter.get_text("alg").and_then(Value::as_int))
        .collect::<Vec<_>>();
    let exclude_list = request
        .get(5)
        .and_then(Value::as_array)
        .map(|credentials| {
            credentials
                .iter()
                // Credential descriptor: {"type","id"} with text keys.
                .filter_map(|credential| credential.get_text("id").and_then(Value::as_bytes))
                .map(<[u8]>::to_vec)
                .collect()
        })
        .unwrap_or_default();
    let options = request.get(7);
    let require_resident_key = options
        .and_then(|options| options.get_text("rk"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let require_uv = options
        .and_then(|options| options.get_text("uv"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(MakeCredentialRequest {
        client_data_hash,
        rp_id,
        rp_name,
        user_id,
        user_name,
        user_display_name,
        algorithms,
        exclude_list,
        require_resident_key,
        require_uv,
    })
}

/// Parse `authenticatorGetAssertion`.
pub fn parse_get_assertion(bytes: &[u8]) -> Result<GetAssertionRequest, WebAuthnError> {
    let request = cbor::decode(bytes)?;
    let rp_id = request
        .get(1)
        .and_then(Value::as_text)
        .ok_or(WebAuthnError::BadRequest("rpId"))?
        .to_string();
    let client_data_hash = request
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or(WebAuthnError::BadRequest("clientDataHash"))?
        .to_vec();
    if client_data_hash.len() != 32 {
        return Err(WebAuthnError::BadRequest("clientDataHash"));
    }
    let allow_list = request
        .get(3)
        .and_then(Value::as_array)
        .map(|credentials| {
            credentials
                .iter()
                .filter_map(|credential| credential.get_text("id").and_then(Value::as_bytes))
                .map(<[u8]>::to_vec)
                .collect()
        })
        .unwrap_or_default();
    let require_uv = request
        .get(5)
        .and_then(|options| options.get_text("uv"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(GetAssertionRequest {
        rp_id,
        client_data_hash,
        allow_list,
        require_uv,
    })
}

/// `authenticatorMakeCredential` response with `fmt: "none"`.
pub fn make_credential_response(auth_data: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (Value::Uint(1), Value::Text("none".into())),
        (Value::Uint(2), Value::Bytes(auth_data.to_vec())),
        (Value::Uint(3), Value::Map(Vec::new())),
    ]))
}

/// `authenticatorGetAssertion` response: credential descriptor, authenticator
/// data, signature and (when known) the user handle.
pub fn get_assertion_response(
    credential_id: &[u8],
    auth_data: &[u8],
    signature: &[u8],
    user: Option<(&[u8], &str, &str)>,
) -> Vec<u8> {
    let descriptor = Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(credential_id.to_vec()),
        ),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ]);
    let mut members = vec![
        (Value::Uint(1), descriptor),
        (Value::Uint(2), Value::Bytes(auth_data.to_vec())),
        (Value::Uint(3), Value::Bytes(signature.to_vec())),
    ];
    if let Some((id, name, display_name)) = user {
        members.push((
            Value::Uint(4),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(id.to_vec())),
                (Value::Text("name".into()), Value::Text(name.to_string())),
                (
                    Value::Text("displayName".into()),
                    Value::Text(display_name.to_string()),
                ),
            ]),
        ));
    }
    cbor::encode(&Value::Map(members))
}

/// `authenticatorGetInfo` advertised at registration time.
pub fn authenticator_get_info() -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        // FIDO_2_0 only: advertising FIDO_2_1 obliges the authenticator to
        // carry `maxMsgSize` and PIN protocol details this engine does not
        // implement. `uv` is absent rather than false because an option map
        // advertises support, and this provider has no PIN/biometric gesture.
        (
            Value::Uint(1),
            Value::Array(vec![Value::Text("FIDO_2_0".into())]),
        ),
        (Value::Uint(3), Value::Bytes(crate::AAGUID.to_vec())),
        (
            Value::Uint(4),
            Value::Map(vec![
                (Value::Text("rk".into()), Value::Bool(true)),
                (Value::Text("up".into()), Value::Bool(true)),
            ]),
        ),
        (Value::Uint(5), Value::Uint(1200)),
    ]))
}

/// Test/general helper: build the attestation object for a fresh credential.
pub fn credential_attestation(
    rp_id: &str,
    credential_id: &[u8],
    key: &CoseKey,
    sign_count: u32,
) -> Vec<u8> {
    let auth_data = AuthenticatorData {
        rp_id_hash: rp_id_hash(rp_id),
        flags: FLAG_UP | FLAG_AT,
        sign_count,
        attested: Some((credential_id, key)),
        extensions: None,
    };
    attestation_object(&auth_data.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cose::SigningMaterial;

    #[test]
    fn get_info_advertises_only_what_is_implemented() {
        let info = cbor::decode(&authenticator_get_info()).unwrap();
        let versions = info.get(1).and_then(Value::as_array).expect("versions");
        assert_eq!(versions, &[Value::Text("FIDO_2_0".into())]);
        let options = info.get(4).expect("options");
        assert_eq!(options.get_text("rk").and_then(Value::as_bool), Some(true));
        assert_eq!(options.get_text("up").and_then(Value::as_bool), Some(true));
        assert_eq!(
            options.get_text("uv"),
            None,
            "no PIN or biometric verification, so uv must not be advertised"
        );
        assert_eq!(
            info.get(3).and_then(Value::as_bytes),
            Some(&crate::AAGUID[..])
        );
        assert_eq!(info.get(5).and_then(Value::as_int), Some(1200));
    }

    #[test]
    fn rp_id_hash_is_sha256_of_the_id() {
        // sha256("example.com")
        assert_eq!(
            rp_id_hash("example.com"),
            [
                0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34,
                0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55,
                0x86, 0xce, 0x19, 0x47,
            ]
        );
    }

    #[test]
    fn authenticator_data_flags_and_sign_count_exact_bytes() {
        let data = AuthenticatorData {
            rp_id_hash: [0xaa; 32],
            flags: FLAG_UP,
            sign_count: 0x0102_0304,
            attested: None,
            extensions: None,
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), 37);
        assert_eq!(&bytes[..32], &[0xaa; 32]);
        assert_eq!(bytes[32], 0x01); // UP only
        assert_eq!(&bytes[33..37], &[0x01, 0x02, 0x03, 0x04]); // big-endian
    }

    #[test]
    fn attested_credential_data_layout_is_exact() {
        let material = SigningMaterial::from_bytes(&[3u8; 32]).unwrap();
        let key = material.public_key();
        let credential_id = [0x11u8; CREDENTIAL_ID_LEN];
        let data = AuthenticatorData {
            rp_id_hash: [0u8; 32],
            flags: FLAG_UP | FLAG_AT,
            sign_count: 0,
            attested: Some((&credential_id, &key)),
            extensions: None,
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes[32], 0x41); // UP | AT
        assert_eq!(&bytes[33..37], &[0, 0, 0, 0]);
        assert_eq!(&bytes[37..53], &crate::AAGUID);
        assert_eq!(&bytes[53..55], &[0x00, 0x20]); // 32-byte credential id
        assert_eq!(&bytes[55..87], &credential_id);
        assert_eq!(&bytes[87..], &key.to_bytes());
    }

    #[test]
    fn credential_id_is_random_and_right_size() {
        let first = generate_credential_id();
        let second = generate_credential_id();
        assert_eq!(first.len(), CREDENTIAL_ID_LEN);
        assert_ne!(first, second);
    }

    #[test]
    fn attestation_object_is_none_with_empty_statement() {
        let object = attestation_object(&[1, 2, 3]);
        // {fmt: "none", attStmt: {}, authData: h'010203'} in canonical order:
        // attStmt (7 chars) < authData (8) < fmt (3)? Length first: fmt is 3,
        // attStmt 7, authData 8, so fmt comes first.
        let expected: Vec<u8> = vec![
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67, b'a', b't', b't',
            b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
            0x43, 1, 2, 3,
        ];
        assert_eq!(object, expected);
        let decoded = cbor::decode(&object).unwrap();
        assert_eq!(decoded.get(1), None); // numeric keys are not used here
    }

    #[test]
    fn es256_assertion_verifies_against_public_key() {
        let material = SigningMaterial::from_bytes(&[5u8; 32]).unwrap();
        let key = material.public_key();
        let auth_data = AuthenticatorData {
            rp_id_hash: rp_id_hash("login.example"),
            flags: FLAG_UP,
            sign_count: 7,
            attested: None,
            extensions: None,
        }
        .to_bytes();
        let client_data_hash = [0x42u8; 32];
        let signature = sign_assertion(&material, &auth_data, &client_data_hash).unwrap();
        assert!(verify_assertion(&key, &auth_data, &client_data_hash, &signature).is_ok());

        // A different client data hash must fail: the signature binds both
        // halves of the WebAuthn message.
        let wrong_hash = [0x43u8; 32];
        assert_eq!(
            verify_assertion(&key, &auth_data, &wrong_hash, &signature),
            Err(WebAuthnError::BadSignature)
        );
        assert_eq!(
            verify_assertion(&key, &auth_data, &client_data_hash, &[0x30, 0x00]),
            Err(WebAuthnError::MalformedSignature)
        );
    }

    #[test]
    fn parse_make_credential_reads_the_fields_it_uses() {
        let request = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bytes(vec![0x11; 32])),
            (
                Value::Uint(2),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (Value::Text("name".into()), Value::Text("Example".into())),
                ]),
            ),
            (
                Value::Uint(3),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![1, 2, 3])),
                    (Value::Text("name".into()), Value::Text("alice".into())),
                    (
                        Value::Text("displayName".into()),
                        Value::Text("Alice".into()),
                    ),
                ]),
            ),
            (
                Value::Uint(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::NegInt(-7)),
                ])]),
            ),
            (
                Value::Uint(7),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(true)),
                    (Value::Text("uv".into()), Value::Bool(false)),
                ]),
            ),
        ]));
        let parsed = parse_make_credential(&request).unwrap();
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.rp_name, "Example");
        assert_eq!(parsed.user_id, vec![1, 2, 3]);
        assert_eq!(parsed.user_name, "alice");
        assert_eq!(parsed.algorithms, vec![-7]);
        assert!(parsed.require_resident_key);
        assert!(!parsed.require_uv);
        assert!(parsed.exclude_list.is_empty());
    }

    #[test]
    fn assertion_verifies_against_the_key_embedded_in_attested_data() {
        let material = SigningMaterial::from_bytes(&[0x21u8; 32]).unwrap();
        let credential_id = [0x33u8; CREDENTIAL_ID_LEN];
        let attestation =
            credential_attestation("example.com", &credential_id, &material.public_key(), 0);
        let object = cbor::decode(&attestation).unwrap();
        let auth_data = object
            .get_text("authData")
            .and_then(Value::as_bytes)
            .expect("authData");
        // Fixed header (37) + AAGUID (16) + credential-id length (2) + id.
        let key_offset = 37 + 16 + 2 + credential_id.len();
        let embedded = CoseKey::from_bytes(&auth_data[key_offset..])
            .expect("credential public key is a COSE_Key");

        // Assertion over a different message than creation.
        let fixed = AuthenticatorData {
            rp_id_hash: rp_id_hash("example.com"),
            flags: FLAG_UP,
            sign_count: 1,
            attested: None,
            extensions: None,
        }
        .to_bytes();
        let client_hash = [0x77u8; 32];
        let signature = sign_assertion(&material, &fixed, &client_hash).unwrap();
        assert!(verify_assertion(&embedded, &fixed, &client_hash, &signature).is_ok());
    }

    #[test]
    fn make_credential_parses_the_spec_text_keyed_entities() {
        // The shape a real client sends (CTAP2 6.1): the outer map is
        // integer-keyed, every nested entity uses its WebAuthn member names.
        let request = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bytes(vec![0u8; 32])),
            (
                Value::Uint(2),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (Value::Text("name".into()), Value::Text("Example".into())),
                ]),
            ),
            (
                Value::Uint(3),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![9u8])),
                    (Value::Text("name".into()), Value::Text("alice".into())),
                    (
                        Value::Text("displayName".into()),
                        Value::Text("Alice".into()),
                    ),
                ]),
            ),
            (
                Value::Uint(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::NegInt(-7)),
                ])]),
            ),
            (
                Value::Uint(5),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("id".into()), Value::Bytes(vec![0xee; 32])),
                ])]),
            ),
        ]));
        let parsed = parse_make_credential(&request).expect("spec-shaped request parses");
        assert_eq!(parsed.rp_id, "example.com");
        assert_eq!(parsed.rp_name, "Example");
        assert_eq!(parsed.user_id, vec![9u8]);
        assert_eq!(parsed.user_name, "alice");
        assert_eq!(parsed.user_display_name, "Alice");
        assert_eq!(parsed.algorithms, vec![-7]);
        assert_eq!(parsed.exclude_list, vec![vec![0xee; 32]]);
    }

    #[test]
    fn an_integer_keyed_entity_is_rejected_instead_of_silently_empty() {
        // The previous parser accepted this shape; no client sends it, and
        // accepting it is how a broken parser looks correct.
        let request = cbor::encode(&Value::Map(vec![
            (Value::Uint(1), Value::Bytes(vec![0u8; 32])),
            (
                Value::Uint(2),
                Value::Map(vec![(Value::Uint(1), Value::Text("example.com".into()))]),
            ),
            (
                Value::Uint(3),
                Value::Map(vec![(Value::Uint(1), Value::Bytes(vec![9u8]))]),
            ),
            (
                Value::Uint(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Uint(1), Value::Text("public-key".into())),
                    (Value::Uint(3), Value::NegInt(-7)),
                ])]),
            ),
        ]));
        assert!(parse_make_credential(&request).is_err());
    }

    #[test]
    fn malformed_requests_are_refused() {
        // Not CBOR at all.
        assert!(matches!(
            parse_make_credential(&[0xff]),
            Err(WebAuthnError::Cbor(_))
        ));
        // A map without the client data hash.
        let missing = cbor::encode(&Value::Map(vec![(
            Value::Uint(2),
            Value::Map(vec![(Value::Text("id".into()), Value::Text("x".into()))]),
        )]));
        assert_eq!(
            parse_make_credential(&missing),
            Err(WebAuthnError::BadRequest("clientDataHash"))
        );
        // A short client data hash is not a hash.
        let short = cbor::encode(&Value::Map(vec![(
            Value::Uint(1),
            Value::Bytes(vec![0u8; 16]),
        )]));
        assert_eq!(
            parse_make_credential(&short),
            Err(WebAuthnError::BadRequest("clientDataHash"))
        );
    }
}
