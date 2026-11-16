//! COSE_Key (RFC 8152) for ES256 on NIST P-256.
//!
//! Only the one algorithm Kestrel issues is implemented. An unknown `alg`,
//! `kty` or `crv` is a hard error instead of a best-effort decode: accepting a
//! key the platform cannot verify would produce a credential that can never be
//! asserted.

use crate::cbor::{self, CborError, Value};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::FieldBytes;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// COSE algorithm identifier for ECDSA with SHA-256.
pub const ALG_ES256: i64 = -7;
/// COSE key type for EC2.
pub const KTY_EC2: i64 = 2;
/// COSE curve identifier for NIST P-256.
pub const CRV_P256: i64 = 1;
const COORDINATE_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseError {
    Cbor(CborError),
    /// Not an integer-keyed COSE map at all.
    NotAMap,
    /// `kty` is not EC2.
    UnsupportedKeyType(i64),
    /// `alg` is not ES256.
    UnsupportedAlgorithm(i64),
    /// `crv` is not P-256.
    UnsupportedCurve(i64),
    /// A required member is missing or has the wrong CBOR type.
    MissingMember(&'static str),
    /// `x`/`y` is not 32 bytes.
    BadCoordinate,
    /// The shared point is not a valid P-256 public key.
    BadPoint,
    /// A private scalar outside the curve order.
    BadPrivateKey,
}

impl From<CborError> for CoseError {
    fn from(value: CborError) -> Self {
        CoseError::Cbor(value)
    }
}

impl std::fmt::Display for CoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoseError::Cbor(error) => write!(f, "COSE CBOR: {error}"),
            CoseError::NotAMap => f.write_str("COSE key is not a map"),
            CoseError::UnsupportedKeyType(value) => write!(f, "unsupported COSE kty {value}"),
            CoseError::UnsupportedAlgorithm(value) => write!(f, "unsupported COSE alg {value}"),
            CoseError::UnsupportedCurve(value) => write!(f, "unsupported COSE crv {value}"),
            CoseError::MissingMember(name) => write!(f, "COSE key is missing {name}"),
            CoseError::BadCoordinate => f.write_str("COSE coordinate is not 32 bytes"),
            CoseError::BadPoint => f.write_str("COSE point is not on P-256"),
            CoseError::BadPrivateKey => f.write_str("private scalar is outside the P-256 order"),
        }
    }
}

impl std::error::Error for CoseError {}

/// A public key as it is stored inside `attestedCredentialData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseKey {
    pub x: [u8; COORDINATE_LEN],
    pub y: [u8; COORDINATE_LEN],
}

impl CoseKey {
    pub fn from_verifying_key(key: &VerifyingKey) -> CoseKey {
        let encoded = key.to_encoded_point(false);
        let mut x = [0u8; COORDINATE_LEN];
        let mut y = [0u8; COORDINATE_LEN];
        // `false` asks for the uncompressed form, which always carries both
        // fixed-width coordinates on P-256.
        x.copy_from_slice(encoded.x().expect("uncompressed point has x"));
        y.copy_from_slice(encoded.y().expect("uncompressed point has y"));
        CoseKey { x, y }
    }

    /// The uncompressed SEC1 point (`0x04 || x || y`).
    pub fn sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..].copy_from_slice(&self.y);
        out
    }

    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(1), Value::Uint(KTY_EC2 as u64)),
            (Value::Uint(3), Value::NegInt(ALG_ES256)),
            (Value::NegInt(-1), Value::Uint(CRV_P256 as u64)),
            (Value::NegInt(-2), Value::Bytes(self.x.to_vec())),
            (Value::NegInt(-3), Value::Bytes(self.y.to_vec())),
        ])
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    pub fn from_value(value: &Value) -> Result<CoseKey, CoseError> {
        if value.as_map().is_none() {
            return Err(CoseError::NotAMap);
        }
        let kty = value
            .get(1)
            .and_then(Value::as_int)
            .ok_or(CoseError::MissingMember("kty"))?;
        if kty != KTY_EC2 {
            return Err(CoseError::UnsupportedKeyType(kty));
        }
        let alg = value
            .get(3)
            .and_then(Value::as_int)
            .ok_or(CoseError::MissingMember("alg"))?;
        if alg != ALG_ES256 {
            return Err(CoseError::UnsupportedAlgorithm(alg));
        }
        let crv = value
            .get(-1)
            .and_then(Value::as_int)
            .ok_or(CoseError::MissingMember("crv"))?;
        if crv != CRV_P256 {
            return Err(CoseError::UnsupportedCurve(crv));
        }
        let x = value
            .get(-2)
            .and_then(Value::as_bytes)
            .ok_or(CoseError::MissingMember("-2"))?;
        let y = value
            .get(-3)
            .and_then(Value::as_bytes)
            .ok_or(CoseError::MissingMember("-3"))?;
        if x.len() != COORDINATE_LEN || y.len() != COORDINATE_LEN {
            return Err(CoseError::BadCoordinate);
        }
        let mut key = CoseKey {
            x: [0u8; COORDINATE_LEN],
            y: [0u8; COORDINATE_LEN],
        };
        key.x.copy_from_slice(x);
        key.y.copy_from_slice(y);
        // Parsing the point here means a decoded key is always usable for
        // verification; callers do not have to repeat the check.
        key.verifying_key()?;
        Ok(key)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<CoseKey, CoseError> {
        CoseKey::from_value(&cbor::decode(bytes)?)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, CoseError> {
        VerifyingKey::from_sec1_bytes(&self.sec1()).map_err(|_| CoseError::BadPoint)
    }
}

/// A freshly generated ES256 credential key.
#[derive(Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SigningMaterial {
    secret: [u8; COORDINATE_LEN],
}

impl std::fmt::Debug for SigningMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the scalar, even from a `{:?}` in a test or a log line.
        f.write_str("SigningMaterial(<redacted>)")
    }
}

impl SigningMaterial {
    /// Generate a scalar uniformly by rejection sampling. `from_bytes` rejects
    /// zero and values at or above the group order; retrying keeps the sample
    /// honest without pulling in a curve-specific RNG API.
    pub fn generate() -> SigningMaterial {
        let mut rng = rand::rngs::OsRng;
        loop {
            let mut bytes = [0u8; COORDINATE_LEN];
            rng.fill_bytes(&mut bytes);
            if SigningKey::from_bytes(&FieldBytes::from(bytes)).is_ok() {
                return SigningMaterial { secret: bytes };
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SigningMaterial, CoseError> {
        if bytes.len() != COORDINATE_LEN {
            return Err(CoseError::BadPrivateKey);
        }
        SigningKey::from_bytes(&FieldBytes::from_slice(bytes))
            .map_err(|_| CoseError::BadPrivateKey)?;
        let mut secret = [0u8; COORDINATE_LEN];
        secret.copy_from_slice(bytes);
        Ok(SigningMaterial { secret })
    }

    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret.to_vec())
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&FieldBytes::from(self.secret))
            .expect("SigningMaterial validates its scalar on construction")
    }

    pub fn public_key(&self) -> CoseKey {
        CoseKey::from_verifying_key(self.signing_key().verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_key_round_trips_through_exact_bytes() {
        let material = SigningMaterial::from_bytes(&[7u8; 32]).unwrap();
        let key = material.public_key();
        let bytes = key.to_bytes();

        // Exact COSE_Key layout, canonical map order: 1, 3, -1, -2, -3.
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(&bytes[1..3], &[0x01, 0x02]); // kty: 2 (EC2)
        assert_eq!(&bytes[3..5], &[0x03, 0x26]); // alg: -7 (ES256)
        assert_eq!(&bytes[5..7], &[0x20, 0x01]); // crv: 1 (P-256)
        assert_eq!(&bytes[7..10], &[0x21, 0x58, 0x20]); // -2: 32-byte x
        assert_eq!(&bytes[42..45], &[0x22, 0x58, 0x20]); // -3: 32-byte y
        assert_eq!(bytes.len(), 77);

        let decoded = CoseKey::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn unknown_algorithm_is_refused() {
        let material = SigningMaterial::from_bytes(&[9u8; 32]).unwrap();
        let mut value = material.public_key().to_value();
        let Value::Map(pairs) = &mut value else {
            unreachable!()
        };
        for (key, item) in pairs.iter_mut() {
            if key.as_int() == Some(3) {
                *item = Value::NegInt(-257);
            }
        }
        assert_eq!(
            CoseKey::from_value(&value),
            Err(CoseError::UnsupportedAlgorithm(-257))
        );
    }

    #[test]
    fn unknown_curve_and_key_type_are_refused() {
        let material = SigningMaterial::from_bytes(&[11u8; 32]).unwrap();
        let base = material.public_key().to_value();
        for (member, replacement, expected) in [
            (-1, Value::Uint(2), CoseError::UnsupportedCurve(2)),
            (1, Value::Uint(3), CoseError::UnsupportedKeyType(3)),
        ] {
            let Value::Map(mut pairs) = base.clone() else {
                unreachable!()
            };
            for (key, item) in pairs.iter_mut() {
                if key.as_int() == Some(member) {
                    *item = replacement.clone();
                }
            }
            assert_eq!(
                CoseKey::from_value(&Value::Map(pairs)),
                Err(expected)
            );
        }
    }

    #[test]
    fn off_curve_point_is_refused() {
        let material = SigningMaterial::from_bytes(&[13u8; 32]).unwrap();
        let mut value = material.public_key().to_value();
        let Value::Map(pairs) = &mut value else {
            unreachable!()
        };
        for (key, item) in pairs.iter_mut() {
            if key.as_int() == Some(-2) {
                *item = Value::Bytes(vec![0u8; 32]);
            }
            if key.as_int() == Some(-3) {
                *item = Value::Bytes(vec![0u8; 32]);
            }
        }
        assert_eq!(CoseKey::from_value(&value), Err(CoseError::BadPoint));
    }

    #[test]
    fn wrong_coordinate_length_is_refused() {
        let material = SigningMaterial::from_bytes(&[17u8; 32]).unwrap();
        let mut value = material.public_key().to_value();
        let Value::Map(pairs) = &mut value else {
            unreachable!()
        };
        for (key, item) in pairs.iter_mut() {
            if key.as_int() == Some(-2) {
                *item = Value::Bytes(vec![1u8; 31]);
            }
        }
        assert_eq!(
            CoseKey::from_value(&value),
            Err(CoseError::BadCoordinate)
        );
    }
}
