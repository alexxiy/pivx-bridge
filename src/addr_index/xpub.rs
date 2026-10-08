//! BIP32 extended public key parsing + non-hardened derivation, and
//! PIVX P2PKH address encoding. Enough to walk a BIP44 account xpub
//! the way Blockbook does (chains 0/1, gap limit).
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, PublicKey, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub public_key: PublicKey,
}

impl ExtendedPubKey {
    /// Parse a base58check xpub. Any 4-byte version is accepted
    /// (MPW serialises with the Bitcoin `xpub` version on every net).
    pub fn parse(s: &str) -> Result<Self, String> {
        let data = bs58::decode(s).with_check(None).into_vec().map_err(|e| format!("bad xpub: {e}"))?;
        if data.len() != 78 {
            return Err("bad xpub length".into());
        }
        let depth = data[4];
        let child_number = u32::from_be_bytes(data[9..13].try_into().unwrap());
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);
        let public_key = PublicKey::from_sec1_bytes(&data[45..78]).map_err(|_| "bad xpub public key".to_string())?;
        Ok(Self { depth, child_number, chain_code, public_key })
    }

    pub fn derive_child(&self, index: u32) -> Result<Self, String> {
        if index & 0x8000_0000 != 0 {
            return Err("cannot derive hardened child from xpub".into());
        }
        let mut mac = HmacSha512::new_from_slice(&self.chain_code).expect("hmac key");
        mac.update(self.public_key.to_encoded_point(true).as_bytes());
        mac.update(&index.to_be_bytes());
        let i = mac.finalize().into_bytes();
        let il: [u8; 32] = i[..32].try_into().unwrap();
        let tweak = Option::<Scalar>::from(Scalar::from_repr(il.into())).ok_or("invalid tweak")?;
        let point = ProjectivePoint::GENERATOR * tweak + self.public_key.to_projective();
        let public_key = PublicKey::from_affine(point.to_affine()).map_err(|_| "derived point at infinity".to_string())?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&i[32..]);
        Ok(Self { depth: self.depth.wrapping_add(1), child_number: index, chain_code, public_key })
    }

    pub fn p2pkh_address(&self, prefix: u8) -> String {
        let sha = Sha256::digest(self.public_key.to_encoded_point(true).as_bytes());
        let h160 = Ripemd160::digest(sha);
        let mut payload = Vec::with_capacity(21);
        payload.push(prefix);
        payload.extend_from_slice(&h160);
        bs58::encode(payload).with_check().into_string()
    }
}

/// Looks like an xpub (vs. a plain address)?
pub fn is_xpub(s: &str) -> bool {
    s.len() > 100 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1: public derivation m/0H/1/2H -> m/0H/1/2H/2.
    #[test]
    fn bip32_vector1_public_derivation() {
        let xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
        let k = ExtendedPubKey::parse(xpub).unwrap();
        let child = k.derive_child(2).unwrap();
        assert_eq!(
            hex(child.public_key.to_encoded_point(true).as_bytes()),
            "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
