//! Utility functions for Ethereum.

#[cfg(test)]
use aes_gcm::{
	aead::{AeadMut, Payload},
	Aes256Gcm, KeyInit, Nonce,
};
use ethereum_types::H256;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;
use sha3::{Digest, Keccak256};

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = H256;

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		H256::from_slice(Keccak256::digest(x).as_slice())
	}
}

/// Generates a trie root hash for a vector of key-value tuples
pub fn trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]> + Ord,
	V: AsRef<[u8]>,
{
	triehash::trie_root::<KeccakHasher, _, _, _>(input)
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
pub fn sec_trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]>,
	V: AsRef<[u8]>,
{
	triehash::sec_trie_root::<KeccakHasher, _, _, _>(input)
}

/// Generates a trie root hash for a vector of values
pub fn ordered_trie_root<I, V>(input: I) -> H256
where
	I: IntoIterator<Item = V>,
	V: AsRef<[u8]>,
{
	triehash::ordered_trie_root::<KeccakHasher, I>(input)
}

#[cfg(test)]
pub fn encrypt(key: &[u8], pubkey: &[u8; 64], nonce: H256, msg: &[u8], aad: &[u8]) -> Vec<u8> {
	let shared_key = shared_secret(key, pubkey).unwrap();
	Aes256Gcm::new_from_slice(&shared_key)
		.unwrap()
		.encrypt(
			Nonce::from_slice(&nonce.as_fixed_bytes()[20..]),
			Payload { aad, msg },
		)
		.unwrap()
}

#[cfg(test)]
pub fn decrypt(key: &[u8], pubkey: &[u8; 64], nonce: H256, msg: &[u8], aad: &[u8]) -> Vec<u8> {
	let shared_key = shared_secret(key, pubkey).unwrap();
	Aes256Gcm::new_from_slice(&shared_key)
		.unwrap()
		.decrypt(
			Nonce::from_slice(&nonce.as_fixed_bytes()[20..]),
			Payload { aad, msg },
		)
		.unwrap()
}

#[cfg(test)]
fn shared_secret(key: &[u8], pubkey: &[u8; 64]) -> Result<[u8; 32], secp256k1::Error> {
	use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

	let mut tagged_full = [0u8; 65];
	tagged_full[0] = 0x04;
	tagged_full[1..].copy_from_slice(pubkey);

	let sk = SecretKey::from_slice(key)?;
	Ok(SharedSecret::new(&PublicKey::from_slice(&tagged_full)?, &sk).secret_bytes())
}

#[cfg(test)]
fn secp256k1_ecdsa_recover(sig: &[u8; 65], msg: &[u8; 32]) -> Result<[u8; 64], secp256k1::Error> {
	use secp256k1::{
		ecdsa::{RecoverableSignature, RecoveryId},
		Message, SECP256K1,
	};

	let rid = RecoveryId::from_i32(if sig[64] > 26 { sig[64] - 27 } else { sig[64] } as i32)?;
	let sig = RecoverableSignature::from_compact(&sig[..64], rid)?;
	let msg = Message::from_slice(msg).expect("Message is 32 bytes; qed");
	let pubkey = SECP256K1.recover_ecdsa(&msg, &sig)?;
	let mut res = [0u8; 64];
	res.copy_from_slice(&pubkey.serialize_uncompressed()[1..]);
	Ok(res)
}

#[cfg(test)]
pub fn recover_signer(transaction: &crate::TransactionV2) -> [u8; 64] {
	let mut sig = [0u8; 65];
	let mut msg = [0u8; 32];
	match transaction {
		crate::TransactionV2::EIP1559(tx) => {
			sig[0..32].copy_from_slice(&tx.r[..]);
			sig[32..64].copy_from_slice(&tx.s[..]);
			sig[64] = tx.odd_y_parity as u8;
			msg.copy_from_slice(
				&crate::transaction::EIP1559TransactionMessage::from(tx.clone()).hash()[..],
			);
		}
		_ => {}
	}

	secp256k1_ecdsa_recover(&sig, &msg).ok().unwrap()
}
