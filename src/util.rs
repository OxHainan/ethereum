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
pub fn encrypt(key: &[u8], nonce: H256, msg: &[u8], aad: &[u8]) -> Vec<u8> {
	Aes256Gcm::new_from_slice(key)
		.unwrap()
		.encrypt(
			Nonce::from_slice(&nonce.as_fixed_bytes()[20..]),
			Payload { aad, msg },
		)
		.unwrap()
}

#[cfg(test)]
pub fn decrypt(key: &[u8], nonce: H256, msg: &[u8], aad: &[u8]) -> Vec<u8> {
	Aes256Gcm::new_from_slice(key)
		.unwrap()
		.decrypt(
			Nonce::from_slice(&nonce.as_fixed_bytes()[20..]),
			Payload { aad, msg },
		)
		.unwrap()
}
