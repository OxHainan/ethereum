#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod account;
mod block;
mod enveloped;
mod header;
mod log;
mod receipt;
mod transaction;
// mod transaction1;
pub mod util;

// Alias for `Vec<u8>`. This type alias is necessary for rlp-derive to work correctly.
type Bytes = alloc::vec::Vec<u8>;

pub use account::Account;
pub use block::*;
pub use enveloped::*;
pub use header::{Header, PartialHeader};
pub use log::Log;
pub use receipt::*;
pub use transaction::*;


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
	BadEncrypte,
	BadDecrypte,
	InvalidKeyLength,
	InvalidRlpDecode,
	/// Invalid secret key
	BadSecretKey,
	/// Invalid  public key
	BadPublicKey,
	NotDecryptedTransaction,
}