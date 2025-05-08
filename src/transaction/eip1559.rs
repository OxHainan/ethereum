use ethereum_types::{H256, U256};
use rlp::{DecoderError, Rlp, RlpStream};
use sha3::{Digest, Keccak256};

use crate::{
	transaction::{AccessList, TransactionAction},
	Bytes, Error,
};

use super::AccessListItem;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransactionMethod {
	Universal(UniversalTransaction),
	Confidential(ConfidentialTransaction),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UniversalTransaction {
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
}


impl From<EIP1559TransactionMessage> for UniversalTransaction {
	fn from(t: EIP1559TransactionMessage) -> Self {
		Self {
			max_priority_fee_per_gas: t.max_priority_fee_per_gas,
			max_fee_per_gas: t.max_fee_per_gas,
			gas_limit: t.gas_limit,
			action: t.action,
			value: t.value,
			input: t.input,
			access_list: t.access_list,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConfidentialTransaction {
	pub cipher: Bytes,
	pub aad: H256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
}

impl From<UniversalTransaction> for ConfidentialParams {
	fn from(t: UniversalTransaction) -> Self {
		Self {
			value: t.value,
			input: t.input,
			access_list: t.access_list,
		}
	}
}



#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EIP1559Transaction {
	pub chain_id: u64,
	pub nonce: U256,
	pub method: TransactionMethod,
	pub odd_y_parity: bool,
	pub r: H256,
	pub s: H256,
}

impl EIP1559Transaction {
	pub fn hash(&self) -> H256 {
		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = 2;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}

	pub fn to_message(self) -> EIP1559TransactionMessage {
		match self.method {
			TransactionMethod::Confidential(con) => EIP1559TransactionMessage {
				aad: Some(con.aad),
				..Default::default()
			},
			TransactionMethod::Universal(uni) => EIP1559TransactionMessage {
				chain_id: self.chain_id,
				nonce: self.nonce,
				max_priority_fee_per_gas: uni.max_priority_fee_per_gas,
				max_fee_per_gas: uni.max_fee_per_gas,
				gas_limit: uni.gas_limit,
				action: uni.action,
				value: uni.value,
				input: uni.input,
				access_list: uni.access_list,
				..Default::default()
			},
		}
	}

    pub fn encrypt<F>(&self, encrypte: F) -> Result<Self, Error>
	where
		F: FnOnce(&[u8], H256) -> Result<Bytes, Error>,
	{
		let message = EIP1559TransactionMessage::from(self.clone());
		let signed_hash = message.hash();
		let universal = UniversalTransaction::from(message);

		Ok(EIP1559Transaction {
			method: TransactionMethod::Confidential(ConfidentialTransaction {
				aad: signed_hash,
				action: universal.action,
				gas_limit: universal.gas_limit,
				max_fee_per_gas: universal.max_fee_per_gas,
				max_priority_fee_per_gas: universal.max_priority_fee_per_gas,
				cipher: encrypte(
					&rlp::encode::<ConfidentialParams>(&universal.into()),
					signed_hash,
				)?,
			}),
			chain_id: self.chain_id,
			nonce: self.nonce,
			odd_y_parity: self.odd_y_parity,
			r: self.r,
			s: self.s,
		})
	}

    pub fn gas_limit(&self) -> U256 {
		match &self.method {
			TransactionMethod::Confidential(con) => con.gas_limit,
			TransactionMethod::Universal(uni) => uni.gas_limit,
		}
	}

	pub fn max_priority_fee_per_gas(&self) -> U256 {
		match &self.method {
			TransactionMethod::Confidential(con) => con.max_priority_fee_per_gas,
			TransactionMethod::Universal(uni) => uni.max_priority_fee_per_gas,
		}
	}

	pub fn max_fee_per_gas(&self) -> U256 {
		match &self.method {
			TransactionMethod::Confidential(con) => con.max_fee_per_gas,
			TransactionMethod::Universal(uni) => uni.max_fee_per_gas,
		}
	}

	pub fn value(&self) -> U256 {
		match &self.method {
			TransactionMethod::Confidential(_con) => U256::zero(),
			TransactionMethod::Universal(uni) => uni.value,
		}
	}

	pub fn action(&self) -> TransactionAction {
		match &self.method {
			TransactionMethod::Confidential(con) => con.action,
			TransactionMethod::Universal(uni) => uni.action,
		}
	}

	pub fn essentials(&self) -> Result<TransactionEssentials, Error> {
		match &self.method {
			TransactionMethod::Universal(uni) => Ok(TransactionEssentials {
				nonce: Some(self.nonce),
				input: uni.input.clone(),
				gas_price: None,
				max_fee_per_gas: Some(uni.max_fee_per_gas),
				max_priority_fee_per_gas: Some(uni.max_priority_fee_per_gas),
				value: uni.value,
				gas_limit: uni.gas_limit,
				action: uni.action,
				access_list: uni.access_list.clone(),
			}),
			_ => Err(Error::NotDecryptedTransaction),
		}
	}

	pub fn essentials_with_decrypt<F>(&self, decrypt: F) -> Result<TransactionEssentials, Error>
	where
		F: FnOnce(&[u8], H256) -> Result<Bytes, Error>,
	{
		let uni = match &self.method {
			TransactionMethod::Universal(uni) => uni.clone(),
			TransactionMethod::Confidential(con) => {
				let confident = rlp::decode::<ConfidentialParams>(
					&decrypt(&con.cipher, con.aad).map_err(|_| Error::BadDecrypte)?,
				)
				.map_err(|_| Error::InvalidRlpDecode)?;
				UniversalTransaction {
					max_fee_per_gas: con.max_fee_per_gas,
					max_priority_fee_per_gas: con.max_priority_fee_per_gas,
					gas_limit: con.gas_limit,
					action: con.action,
					value: confident.value,
					input: confident.input,
					access_list: confident.access_list,
				}
			}
		};

		Ok(TransactionEssentials {
			nonce: Some(self.nonce),
			input: uni.input,
			gas_price: None,
			max_fee_per_gas: Some(uni.max_fee_per_gas),
			max_priority_fee_per_gas: Some(uni.max_priority_fee_per_gas),
			value: uni.value,
			gas_limit: uni.gas_limit,
			action: uni.action,
			access_list: uni.access_list,
		})
	}

	pub fn is_universal(&self) -> bool {
		match &self.method {
			TransactionMethod::Confidential(_) => false,
			TransactionMethod::Universal(_) => true,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
	feature = "with-scale",
	derive(scale_codec::Encode, scale_codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ConfidentialParams {
	pub value: U256,
	pub input: Bytes,
	pub access_list: Vec<AccessListItem>,
}

impl rlp::Encodable for EIP1559Transaction {
	fn rlp_append(&self, s: &mut RlpStream) {
        match self.method {
			TransactionMethod::Confidential(_) => s.begin_list(10),
			TransactionMethod::Universal(_) => s.begin_list(12),
		};

		s.append(&self.chain_id);
		s.append(&self.nonce);
		match &self.method {
			TransactionMethod::Universal(uni) => {
				s.append(&uni.max_priority_fee_per_gas);
				s.append(&uni.max_fee_per_gas);
				s.append(&uni.gas_limit);
				s.append(&uni.action);
				s.append(&uni.value);
				s.append(&uni.input);
				s.append_list(&uni.access_list);
			}
			TransactionMethod::Confidential(con) => {
				s.append(&con.max_priority_fee_per_gas);
				s.append(&con.max_fee_per_gas);
				s.append(&con.gas_limit);
				s.append(&con.action);
				s.append(&con.aad);
				s.append(&con.cipher);
			}
		};

		s.append(&self.odd_y_parity);
		s.append(&self.r);
		s.append(&self.s);
	}
}

impl rlp::Decodable for EIP1559Transaction {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let (method, listlen) = match rlp.item_count()? {
			12 => (
				TransactionMethod::Universal(UniversalTransaction {
					max_priority_fee_per_gas: rlp.val_at(2)?,
					max_fee_per_gas: rlp.val_at(3)?,
					gas_limit: rlp.val_at(4)?,
					action: rlp.val_at(5)?,
					value: rlp.val_at(6)?,
					input: rlp.val_at(7)?,
					access_list: rlp.list_at(8)?,
				}),
				12,
			),
			11 => (
				TransactionMethod::Confidential(ConfidentialTransaction {
					max_priority_fee_per_gas: rlp.val_at(2)?,
					max_fee_per_gas: rlp.val_at(3)?,
					gas_limit: rlp.val_at(4)?,
					action: rlp.val_at(5)?,
					aad: rlp.val_at(6)?,
					cipher: rlp.val_at(7)?,
				}),
				11,
			),
			_ => return Err(rlp::DecoderError::RlpIncorrectListLen),
		};

		Ok(Self {
			chain_id: rlp.val_at(0)?,
			nonce: rlp.val_at(1)?,
			method: method,
			odd_y_parity: rlp.val_at(listlen - 3)?,
			r: rlp.val_at(listlen - 2)?,
			s: rlp.val_at(listlen - 1)?,
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EIP1559TransactionMessage {
	pub chain_id: u64,
	pub nonce: U256,
	pub max_priority_fee_per_gas: U256,
	pub max_fee_per_gas: U256,
	pub gas_limit: U256,
	pub action: TransactionAction,
	pub value: U256,
	pub input: Bytes,
	pub access_list: AccessList,
	pub aad: Option<H256>,
}

impl EIP1559TransactionMessage {
	pub fn hash(&self) -> H256 {
if let Some(aad) = self.aad {
			return aad;
		}

		let encoded = rlp::encode(self);
		let mut out = alloc::vec![0; 1 + encoded.len()];
		out[0] = 2;
		out[1..].copy_from_slice(&encoded);
		H256::from_slice(Keccak256::digest(&out).as_slice())
	}
}

impl rlp::Encodable for EIP1559TransactionMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.chain_id);
		s.append(&self.nonce);
		s.append(&self.max_priority_fee_per_gas);
		s.append(&self.max_fee_per_gas);
		s.append(&self.gas_limit);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.input);
		s.append_list(&self.access_list);
	}
}

impl From<EIP1559Transaction> for EIP1559TransactionMessage {
	fn from(t: EIP1559Transaction) -> Self {
		t.to_message()
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TransactionEssentials {
	pub input: Bytes,
	pub value: U256,
	pub gas_limit: U256,
	pub gas_price: Option<U256>,
	pub max_fee_per_gas: Option<U256>,
	pub max_priority_fee_per_gas: Option<U256>,
	pub nonce: Option<U256>,
	pub action: TransactionAction,
	pub access_list: AccessList,
}
