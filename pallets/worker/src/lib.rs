#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction,
	}
};
use frame_support::{
	debug, decl_module, decl_storage, decl_event,
	traits::Get,
};
use sp_runtime::{
	RuntimeDebug,
	traits::{Hash},
	transaction_validity::{
		ValidTransaction, TransactionValidity, TransactionSource,
		TransactionPriority,
	},
	offchain::{
		http, Duration
	}
};
use codec::{Encode, Decode};
use sp_std::vec::Vec;
use sp_io::crypto::sr25519_verify;
use sp_core::sr25519::{Public, Signature};
use sp_core::crypto::{KeyTypeId, UncheckedFrom};

#[cfg(test)]
mod tests;

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"iden");
pub mod crypto {
        use super::KEY_TYPE;
        use sp_runtime::{
                app_crypto::{app_crypto, sr25519},
                traits::Verify,
        };
        use sp_core::sr25519::Signature as Sr25519Signature;
        app_crypto!(sr25519, KEY_TYPE);

        pub struct TestAuthId;
        impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature> for TestAuthId {
                type RuntimeAppPublic = Public;
                type GenericSignature = sp_core::sr25519::Signature;
                type GenericPublic = sp_core::sr25519::Public;
        }
}

/// This pallet's configuration trait
pub trait Trait: CreateSignedTransaction<Call<Self>> {
	/// The identifier type for an offchain worker.
	type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Trait>::Event>;
	/// The overarching dispatch call type.
	type Call: From<Call<Self>>;

	// Configuration parameters

	/// A grace period after we send transaction.
	type GracePeriod: Get<Self::BlockNumber>;

	/// Number of blocks of cooldown after unsigned transaction is included.
	type UnsignedInterval: Get<Self::BlockNumber>;

	/// A configuration for base priority of unsigned transactions.
	type UnsignedPriority: Get<TransactionPriority>;
}

/// The type of endpoint
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub enum Endpoint {
	Github,
	Twitter,
	Other,
}

/// A pending identity verification.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PendingVerification<AccountId> {
	/// The type of endpoint we're querying for verification
	endpoint: Endpoint,
	/// The endpoint for the verification page
	url: Vec<u8>,
	/// The account submitting the verification request
	submitter: AccountId,
	/// The target account to verify
	target: AccountId,
}

decl_storage! {
	trait Store for Module<T: Trait> as WorkerModule {
		/// Verification submitted and waiting for approval. FIFO queue.
		PendingVerifications get(fn pending_verifications): Vec<PendingVerification<T::AccountId>>;
	}
}

decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Trait>::AccountId {
		NewHeader(u32, AccountId),
		/// An identity verification was processed, and was approved (true/false)
		VerificationProcessed(AccountId, bool),
	}
);

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		// // Errors must be initialized if they are used by the pallet.
		// type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		/// Offchain Worker entry point.
		fn offchain_worker(block_number: T::BlockNumber) {
			debug::native::info!("Hello World from offchain workers!");

			// We can easily import `frame_system` and retrieve a block hash of the parent block.
			let parent_hash = <system::Module<T>>::block_hash(block_number - 1.into());
			debug::debug!("Current block: {:?} (parent hash: {:?})", block_number, parent_hash);

			// Grab the next item off the pending verifications queue
			let verification_opt = PendingVerifications::<T>::mutate(|v| { v.pop() });
			let verification = match verification_opt {
				Some(v) => v,
				None => return, // do nothing if no pending verifications
			};
			let result = Self::process(verification);
			debug::debug!("Result: {:?}", result);
		}
	}
}

impl<T: Trait> Module<T> {
	pub fn add_to_pending_queue(verification: PendingVerification<T::AccountId>) -> Result<(), &'static str> {
		PendingVerifications::<T>::mutate(|v| { v.push(verification) });
		Ok(())
	}

	fn verify(signature: &str, target: T::AccountId) -> bool {
		// interpret the entire string as a base64 encoded "signature | public key"
		// allocate a buffer of sufficient size -- signature is 64 bytes, pubkey is 32 bytes
		let mut buf: [u8; 96] = [0; 96];
		base64::decode_config_slice(signature, base64::STANDARD, &mut buf).unwrap();

		// verify pub key matches given account
		if T::Hashing::hash(&buf[64..]) == T::Hashing::hash(&target.encode()) {
			// verify signature matches
			let mut pub_bytes: [u8; 32] = [0; 32];
			pub_bytes.copy_from_slice(&buf[64..]);
			let public: Public = Public::unchecked_from(pub_bytes);
			let mut sig_bytes: [u8; 64] = [0; 64];
			sig_bytes.copy_from_slice(&buf[..64]);
			let signature = Signature::from_raw(sig_bytes);
			sr25519_verify(&signature, &public, &public)
		} else {
			false
		}
	} 

	fn process(verification: PendingVerification<T::AccountId>) -> Result<bool, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let provided_url_str = sp_std::str::from_utf8(&verification.url).map_err(|_| {
			debug::warn!("No UTF8 url");
			http::Error::Unknown
		})?;
		// TODO: Twitter
		let url_vec = match verification.endpoint {
			// for github, use the gist's common URL to construct an API query
			Endpoint::Github => {
				// retrieve the id string and construct the API call
				let gist_id = provided_url_str.split('/').last().unwrap().as_bytes();
				let gist_api_prefix = b"https://api.github.com/gists/";
				let mut gist_url = Vec::new();
				gist_url.extend(gist_api_prefix);
				gist_url.extend(gist_id);
				gist_url
			}
			// plaintext URLs require no modification
			_ => provided_url_str.as_bytes().to_vec(),
		};
		let url_str = sp_std::str::from_utf8(&url_vec).map_err(|_| {
			debug::warn!("No UTF8 url");
			http::Error::Unknown
		})?;
		let request = http::Request::get(url_str);
		// TODO: set headers, oauth stuff
		let pending = request
			.deadline(deadline)
			.send()
			.map_err(|_| http::Error::IoError)?;

		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		if response.code != 200 {
			debug::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}

		// Collect body and create a str slice.
		let body = response.body().collect::<Vec<u8>>();
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			debug::warn!("No UTF8 body");
			http::Error::Unknown
		})?;
		debug::debug!("Got response body: {:?}", body_str);

		let result = match verification.endpoint {
			Endpoint::Github => {
				// TODO: interpret the string as a JSON blob: the base64 string should be found under "response_json.files[filename].content"
				let content = "";
				Self::verify(&content, verification.target)
			},

			// plaintext endpoint
			Endpoint::Other => Self::verify(&body_str, verification.target),
			_ => false,
		};
		Ok(result)
	}
}

#[allow(deprecated)] // ValidateUnsigned
impl<T: Trait> frame_support::unsigned::ValidateUnsigned for Module<T> {
	type Call = Call<T>;

	/// Validate unsigned call to this module.
	fn validate_unsigned(
		_source: TransactionSource,
		_call: &Self::Call,
	) -> TransactionValidity {
		ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
		// We set base priority to 2**20 and hope it's included before any other
		// transactions in the pool. Next we tweak the priority depending on how much
		// it differs from the current average. (the more it differs the more priority it
		// has).
		.priority(T::UnsignedPriority::get())
		// The transaction is only valid for next 5 blocks. After that it's
		// going to be revalidated by the pool.
		.longevity(5)
		// It's fine to propagate that transaction to other peers, which means it can be
		// created even by nodes that don't produce blocks.
		// Note that sometimes it's better to keep it for yourself (if you are the block
		// producer), since for instance in some schemes others may copy your solution and
		// claim a reward.
		.propagate(true)
		.build()
	}
}