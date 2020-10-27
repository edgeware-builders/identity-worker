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

/// A pending identity verification.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug)]
pub struct PendingVerification<AccountId> {
	/// The location of the verification page
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
			Self::verify(verification);
		}
	}
}

impl<T: Trait> Module<T> {
	fn verify(verification: PendingVerification<T::AccountId>) -> Result<bool, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let url_str = sp_std::str::from_utf8(&verification.url).map_err(|_| {
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

		// TODO: verify fetched response
		Ok(true)
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