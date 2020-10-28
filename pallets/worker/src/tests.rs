use crate::*;
use codec::{Encode, Decode};
use frame_support::{
	impl_outer_origin, parameter_types,
	weights::Weight,
};
use sp_core::{
	H256,
	offchain::{OffchainExt, testing},
	sr25519::{Pair, Signature},
};

use sp_runtime::{
	Perbill,
	testing::{Header, TestXt},
	traits::{
		BlakeTwo256, IdentityLookup, Extrinsic as ExtrinsicT,
		IdentifyAccount, Verify,
	},
};

impl_outer_origin! {
	pub enum Origin for Test where system = frame_system {}
}

// For testing the module, we construct most of a mock runtime. This means
// first constructing a configuration type (`Test`) which `impl`s each of the
// configuration traits of modules we want to use.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct Test;
parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const MaximumBlockWeight: Weight = 1024;
	pub const MaximumBlockLength: u32 = 2 * 1024;
	pub const AvailableBlockRatio: Perbill = Perbill::one();
}
impl frame_system::Trait for Test {
	type BaseCallFilter = ();
	type Origin = Origin;
	type Call = ();
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sp_core::sr25519::Public;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = ();
	type BlockHashCount = BlockHashCount;
	type MaximumBlockWeight = MaximumBlockWeight;
	type DbWeight = ();
	type BlockExecutionWeight = ();
	type ExtrinsicBaseWeight = ();
	type MaximumExtrinsicWeight = MaximumBlockWeight;
	type MaximumBlockLength = MaximumBlockLength;
	type AvailableBlockRatio = AvailableBlockRatio;
	type Version = ();
	type PalletInfo = ();
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
}

type Extrinsic = TestXt<Call<Test>, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Test {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test where
	Call<Test>: From<LocalCall>,
{
	type OverarchingCall = Call<Test>;
	type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test where
	Call<Test>: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call<Test>,
		_public: <Signature as Verify>::Signer,
		_account: AccountId,
		nonce: u64,
	) -> Option<(Call<Test>, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (nonce, ())))
	}
}

parameter_types! {
	pub const GracePeriod: u64 = 5;
	pub const UnsignedInterval: u64 = 128;
	pub const UnsignedPriority: u64 = 1 << 20;
}

impl Trait for Test {
	type Event = ();
	type AuthorityId = crypto::TestAuthId;
	type Call = Call<Test>;
	type GracePeriod = GracePeriod;
	type UnsignedInterval = UnsignedInterval;
	type UnsignedPriority = UnsignedPriority;
}

type Example = Module<Test>;

#[test]
fn should_make_http_call_and_parse_result() {
	let (offchain, state) = testing::TestOffchainExt::new();
	let mut t = sp_io::TestExternalities::default();
	t.register_extension(OffchainExt::new(offchain));

	set_block_response(&mut state.write());

	t.execute_with(|| {
		// when
		let alice_pubkey = sp_core::sr25519::Pair::from_string("//Alice", None).unwrap().public();
		let bob_pubkey = sp_core::sr25519::Pair::from_string("//Bob", None).unwrap().public();
		Example::add_to_pending_queue(PendingVerification {
			endpoint: Endpoint::Other,
			url: b"http://localhost:1234".to_vec(),
			submitter: bob_pubkey,
			target: alice_pubkey,
		})
		let result = Example::verify();
		// then
		assert!(result);
	});
}

fn set_block_response(state: &mut testing::OffchainState) {
	let alice_pubkey = sp_core::sr25519::Pair::from_string("//Alice", None).unwrap().public();
	// TODO: Marshall alice pubkey into a base64 signature
	let blob = b"jryGnU7CYzBaG/TCuObf3eSRuc5Qb0ADbIKAL7ZuOCFYKQhKaR+Qzpnzyx6ojfzNvrIPRqRMZ4yd5qum4LawjtQ1k8cV/dMcYRQavQSpn9aCLIVYhUzN45pWhOelbaJ9";
	state.expect_request(testing::PendingRequest {
		method: "GET".into(),
    uri: "http://localhost:1234".into(),
		response: Some(blob.to_vec()),
		sent: true,
		..Default::default()
	});
}