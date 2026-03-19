#![allow(dead_code)]

/// Defines field-specific STARK config aliases and constructors, wiring challenge fields, MMCS, PCS, challenger, and profile-derived prover/verifier configs.
macro_rules! define_field_config {
    (
        $config:ident,
        $field:ty,
        $challenge:ident,
        $transcript_hash:ident,
        $transcript_compress:ident,
        $val_mmcs:ident,
        $challenge_mmcs:ident,
        $challenger:ident,
        $dft:ident,
        $pcs:ident,
        $stark_config:ident,
    ) => {
        #[derive(Clone, Copy, Default)]
        pub struct $config<P>(core::marker::PhantomData<P>)
        where
            P: crate::security_profile::SecurityProfile;

        pub type $challenge = p3_field::extension::BinomialExtensionField<$field, 4>;
        pub type $transcript_hash = $crate::ff::StarkFieldHash;
        pub type $transcript_compress = $crate::ff::StarkCompress;
        pub type $val_mmcs = p3_merkle_tree::MerkleTreeHidingMmcs<
            [$field; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            $transcript_hash,
            $transcript_compress,
            $crate::rng::ChaChaCsrng,
            2,
            4,
            4,
        >;
        pub type $challenge_mmcs = p3_commit::ExtensionMmcs<$field, $challenge, $val_mmcs>;
        pub type $challenger = p3_challenger::SerializingChallenger32<
            $field,
            p3_challenger::HashChallenger<u8, $crate::ff::StarkByteHash, 32>,
        >;
        pub type $dft = p3_dft::Radix2DitParallel<$field>;
        pub type $pcs = p3_fri::HidingFriPcs<
            $field,
            $dft,
            $val_mmcs,
            $challenge_mmcs,
            $crate::rng::ChaChaCsrng,
        >;
        pub type $stark_config = p3_uni_stark::StarkConfig<$pcs, $challenge, $challenger>;

        impl<P> $config<P>
        where
            P: crate::security_profile::SecurityProfile,
        {
            pub fn prover_config() -> $stark_config {
                Self::prover_config_with_security_parameters(P::security_parameters())
            }

            pub fn prover_config_with_security_parameters(
                security_parameters: $crate::security_profile::SecurityParameters,
            ) -> $stark_config {
                $crate::ff::stark_config!(
                    $crate::rng::ChaChaCsrng::from_entropy(),
                    $crate::rng::ChaChaCsrng::from_entropy(),
                    security_parameters,
                    $val_mmcs,
                    $challenge_mmcs,
                    $pcs,
                    $dft,
                    $challenger,
                    $stark_config,
                )
            }

            pub fn verifier_config() -> $stark_config {
                Self::verifier_config_with_security_parameters(P::security_parameters())
            }

            pub fn verifier_config_with_security_parameters(
                security_parameters: crate::security_profile::SecurityParameters,
            ) -> $stark_config {
                $crate::ff::stark_config!(
                    $crate::rng::ChaChaCsrng::from_seed_u64($crate::ff::PLACEHOLDER_MMCS_SEED),
                    $crate::rng::ChaChaCsrng::from_seed_u64($crate::ff::PLACEHOLDER_PCS_SEED),
                    security_parameters,
                    $val_mmcs,
                    $challenge_mmcs,
                    $pcs,
                    $dft,
                    $challenger,
                    $stark_config,
                )
            }
        }
    };
}

#[cfg(feature = "p3-baby-bear")]
define_field_config!(
    BabyBearConfig,
    p3_baby_bear::BabyBear,
    BabyBearChallenge,
    BabyBearTranscriptHash,
    BabyBearTranscriptCompress,
    BabyBearValMmcs,
    BabyBearChallengeMmcs,
    BabyBearChallenger,
    BabyBearDft,
    BabyBearPcs,
    BabyBearStarkConfig,
);

#[cfg(feature = "p3-koala-bear")]
define_field_config!(
    KoalaBearConfig,
    p3_koala_bear::KoalaBear,
    KoalaBearChallenge,
    KoalaBearTranscriptHash,
    KoalaBearTranscriptCompress,
    KoalaBearValMmcs,
    KoalaBearChallengeMmcs,
    KoalaBearChallenger,
    KoalaBearDft,
    KoalaBearPcs,
    KoalaBearStarkConfig,
);

use p3_keccak::{Keccak256Hash, KeccakF};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};

pub(crate) use crate::rng::{PLACEHOLDER_MMCS_SEED, PLACEHOLDER_PCS_SEED};

pub type StarkByteHash = Keccak256Hash;
pub type StarkU64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
pub type StarkFieldHash = SerializingHasher<StarkU64Hash>;
pub type StarkCompress = CompressionFunctionFromHasher<StarkU64Hash, 2, 4>;

/// Builds a concrete STARK config from RNGs, security parameters, MMCS/PCS types, DFT, challenger, and optional hiding codeword count.
macro_rules! stark_config {
    (
        $mmcs_rng:expr,
        $pcs_rng:expr,
        $security_parameters:expr,
        $val_mmcs:ty,
        $challenge_mmcs:ty,
        $pcs:ty,
        $dft:ty,
        $challenger:ty,
        $stark_config:ty,
    ) => {{
        let hiding_random_codewords = <<$stark_config as p3_uni_stark::StarkGenericConfig>::Challenge as p3_field::BasedVectorSpace<p3_uni_stark::Val<$stark_config>>>::DIMENSION;
        $crate::ff::stark_config!(
            $mmcs_rng,
            $pcs_rng,
            $security_parameters,
            hiding_random_codewords,
            $val_mmcs,
            $challenge_mmcs,
            $pcs,
            $dft,
            $challenger,
            $stark_config,
        )
    }};
    (
        $mmcs_rng:expr,
        $pcs_rng:expr,
        $security_parameters:expr,
        $hiding_random_codewords:expr,
        $val_mmcs:ty,
        $challenge_mmcs:ty,
        $pcs:ty,
        $dft:ty,
        $challenger:ty,
        $stark_config:ty,
    ) => {{
        let byte_hash = $crate::ff::StarkByteHash {};
        let u64_hash = $crate::ff::StarkU64Hash::new(p3_keccak::KeccakF {});
        let hash = $crate::ff::StarkFieldHash::new(u64_hash);
        let compress = $crate::ff::StarkCompress::new(u64_hash);
        let val_mmcs = <$val_mmcs>::new(hash, compress, 0, $mmcs_rng);
        let challenge_mmcs = <$challenge_mmcs>::new(val_mmcs.clone());
        let fri_params = $security_parameters.fri_params_zk(challenge_mmcs);
        let pcs = <$pcs>::new(
            <$dft>::default(),
            val_mmcs,
            fri_params,
            $hiding_random_codewords,
            $pcs_rng,
        );
        let challenger = <$challenger>::from_hasher(alloc::vec::Vec::new(), byte_hash);
        <$stark_config>::new(pcs, challenger)
    }};
}

pub(crate) use stark_config;
