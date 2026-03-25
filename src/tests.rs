use crate::{
    poseidon2::{
        BabyBearPoseidon2Backend, BabyBearPoseidon2_16HashAir, KoalaBearPoseidon2Backend,
        KoalaBearPoseidon2_16HashAir, POSEIDON2_16_WIDTH,
    },
    relation, HashInvocationAir, RelationChallenge, RelationField, StarkRelationBackend,
};
use alloc::vec::Vec;
use p3_air::SymbolicExpressionExt;
#[cfg(feature = "keccak")]
use p3_field::PrimeField64;
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing};
use spongefish::{Permutation, Unit};
use spongefish_circuit::{
    allocator::FieldVar,
    permutation::{LinearEquation, PermutationInstanceBuilder, PermutationWitnessBuilder},
};
use spongefish_poseidon2::{BabyBearPoseidon2_16, KoalaBearPoseidon2_16};

const TEST_LINEAR_WIDTH: usize = 1;

#[cfg(feature = "keccak")]
type RelationCase<B, const WIDTH: usize> =
    ([RelationField<B>; WIDTH], Vec<(usize, RelationField<B>)>);

#[cfg(feature = "keccak")]
/// Source hashes generated via https://emn178.github.io/online-tools/keccak_256.html
const KECCAK256_PREIMAGE_VECTORS: [(&str, &str); 4] = [
    (
        "testing",
        "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
    ),
    (
        "foobar",
        "38d18acb67d25c8bb9942764b62f18e17054f66a817bd4295423adf9ed98873e",
    ),
    (
        "spongefish test",
        "3a0b0512da20c3b789806be8538789ae85550f63d034b1a6ba242f018a079c9f",
    ),
    (
        "abcdefghilmn",
        "f560efad31de65af6d82893de70a71a7f32e72b9ea44c3b42fe2da5f641845e5",
    ),
];

#[derive(Clone)]
struct WrongOutputPermutation<P>(P);

impl<P, const WIDTH: usize> Permutation<WIDTH> for WrongOutputPermutation<P>
where
    P: Permutation<WIDTH>,
    P::U: Field + Unit + PrimeCharacteristicRing,
{
    type U = P::U;

    fn permute(&self, state: &[Self::U; WIDTH]) -> [Self::U; WIDTH] {
        let mut output = self.0.permute(state);
        output[0] += <Self::U as PrimeCharacteristicRing>::ONE;
        output
    }
}

fn sample_input<F, const WIDTH: usize>() -> [F; WIDTH]
where
    F: Field + Unit + PartialEq,
{
    core::array::from_fn(|i| F::from_usize(i + 1))
}

#[cfg(feature = "keccak")]
fn decode_hex_32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "expected 32-byte hex digest");
    core::array::from_fn(|i| {
        let hi = hex.as_bytes()[2 * i];
        let lo = hex.as_bytes()[2 * i + 1];
        (decode_hex_nibble(hi) << 4) | decode_hex_nibble(lo)
    })
}

#[cfg(feature = "keccak")]
const fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

#[cfg(feature = "keccak")]
fn keccak256_single_block_input<F>(message: &str) -> [F; 100]
where
    F: PrimeField64 + Unit,
{
    const RATE_BYTES: usize = 136;
    let message = message.as_bytes();
    assert!(
        message.len() < RATE_BYTES,
        "test helper only supports one Keccak-256 block"
    );

    let mut block = [0u8; 200];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;

    core::array::from_fn(|idx| {
        let limb_offset = idx * 2;
        let limb = u16::from_le_bytes([block[limb_offset], block[limb_offset + 1]]);
        F::from_u16(limb)
    })
}

#[cfg(feature = "keccak")]
fn keccak256_public_outputs<B>(digest: [u8; 32]) -> Vec<(usize, RelationField<B>)>
where
    B: StarkRelationBackend,
    RelationField<B>: PrimeField64 + Field + Unit + PartialEq + Send + Sync,
{
    (0..16)
        .map(|idx| {
            let limb = u16::from_le_bytes([digest[2 * idx], digest[2 * idx + 1]]);
            (idx, RelationField::<B>::from_u16(limb))
        })
        .collect()
}

#[cfg(feature = "keccak")]
fn keccak256_digest_from_state<F>(state: &[F; 100]) -> [u8; 32]
where
    F: PrimeField64,
{
    let mut digest = [0u8; 32];
    for limb_idx in 0..16 {
        let limb = state[limb_idx].as_canonical_u64() as u16;
        let bytes = limb.to_le_bytes();
        digest[2 * limb_idx] = bytes[0];
        digest[2 * limb_idx + 1] = bytes[1];
    }
    digest
}

#[cfg(feature = "keccak")]
fn keccak256_vector_cases<B>() -> Vec<RelationCase<B, 100>>
where
    B: StarkRelationBackend,
    RelationField<B>: PrimeField64 + Field + Unit + PartialEq + Send + Sync,
{
    KECCAK256_PREIMAGE_VECTORS
        .iter()
        .map(|(message, expected_digest_hex)| {
            let input = keccak256_single_block_input::<RelationField<B>>(message);
            let expected_digest = decode_hex_32(expected_digest_hex);
            let public_outputs = keccak256_public_outputs::<B>(expected_digest);
            (input, public_outputs)
        })
        .collect()
}

#[cfg(feature = "keccak")]
fn build_private_input_relation_instance_and_witness<
    B,
    P,
    const WIDTH: usize,
    const LIN_WIDTH: usize,
>(
    permutation: P,
    cases: impl IntoIterator<Item = RelationCase<B, WIDTH>>,
) -> (
    PermutationInstanceBuilder<RelationField<B>, WIDTH>,
    PermutationWitnessBuilder<P, WIDTH>,
)
where
    B: StarkRelationBackend,
    P: Permutation<WIDTH, U = RelationField<B>>,
    RelationField<B>: Field + Unit + PartialEq + Send + Sync,
{
    let instance = PermutationInstanceBuilder::<RelationField<B>, WIDTH>::new();
    let witness = PermutationWitnessBuilder::<P, WIDTH>::new(permutation);

    for (input, public_outputs) in cases {
        let input_vars = instance.allocator().allocate_vars::<WIDTH>();
        let output_vars = instance.allocate_permutation(&input_vars);
        let output_vals = witness.allocate_permutation(&input);

        instance.allocator().set_public_vars(
            public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
            public_outputs.iter().map(|(_, val)| *val),
        );

        instance.add_equation(LinearEquation::new(
            core::iter::once((
                <RelationField<B> as PrimeCharacteristicRing>::ONE,
                output_vars[0],
            ))
            .chain((1..LIN_WIDTH).map(|_| {
                (
                    <RelationField<B> as PrimeCharacteristicRing>::ZERO,
                    FieldVar(0),
                )
            })),
            output_vals[0],
        ));
        witness.add_equation(LinearEquation::new(
            core::iter::once((
                <RelationField<B> as PrimeCharacteristicRing>::ONE,
                output_vals[0],
            ))
            .chain((1..LIN_WIDTH).map(|_| {
                (
                    <RelationField<B> as PrimeCharacteristicRing>::ZERO,
                    <RelationField<B> as PrimeCharacteristicRing>::ZERO,
                )
            })),
            output_vals[0],
        ));
    }

    (instance, witness)
}

fn build_relation_instance_and_witness<B, P, const WIDTH: usize, const LIN_WIDTH: usize>(
    permutation: P,
    input: [RelationField<B>; WIDTH],
    public_outputs: &[(usize, RelationField<B>)],
) -> (
    PermutationInstanceBuilder<RelationField<B>, WIDTH>,
    PermutationWitnessBuilder<P, WIDTH>,
)
where
    B: StarkRelationBackend,
    P: Permutation<WIDTH, U = RelationField<B>>,
    RelationField<B>: Field + Unit + PartialEq + Send + Sync,
{
    let instance = PermutationInstanceBuilder::<RelationField<B>, WIDTH>::new();
    let witness = PermutationWitnessBuilder::<P, WIDTH>::new(permutation);

    let input_vars = instance.allocator().allocate_public::<WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        public_outputs.iter().map(|(idx, _)| output_vars[*idx]),
        public_outputs.iter().map(|(_, val)| *val),
    );

    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        ))
        .chain((1..LIN_WIDTH).map(|_| {
            (
                <RelationField<B> as PrimeCharacteristicRing>::ZERO,
                FieldVar(0),
            )
        })),
        output_vals[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<B> as PrimeCharacteristicRing>::ONE,
            output_vals[0],
        ))
        .chain((1..LIN_WIDTH).map(|_| {
            (
                <RelationField<B> as PrimeCharacteristicRing>::ZERO,
                <RelationField<B> as PrimeCharacteristicRing>::ZERO,
            )
        })),
        output_vals[0],
    ));

    (instance, witness)
}

fn run_hash_relation_checks<B, H, P, const WIDTH: usize, const LIN_WIDTH: usize>(
    backend: &B,
    hash: &H,
    permutation: P,
) where
    B: StarkRelationBackend,
    H: HashInvocationAir<RelationField<B>, WIDTH> + Sync,
    P: Permutation<WIDTH, U = RelationField<B>> + Clone,
    RelationField<B>: Field + Unit + PartialEq + Send + Sync,
    RelationChallenge<B>: BasedVectorSpace<RelationField<B>>,
    SymbolicExpressionExt<RelationField<B>, RelationChallenge<B>>: Algebra<RelationChallenge<B>>,
{
    let input = sample_input::<RelationField<B>, WIDTH>();
    let expected_output = permutation.permute(&input);
    let public_outputs = Vec::from([
        (1usize, expected_output[1]),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);

    let (instance, witness) = build_relation_instance_and_witness::<B, P, WIDTH, LIN_WIDTH>(
        permutation.clone(),
        input,
        &public_outputs,
    );

    let proof = relation::prove::<B, H, P, WIDTH, LIN_WIDTH>(backend, hash, &instance, &witness);
    assert!(relation::verify::<B, H, WIDTH, LIN_WIDTH>(backend, hash, &instance, &proof).is_ok());

    let mut bad_proof = proof.clone();
    bad_proof[0] ^= 0x01;
    assert!(
        relation::verify::<B, H, WIDTH, LIN_WIDTH>(backend, hash, &instance, &bad_proof).is_err()
    );

    let bad_public_outputs = Vec::from([
        (
            1usize,
            expected_output[1] + <RelationField<B> as PrimeCharacteristicRing>::ONE,
        ),
        (2usize, expected_output[2]),
        (3usize, expected_output[3]),
    ]);
    let (bad_instance, _) = build_relation_instance_and_witness::<B, P, WIDTH, LIN_WIDTH>(
        permutation,
        input,
        &bad_public_outputs,
    );
    assert!(
        relation::verify::<B, H, WIDTH, LIN_WIDTH>(backend, hash, &bad_instance, &proof).is_err()
    );

    let mut shifted_proof = proof;
    shifted_proof.insert(0, 0x00);
    assert!(
        relation::verify::<B, H, WIDTH, LIN_WIDTH>(backend, hash, &instance, &shifted_proof)
            .is_err()
    );
}

#[test]
fn poseidon2_16_relation_proof_and_false_checks() {
    run_hash_relation_checks::<
        BabyBearPoseidon2Backend,
        BabyBearPoseidon2_16HashAir,
        BabyBearPoseidon2_16,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(
        &BabyBearPoseidon2Backend::default(),
        &BabyBearPoseidon2_16HashAir::default(),
        BabyBearPoseidon2_16::default(),
    );

    run_hash_relation_checks::<
        KoalaBearPoseidon2Backend,
        KoalaBearPoseidon2_16HashAir,
        KoalaBearPoseidon2_16,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(
        &KoalaBearPoseidon2Backend::default(),
        &KoalaBearPoseidon2_16HashAir::default(),
        KoalaBearPoseidon2_16::default(),
    );
}

#[cfg(feature = "keccak")]
#[test]
fn keccak256_single_block_vectors_match_reference() {
    use crate::keccak::KeccakF1600Permutation;

    type B = BabyBearPoseidon2Backend;
    let permutation = KeccakF1600Permutation::<RelationField<B>>::default();

    for (message, expected_digest_hex) in KECCAK256_PREIMAGE_VECTORS {
        let input = keccak256_single_block_input::<RelationField<B>>(message);
        let output = permutation.permute(&input);
        assert_eq!(
            keccak256_digest_from_state(&output),
            decode_hex_32(expected_digest_hex),
            "Keccak-256 digest mismatch for message {message:?}"
        );
    }
}

#[cfg(feature = "keccak")]
#[test]
fn keccak256_secret_preimage_relation_keeps_inputs_private() {
    use crate::keccak::{KeccakF1600Permutation, KECCAK_WIDTH};

    type B = BabyBearPoseidon2Backend;
    let cases = keccak256_vector_cases::<B>();

    let (instance, witness) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            KeccakF1600Permutation::<RelationField<B>>::default(),
            vec![cases[0].clone()],
        );

    let public_vars = instance.public_vars();
    assert_eq!(public_vars.len(), 1 + 16);
    assert!(public_vars
        .iter()
        .all(|(var, _)| var.0 == 0 || var.0 > KECCAK_WIDTH));

    let witness_trace = witness.trace();
    let output = witness_trace.as_ref()[0].output;
    assert_eq!(
        keccak256_digest_from_state(&output),
        decode_hex_32(KECCAK256_PREIMAGE_VECTORS[0].1)
    );
}

#[cfg(feature = "keccak")]
#[test]
fn keccak256_secret_preimages_match_documented_vectors_in_one_proof() {
    use crate::keccak::{KeccakF1600HashAir, KeccakF1600Permutation, KECCAK_WIDTH};

    type B = BabyBearPoseidon2Backend;
    let backend = B::default();
    let hash = KeccakF1600HashAir::<RelationField<B>>::default();
    let permutation = KeccakF1600Permutation::<RelationField<B>>::default();

    let cases = keccak256_vector_cases::<B>();
    let (instance, witness) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            permutation,
            cases.clone(),
        );

    // Only the digest limbs should be public, not the 100-limb padded preimages.
    assert_eq!(
        instance.public_vars().len(),
        1 + 16 * KECCAK256_PREIMAGE_VECTORS.len()
    );

    let proof = relation::prove::<B, _, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
        &backend, &hash, &instance, &witness,
    );
    assert!(relation::verify::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
        &backend, &hash, &instance, &proof
    )
    .is_ok());

    let mut bad_cases = cases;
    bad_cases[0].1[0].1 += <RelationField<B> as PrimeCharacteristicRing>::ONE;
    let (bad_instance, _) =
        build_private_input_relation_instance_and_witness::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            KeccakF1600Permutation::<RelationField<B>>::default(),
            bad_cases,
        );
    assert!(relation::verify::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
        &backend,
        &hash,
        &bad_instance,
        &proof
    )
    .is_err());

    let mut bad_proof = proof;
    bad_proof[0] ^= 0x01;
    assert!(relation::verify::<B, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
        &backend, &hash, &instance, &bad_proof
    )
    .is_err());
}

#[cfg(feature = "keccak")]
#[test]
fn keccak_relation_rejects_non_16_bit_inputs() {
    use crate::keccak::{KeccakF1600HashAir, KeccakF1600Permutation, KECCAK_WIDTH};

    type B = BabyBearPoseidon2Backend;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let permutation = KeccakF1600Permutation::<RelationField<B>>::default();
        let hash = KeccakF1600HashAir::<RelationField<B>>::default();
        let input = core::array::from_fn(|i| {
            if i == 0 {
                RelationField::<B>::from_u32(1 << 20)
            } else {
                RelationField::<B>::from_u16(i as u16)
            }
        });
        let public_outputs = Vec::from([
            (1usize, <RelationField<B> as PrimeCharacteristicRing>::ZERO),
            (2usize, <RelationField<B> as PrimeCharacteristicRing>::ZERO),
            (3usize, <RelationField<B> as PrimeCharacteristicRing>::ZERO),
        ]);
        let (instance, witness) = build_relation_instance_and_witness::<
            B,
            _,
            KECCAK_WIDTH,
            TEST_LINEAR_WIDTH,
        >(permutation, input, &public_outputs);
        relation::prove::<B, _, _, KECCAK_WIDTH, TEST_LINEAR_WIDTH>(
            &BabyBearPoseidon2Backend::default(),
            &hash,
            &instance,
            &witness,
        )
    }));
    assert!(result.is_err());
}

#[test]
fn poseidon2_16_relation_rejects_wrong_witness_outputs() {
    let backend = BabyBearPoseidon2Backend::default();
    let hash = BabyBearPoseidon2_16HashAir::default();
    let permutation = BabyBearPoseidon2_16::default();
    let input = sample_input::<RelationField<BabyBearPoseidon2Backend>, POSEIDON2_16_WIDTH>();
    let expected_output = permutation.permute(&input);

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2Backend>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness = PermutationWitnessBuilder::<
        WrongOutputPermutation<BabyBearPoseidon2_16>,
        POSEIDON2_16_WIDTH,
    >::new(WrongOutputPermutation(permutation));

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let output_vars = instance.allocate_permutation(&input_vars);
    let wrong_output_vals = witness.allocate_permutation(&input);

    instance.allocator().set_public_vars(
        [
            (1usize, output_vars[1]),
            (2usize, output_vars[2]),
            (3usize, output_vars[3]),
        ]
        .into_iter()
        .map(|(_, var)| var),
        [expected_output[1], expected_output[2], expected_output[3]],
    );

    instance.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<BabyBearPoseidon2Backend> as PrimeCharacteristicRing>::ONE,
            output_vars[0],
        )),
        expected_output[0],
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::once((
            <RelationField<BabyBearPoseidon2Backend> as PrimeCharacteristicRing>::ONE,
            wrong_output_vals[0],
        )),
        wrong_output_vals[0],
    ));

    let worker = std::thread::spawn(move || {
        relation::prove::<
            BabyBearPoseidon2Backend,
            BabyBearPoseidon2_16HashAir,
            WrongOutputPermutation<BabyBearPoseidon2_16>,
            POSEIDON2_16_WIDTH,
            TEST_LINEAR_WIDTH,
        >(&backend, &hash, &instance, &witness)
    });

    assert!(worker.join().is_err());
}

#[test]
#[should_panic(expected = "must have exactly 1 terms")]
fn poseidon2_16_relation_panics_on_malformed_linear_constraints() {
    let backend = BabyBearPoseidon2Backend::default();
    let hash = BabyBearPoseidon2_16HashAir::default();
    let permutation = BabyBearPoseidon2_16::default();
    let input = sample_input::<RelationField<BabyBearPoseidon2Backend>, POSEIDON2_16_WIDTH>();

    let instance = PermutationInstanceBuilder::<
        RelationField<BabyBearPoseidon2Backend>,
        POSEIDON2_16_WIDTH,
    >::new();
    let witness =
        PermutationWitnessBuilder::<BabyBearPoseidon2_16, POSEIDON2_16_WIDTH>::new(permutation);

    let input_vars = instance
        .allocator()
        .allocate_public::<POSEIDON2_16_WIDTH>(&input);
    let _ = instance.allocate_permutation(&input_vars);
    let _ = witness.allocate_permutation(&input);

    instance.add_equation(LinearEquation::new(
        core::iter::empty::<(RelationField<BabyBearPoseidon2Backend>, FieldVar)>(),
        <RelationField<BabyBearPoseidon2Backend> as PrimeCharacteristicRing>::ZERO,
    ));
    witness.add_equation(LinearEquation::new(
        core::iter::empty::<(
            RelationField<BabyBearPoseidon2Backend>,
            RelationField<BabyBearPoseidon2Backend>,
        )>(),
        <RelationField<BabyBearPoseidon2Backend> as PrimeCharacteristicRing>::ZERO,
    ));

    let _ = relation::prove::<
        BabyBearPoseidon2Backend,
        BabyBearPoseidon2_16HashAir,
        BabyBearPoseidon2_16,
        POSEIDON2_16_WIDTH,
        TEST_LINEAR_WIDTH,
    >(&backend, &hash, &instance, &witness);
}
