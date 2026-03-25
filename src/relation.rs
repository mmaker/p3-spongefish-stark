use alloc::{boxed::Box, string::ToString, vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{
    Air, AirBuilder, AirLayout, BaseAir, SymbolicAirBuilder, SymbolicExpressionExt, WindowAccess,
};
use p3_batch_stark::{BatchProof, ProverData, StarkInstance};
use p3_field::{Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::{Direction, Kind, Lookup, LookupAir};
use p3_matrix::{
    dense::{DenseMatrix, RowMajorMatrix},
    Matrix,
};
use p3_uni_stark::StarkGenericConfig;
use spongefish::{Permutation, Unit, VerificationError, VerificationResult};
use spongefish_circuit::{
    allocator::FieldVar,
    permutation::{LinearConstraints, PermutationInstanceBuilder, PermutationWitnessBuilder},
};

use crate::{
    HashInvocationAir, QueryAnswerPair, RelationChallenge, RelationField, StarkRelationBackend,
};

/// The first lookup, checking that outputs re-appear as inputs.
pub const IO_LOOKUP_NAME: &str = "in-out";
/// The second lookup, checking that public variables are correctly assigned.
pub const PUB_LOOKUP_NAME: &str = "public-vars";
/// The third lookup, checking linear relations between inputs and outputs.
pub const LIN_LOOKUP_NAME: &str = "linear-constraints";

type LinearConstraintsInstance<F> = LinearConstraints<FieldVar, F>;
type LinearConstraintsWitness<F> = LinearConstraints<F, F>;

#[repr(C)]
struct LookupCols<T, const WIDTH: usize> {
    input_vars: [T; WIDTH],
    output_vars: [T; WIDTH],
    output_multiplicities: [T; WIDTH],
    input_multiplicities: [T; WIDTH],
    input_public: [T; WIDTH],
    output_public: [T; WIDTH],
    input_linear_constraints: [T; WIDTH],
    output_linear_constraints: [T; WIDTH],
}

#[repr(C)]
struct PublicLookupCols<T> {
    var: T,
    val: T,
    multiplicity: T,
}

#[repr(C)]
struct LinearConstraintCols<T, const LIN_WIDTH: usize> {
    linear_coefficients: [T; LIN_WIDTH],
    linear_combination: [T; LIN_WIDTH],
    image: T,
}

#[repr(C)]
struct LinearConstraintPreprocessedCols<T, const LIN_WIDTH: usize> {
    linear_vars: [T; LIN_WIDTH],
    image_value: T,
    linear_multiplicities: [T; LIN_WIDTH],
}

impl<T, const WIDTH: usize> Borrow<LookupCols<T, WIDTH>> for [T] {
    fn borrow(&self) -> &LookupCols<T, WIDTH> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<LookupCols<T, WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const WIDTH: usize> BorrowMut<LookupCols<T, WIDTH>> for [T] {
    fn borrow_mut(&mut self) -> &mut LookupCols<T, WIDTH> {
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<LookupCols<T, WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T> Borrow<PublicLookupCols<T>> for [T] {
    fn borrow(&self) -> &PublicLookupCols<T> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PublicLookupCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<PublicLookupCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PublicLookupCols<T> {
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<PublicLookupCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T, const LIN_WIDTH: usize> Borrow<LinearConstraintCols<T, LIN_WIDTH>> for [T] {
    fn borrow(&self) -> &LinearConstraintCols<T, LIN_WIDTH> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<LinearConstraintCols<T, LIN_WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const LIN_WIDTH: usize> BorrowMut<LinearConstraintCols<T, LIN_WIDTH>> for [T] {
    fn borrow_mut(&mut self) -> &mut LinearConstraintCols<T, LIN_WIDTH> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<LinearConstraintCols<T, LIN_WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<T, const LIN_WIDTH: usize> Borrow<LinearConstraintPreprocessedCols<T, LIN_WIDTH>> for [T] {
    fn borrow(&self) -> &LinearConstraintPreprocessedCols<T, LIN_WIDTH> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<LinearConstraintPreprocessedCols<T, LIN_WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const LIN_WIDTH: usize> BorrowMut<LinearConstraintPreprocessedCols<T, LIN_WIDTH>>
    for [T]
{
    fn borrow_mut(&mut self) -> &mut LinearConstraintPreprocessedCols<T, LIN_WIDTH> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<LinearConstraintPreprocessedCols<T, LIN_WIDTH>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

const fn num_lookup_cols<const WIDTH: usize>() -> usize {
    size_of::<LookupCols<u8, WIDTH>>()
}

const fn num_public_lookup_cols() -> usize {
    size_of::<PublicLookupCols<u8>>()
}

const fn num_linear_main_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintCols<u8, LIN_WIDTH>>()
}

const fn num_linear_preprocessed_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintPreprocessedCols<u8, LIN_WIDTH>>()
}

#[derive(Clone)]
struct HashLookupAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    hash: H,
    builder: PermutationInstanceBuilder<F, WIDTH>,
    linear_constraints: Option<LinearConstraintsInstance<F>>,
    trace_len: usize,
}

#[derive(Clone)]
struct PublicVarLookupAir<F, const WIDTH: usize> {
    instance: PermutationInstanceBuilder<F, WIDTH>,
    trace_len: usize,
}

#[derive(Clone)]
struct LinearConstraintsAir<F, const WIDTH: usize, const LIN_WIDTH: usize> {
    instance: PermutationInstanceBuilder<F, WIDTH>,
    constraints: LinearConstraintsInstance<F>,
    trace_len: usize,
}

#[derive(Clone)]
enum GenericHashRelationAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    Hash(Box<HashLookupAir<H, F, WIDTH, LIN_WIDTH>>),
    Public(PublicVarLookupAir<F, WIDTH>),
    Linear(LinearConstraintsAir<F, WIDTH, LIN_WIDTH>),
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> HashLookupAir<H, F, WIDTH, LIN_WIDTH> {
    fn new_with_linear(
        hash: H,
        builder: PermutationInstanceBuilder<F, WIDTH>,
        linear_constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
    ) -> Self {
        Self {
            hash,
            builder,
            linear_constraints: Some(linear_constraints),
            trace_len,
        }
    }
}

impl<F, const WIDTH: usize> PublicVarLookupAir<F, WIDTH> {
    fn new(instance: PermutationInstanceBuilder<F, WIDTH>, trace_len: usize) -> Self {
        assert!(trace_len.is_power_of_two());
        Self {
            instance,
            trace_len,
        }
    }
}

impl<F, const WIDTH: usize, const LIN_WIDTH: usize> LinearConstraintsAir<F, WIDTH, LIN_WIDTH> {
    fn new(
        instance: PermutationInstanceBuilder<F, WIDTH>,
        constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
    ) -> Self {
        assert!(trace_len.is_power_of_two());
        assert!(constraints.as_ref().len() <= trace_len);
        Self {
            instance,
            constraints,
            trace_len,
        }
    }
}

pub fn prove<B, H, P, const WIDTH: usize, const LIN_WIDTH: usize>(
    backend: &B,
    hash: &H,
    instance: &PermutationInstanceBuilder<RelationField<B>, WIDTH>,
    witness: &PermutationWitnessBuilder<P, WIDTH>,
) -> Vec<u8>
where
    B: StarkRelationBackend,
    H: HashInvocationAir<RelationField<B>, WIDTH> + Sync,
    P: Permutation<WIDTH, U = RelationField<B>>,
    RelationField<B>: Field + Unit + PartialEq + Send + Sync,
    RelationChallenge<B>: BasedVectorSpace<RelationField<B>>,
    SymbolicExpressionExt<RelationField<B>, RelationChallenge<B>>: Algebra<RelationChallenge<B>>,
{
    let logical_target_len = target_len_with_linear(instance);
    pad_witness_permutations(instance, witness, logical_target_len);
    let target_len = hash_trace_target_len(hash, instance).max(logical_target_len);
    let (mut airs, traces) =
        generate_trace_rows_with_linear::<H, RelationField<B>, P, WIDTH, LIN_WIDTH>(
            hash, instance, witness,
        );
    let traces = traces
        .into_iter()
        .map(|trace| pad_dense_matrix_to_height(trace, target_len))
        .collect::<Vec<_>>();
    let log_degrees = trace_degree_bits(&traces, target_len);
    let config = backend.config(2024);
    let log_ext_degrees = log_ext_degrees(&log_degrees, &config);
    let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &log_ext_degrees);
    let common = &prover_data.common;
    let publics = vec![Vec::new(); airs.len()];
    let trace_refs = traces.iter().collect::<Vec<_>>();
    let instances = StarkInstance::new_multiple(&airs, &trace_refs, &publics, common);
    let proof = p3_batch_stark::prove_batch(&config, &instances, &prover_data);
    postcard::to_allocvec(&proof).expect("proof serialization should succeed")
}

pub fn verify<B, H, const WIDTH: usize, const LIN_WIDTH: usize>(
    backend: &B,
    hash: &H,
    instance: &PermutationInstanceBuilder<RelationField<B>, WIDTH>,
    proof_bytes: &[u8],
) -> VerificationResult<()>
where
    B: StarkRelationBackend,
    H: HashInvocationAir<RelationField<B>, WIDTH> + Sync,
    RelationField<B>: Field + Unit + PartialEq + Send + Sync,
    RelationChallenge<B>: BasedVectorSpace<RelationField<B>>,
    SymbolicExpressionExt<RelationField<B>, RelationChallenge<B>>: Algebra<RelationChallenge<B>>,
{
    let linear_constraints = instance.linear_constraints();
    validate_linear_constraints::<LIN_WIDTH, _, _>(&linear_constraints, "instance");
    let config = backend.config(2024);
    let proof: BatchProof<B::Config> =
        postcard::from_bytes(proof_bytes).map_err(|_| VerificationError)?;
    let logical_target_len = target_len_with_linear(instance);
    pad_instance_permutations(instance, logical_target_len);
    let target_len = hash_trace_target_len(hash, instance).max(logical_target_len);
    if let Some(&log_degree) = proof.degree_bits.first() {
        let proof_len = 1usize << log_degree.saturating_sub(config.is_zk());
        assert_eq!(target_len, proof_len);
    }
    let mut airs = vec![
        GenericHashRelationAir::Hash(Box::new(HashLookupAir::<
            H,
            RelationField<B>,
            WIDTH,
            LIN_WIDTH,
        >::new_with_linear(
            hash.clone(),
            instance.clone(),
            linear_constraints.clone(),
            target_len,
        ))),
        GenericHashRelationAir::Public(PublicVarLookupAir::new(instance.clone(), target_len)),
        GenericHashRelationAir::Linear(
            LinearConstraintsAir::<RelationField<B>, WIDTH, LIN_WIDTH>::new(
                instance.clone(),
                linear_constraints,
                target_len,
            ),
        ),
    ];
    let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &proof.degree_bits);
    let publics = vec![Vec::new(); airs.len()];
    p3_batch_stark::verify_batch(&config, &airs, &proof, &publics, &prover_data.common)
        .map_err(|_| VerificationError)
}

fn generate_trace_rows_with_linear<H, F, P, const WIDTH: usize, const LIN_WIDTH: usize>(
    hash: &H,
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    witness: &PermutationWitnessBuilder<P, WIDTH>,
) -> (
    Vec<GenericHashRelationAir<H, F, WIDTH, LIN_WIDTH>>,
    Vec<DenseMatrix<F>>,
)
where
    H: HashInvocationAir<F, WIDTH> + Sync,
    P: Permutation<WIDTH, U = F>,
    F: Field + Unit + PartialEq + Send + Sync,
{
    let linear_constraints = instance.linear_constraints();
    let linear_witness = witness.linear_constraints();
    assert_eq!(
        linear_constraints.as_ref().len(),
        linear_witness.as_ref().len()
    );
    validate_linear_constraints::<LIN_WIDTH, _, _>(&linear_constraints, "instance");
    validate_linear_constraints::<LIN_WIDTH, _, _>(&linear_witness, "witness");

    let hash_trace = build_hash_lookup_trace(hash, witness);
    let trace_len = hash_trace.height().max(target_len_with_linear(instance));
    let trace = pad_dense_matrix_to_height(hash_trace, trace_len);
    let public_trace = build_public_lookup_main_trace::<F>(trace_len);
    let linear_trace = build_linear_constraints_trace::<F, LIN_WIDTH>(&linear_witness);

    let airs = vec![
        GenericHashRelationAir::Hash(Box::new(
            HashLookupAir::<H, F, WIDTH, LIN_WIDTH>::new_with_linear(
                hash.clone(),
                instance.clone(),
                linear_constraints.clone(),
                trace_len,
            ),
        )),
        GenericHashRelationAir::Public(PublicVarLookupAir::new(instance.clone(), trace_len)),
        GenericHashRelationAir::Linear(LinearConstraintsAir::<F, WIDTH, LIN_WIDTH>::new(
            instance.clone(),
            linear_constraints,
            trace_len,
        )),
    ];

    (airs, vec![trace, public_trace, linear_trace])
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for GenericHashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        match self {
            Self::Hash(air) => <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::width(air),
            Self::Public(air) => <PublicVarLookupAir<F, WIDTH> as BaseAir<F>>::width(air),
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as BaseAir<F>>::width(air)
            }
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
            Self::Public(air) => {
                <PublicVarLookupAir<F, WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as BaseAir<F>>::preprocessed_trace(air)
            }
        }
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        self.hash.main_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let input_outputs = self.builder.constraints();
        let vars_count = self.builder.allocator().vars_count();
        let output_count = input_outputs.as_ref().len();
        let rows_per_invocation = self.hash.trace_rows_per_invocation();
        let unpadded_rows = output_count * rows_per_invocation;
        let mut ptrace = DenseMatrix::new(
            vec![<F as PrimeCharacteristicRing>::ZERO; num_lookup_cols::<WIDTH>() * self.trace_len],
            num_lookup_cols::<WIDTH>(),
        );

        let public_multiplicities = public_multiplicities(&self.builder);
        let linear_multiplicities = self.linear_constraints.as_ref().map(lin_multiplicities);
        let linear_lookup_multiplicities = self.linear_constraints.as_ref().map(|constraints| {
            linear_lookup_multiplicities::<WIDTH>(
                input_outputs.as_ref(),
                &lin_multiplicities(constraints),
            )
        });
        let output_multiplicities = output_multiplicities(input_outputs.as_ref(), vars_count);
        let input_multiplicities = input_multiplicities(input_outputs.as_ref(), vars_count);
        let linear_inputs = linear_lookup_multiplicities
            .as_ref()
            .map(|(input, _)| input.clone())
            .unwrap_or_else(|| vec![[0; WIDTH]; output_count]);
        let linear_outputs = linear_lookup_multiplicities
            .as_ref()
            .map(|(_, output)| output.clone())
            .unwrap_or_else(|| vec![[0; WIDTH]; output_count]);

        for (row_idx, column) in ptrace.rows_mut().take(unpadded_rows).enumerate() {
            let pair_idx = row_idx / rows_per_invocation;
            let pair = &input_outputs.as_ref()[pair_idx];
            let output_mult = output_multiplicities[pair_idx];
            let input_mult = input_multiplicities[pair_idx];
            let linear_input = linear_inputs[pair_idx];
            let linear_output = linear_outputs[pair_idx];
            let lookup: &mut LookupCols<F, WIDTH> = column.borrow_mut();
            lookup.input_public = pair
                .input
                .map(|var| F::from_bool(public_multiplicities[var.0].is_some()));
            lookup.output_public = pair
                .output
                .map(|var| F::from_bool(public_multiplicities[var.0].is_some()));
            lookup.input_vars = pair.input.map(|var| F::from_usize(var.0));
            lookup.output_vars = pair.output.map(|var| F::from_usize(var.0));
            lookup.output_multiplicities = output_mult.map(F::from_usize);
            lookup.input_multiplicities = input_mult.map(F::from_usize);
            lookup.input_linear_constraints = match &linear_multiplicities {
                Some(_) => linear_input.map(F::from_usize),
                None => core::array::from_fn(|_| <F as PrimeCharacteristicRing>::ZERO),
            };
            lookup.output_linear_constraints = match &linear_multiplicities {
                Some(_) => linear_output.map(F::from_usize),
                None => core::array::from_fn(|_| <F as PrimeCharacteristicRing>::ZERO),
            };
        }

        Some(ptrace)
    }
}

impl<F, const WIDTH: usize> BaseAir<F> for PublicVarLookupAir<F, WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        1
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let trace = build_public_lookup_table_trace(&self.instance);
        Some(pad_dense_matrix_to_height(trace, self.trace_len))
    }
}

impl<F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for LinearConstraintsAir<F, WIDTH, LIN_WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn width(&self) -> usize {
        num_linear_main_cols::<LIN_WIDTH>()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let trace =
            build_lin_lookup_trace::<F, WIDTH, LIN_WIDTH>(&self.instance, &self.constraints);
        Some(pad_dense_matrix_to_height(trace, self.trace_len))
    }
}

impl<AB, H, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for GenericHashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    AB: AirBuilder<F = F>,
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as Air<AB>>::eval(air, builder)
            }
            Self::Public(air) => <PublicVarLookupAir<F, WIDTH> as Air<AB>>::eval(air, builder),
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as Air<AB>>::eval(air, builder)
            }
        }
    }
}

impl<AB, H, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    AB: AirBuilder<F = F>,
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        self.hash.eval(builder);
    }
}

impl<AB, F, const WIDTH: usize> Air<AB> for PublicVarLookupAir<F, WIDTH>
where
    AB: AirBuilder<F = F>,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, _builder: &mut AB) {}
}

impl<AB, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for LinearConstraintsAir<F, WIDTH, LIN_WIDTH>
where
    AB: AirBuilder<F = F>,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &LinearConstraintCols<_, LIN_WIDTH> = main.current_slice().borrow();
        let preprocessed = builder.preprocessed();
        let prep: &LinearConstraintPreprocessedCols<_, LIN_WIDTH> =
            preprocessed.current_slice().borrow();
        let image_value = prep.image_value;
        let mut sum = AB::Expr::ZERO;
        for i in 0..LIN_WIDTH {
            sum += local.linear_coefficients[i] * local.linear_combination[i];
        }
        builder.assert_eq(sum, local.image);
        builder.assert_eq(local.image, image_value);
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> LookupAir<F>
    for GenericHashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as LookupAir<F>>::add_lookup_columns(air)
            }
            Self::Public(air) => {
                <PublicVarLookupAir<F, WIDTH> as LookupAir<F>>::add_lookup_columns(air)
            }
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as LookupAir<F>>::add_lookup_columns(air)
            }
        }
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        match self {
            Self::Hash(air) => {
                <HashLookupAir<H, F, WIDTH, LIN_WIDTH> as LookupAir<F>>::get_lookups(air)
            }
            Self::Public(air) => <PublicVarLookupAir<F, WIDTH> as LookupAir<F>>::get_lookups(air),
            Self::Linear(air) => {
                <LinearConstraintsAir<F, WIDTH, LIN_WIDTH> as LookupAir<F>>::get_lookups(air)
            }
        }
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> LookupAir<F>
    for HashLookupAir<H, F, WIDTH, LIN_WIDTH>
where
    H: HashInvocationAir<F, WIDTH> + Sync,
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            preprocessed_width: num_lookup_cols::<WIDTH>(),
            main_width: BaseAir::<F>::width(self),
            ..Default::default()
        });
        let main = symbolic.main();
        let row = main.row_slice(0).expect("symbolic row should exist");
        let frame = self.hash.row_frame(&row);
        let invocation = self.hash.invocation::<SymbolicAirBuilder<F>>(&frame);
        let selector = self.hash.lookup_selector::<SymbolicAirBuilder<F>>(&frame);
        let preprocessed = symbolic.preprocessed();
        let lookup_row = preprocessed
            .row_slice(0)
            .expect("symbolic row should exist");
        let lookup_column: &LookupCols<_, WIDTH> = (*lookup_row).borrow();
        type Expr<F> = <SymbolicAirBuilder<F> as AirBuilder>::Expr;

        let mut lookups = Vec::new();
        for i in 0..WIDTH {
            let input = invocation.input[i].clone();
            let output = invocation.output[i].clone();
            let input_var = lookup_column.input_vars[i];
            let output_var = lookup_column.output_vars[i];
            let input_multiplicity = lookup_column.input_multiplicities[i];
            let output_multiplicity = lookup_column.output_multiplicities[i];
            let input_public = lookup_column.input_public[i];
            let output_public = lookup_column.output_public[i];
            let input_linear = lookup_column.input_linear_constraints[i];
            let output_linear = lookup_column.output_linear_constraints[i];
            let input_multiplicity: Expr<F> = input_multiplicity.into();
            let output_multiplicity: Expr<F> = output_multiplicity.into();
            let input_public: Expr<F> = input_public.into();
            let output_public: Expr<F> = output_public.into();
            let input_linear: Expr<F> = input_linear.into();
            let output_linear: Expr<F> = output_linear.into();

            lookups.push(Lookup::new(
                Kind::Global(IO_LOOKUP_NAME.to_string()),
                vec![
                    vec![input_var.into(), input.clone()],
                    vec![output_var.into(), output.clone()],
                ],
                vec![
                    Direction::Send.multiplicity(selector.clone() * input_multiplicity),
                    Direction::Receive.multiplicity(selector.clone() * output_multiplicity),
                ],
                vec![3 * i],
            ));
            lookups.push(Lookup::new(
                Kind::Global(PUB_LOOKUP_NAME.to_string()),
                vec![
                    vec![output_var.into(), output.clone()],
                    vec![input_var.into(), input.clone()],
                ],
                vec![
                    Direction::Send.multiplicity(selector.clone() * output_public),
                    Direction::Send.multiplicity(selector.clone() * input_public),
                ],
                vec![3 * i + 1],
            ));
            lookups.push(Lookup::new(
                Kind::Global(LIN_LOOKUP_NAME.to_string()),
                vec![
                    vec![input_var.into(), input],
                    vec![output_var.into(), output],
                ],
                vec![
                    Direction::Send.multiplicity(selector.clone() * input_linear),
                    Direction::Send.multiplicity(selector.clone() * output_linear),
                ],
                vec![3 * i + 2],
            ));
        }
        lookups
    }
}

impl<F, const WIDTH: usize> LookupAir<F> for PublicVarLookupAir<F, WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            preprocessed_width: num_public_lookup_cols(),
            main_width: BaseAir::<F>::width(self),
            ..Default::default()
        });
        let preprocessed = symbolic.preprocessed();
        let row = preprocessed
            .row_slice(0)
            .expect("symbolic preprocessed row should exist");
        let public_column: &PublicLookupCols<_> = (*row).borrow();
        vec![Lookup::new(
            Kind::Global(PUB_LOOKUP_NAME.to_string()),
            vec![vec![public_column.var.into(), public_column.val.into()]],
            vec![Direction::Receive.multiplicity(public_column.multiplicity.into())],
            vec![0],
        )]
    }
}

impl<F, const WIDTH: usize, const LIN_WIDTH: usize> LookupAir<F>
    for LinearConstraintsAir<F, WIDTH, LIN_WIDTH>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let symbolic = SymbolicAirBuilder::<F>::new(AirLayout {
            preprocessed_width: num_linear_preprocessed_cols::<LIN_WIDTH>(),
            main_width: BaseAir::<F>::width(self),
            ..Default::default()
        });
        let main = symbolic.main();
        let row = main.row_slice(0).expect("symbolic row should exist");
        let main_cols: &LinearConstraintCols<_, LIN_WIDTH> = (*row).borrow();
        let preprocessed = symbolic.preprocessed();
        let pre_row = preprocessed
            .row_slice(0)
            .expect("symbolic row should exist");
        let pre_cols: &LinearConstraintPreprocessedCols<_, LIN_WIDTH> = (*pre_row).borrow();

        let mut entries = Vec::with_capacity(LIN_WIDTH);
        for i in 0..LIN_WIDTH {
            entries.push((
                vec![
                    pre_cols.linear_vars[i].into(),
                    main_cols.linear_combination[i].into(),
                ],
                pre_cols.linear_multiplicities[i].into(),
                Direction::Receive,
            ));
        }
        let (element_exprs, multiplicities_exprs): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .map(|(elements, multiplicity, direction)| {
                (elements, direction.multiplicity(multiplicity))
            })
            .unzip();
        vec![Lookup::new(
            Kind::Global(LIN_LOOKUP_NAME.to_string()),
            element_exprs,
            multiplicities_exprs,
            vec![0],
        )]
    }
}

fn build_hash_lookup_trace<H, F, P, const WIDTH: usize>(
    hash: &H,
    witness: &PermutationWitnessBuilder<P, WIDTH>,
) -> DenseMatrix<F>
where
    H: HashInvocationAir<F, WIDTH>,
    P: Permutation<WIDTH, U = F>,
    F: Field,
{
    hash.build_trace(witness, 2)
}

fn build_public_lookup_table_trace<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    let public_multiplicities = public_multiplicities(instance);
    let public_vars = instance.public_vars();
    let width = num_public_lookup_cols();
    let height = public_vars.len().next_power_of_two().max(1);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * height];

    for (row_idx, (var, val)) in public_vars.iter().enumerate() {
        let multiplicity = public_multiplicities[var.0].unwrap_or(0);
        let offset = row_idx * width;
        values[offset] = F::from_usize(var.0);
        values[offset + 1] = *val;
        values[offset + 2] = F::from_usize(multiplicity);
    }

    DenseMatrix::new(values, width)
}

fn build_public_lookup_main_trace<F>(trace_len: usize) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    assert!(trace_len.is_power_of_two());
    DenseMatrix::new(vec![<F as PrimeCharacteristicRing>::ZERO; trace_len], 1)
}

fn build_lin_lookup_trace<F, const WIDTH: usize, const LIN_WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    lc: &LinearConstraintsInstance<F>,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    validate_linear_constraints::<LIN_WIDTH, _, _>(lc, "instance");
    let constraints_len = lc.as_ref().len();
    let width = num_linear_preprocessed_cols::<LIN_WIDTH>();
    let height = constraints_len.next_power_of_two().max(1);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * height];
    let _ = instance;

    for (row_idx, equation) in lc.as_ref().iter().enumerate() {
        let linear_vars = core::array::from_fn(|i| equation.linear_combination[i].1);
        let linear_multiplicities = core::array::from_fn(|i| {
            if equation.linear_combination[i].0 == <F as PrimeCharacteristicRing>::ZERO {
                <F as PrimeCharacteristicRing>::ZERO
            } else {
                <F as PrimeCharacteristicRing>::ONE
            }
        });
        let offset = row_idx * width;
        let row = &mut values[offset..offset + width];
        let column: &mut LinearConstraintPreprocessedCols<F, LIN_WIDTH> = row.borrow_mut();
        column.linear_vars = linear_vars.map(|var| F::from_usize(var.0));
        column.image_value = equation.image;
        column.linear_multiplicities = linear_multiplicities;
    }

    DenseMatrix::new(values, width)
}

fn build_linear_constraints_trace<F, const LIN_WIDTH: usize>(
    lc: &LinearConstraintsWitness<F>,
) -> DenseMatrix<F>
where
    F: Field + Unit + PartialEq + Send + Sync,
{
    validate_linear_constraints::<LIN_WIDTH, _, _>(lc, "witness");
    let constraints_len = lc.as_ref().len();
    let width = num_linear_main_cols::<LIN_WIDTH>();
    let height = constraints_len.next_power_of_two().max(1);
    let mut values = vec![<F as PrimeCharacteristicRing>::ZERO; width * height];

    for (row_idx, equation) in lc.as_ref().iter().enumerate() {
        let linear_coefficients = core::array::from_fn(|i| equation.linear_combination[i].0);
        let linear_values = core::array::from_fn(|i| equation.linear_combination[i].1);
        let offset = row_idx * width;
        let row = &mut values[offset..offset + width];
        let column: &mut LinearConstraintCols<F, LIN_WIDTH> = row.borrow_mut();
        column.linear_coefficients = linear_coefficients;
        column.linear_combination = linear_values;
        column.image = equation.image;
    }

    DenseMatrix::new(values, width)
}

fn output_multiplicities<const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    vars_count: usize,
) -> Vec<[usize; WIDTH]> {
    let multiplicities = multiplicities(constraints, vars_count);
    constraints
        .iter()
        .map(|pair| pair.output.map(|var| multiplicities[var.0]))
        .collect()
}

fn input_multiplicities<const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    vars_count: usize,
) -> Vec<[usize; WIDTH]> {
    let mut outputs = vec![false; vars_count];
    for pair in constraints {
        for var in pair.output {
            outputs[var.0] = true;
        }
    }

    constraints
        .iter()
        .map(|pair| pair.input.map(|var| usize::from(outputs[var.0])))
        .collect()
}

fn multiplicities<const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    vars_count: usize,
) -> Vec<usize> {
    let mut mult = vec![0; vars_count];
    for input_var in constraints.iter().flat_map(|pair| pair.input.iter()) {
        mult[input_var.0] += 1;
    }
    mult
}

fn linear_lookup_multiplicities<const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    linear_counts: &[Option<usize>],
) -> (Vec<[usize; WIDTH]>, Vec<[usize; WIDTH]>) {
    let mut remaining = linear_counts
        .iter()
        .map(|count| count.unwrap_or(0))
        .collect::<Vec<_>>();
    let mut input_multiplicities = Vec::with_capacity(constraints.len());
    let mut output_multiplicities = Vec::with_capacity(constraints.len());

    for pair in constraints {
        let mut input_counts = [0; WIDTH];
        let mut output_counts = [0; WIDTH];

        for (slot, var) in input_counts.iter_mut().zip(pair.input.iter()) {
            let count = remaining.get_mut(var.0).map_or(0, core::mem::take);
            *slot = count;
        }
        for (slot, var) in output_counts.iter_mut().zip(pair.output.iter()) {
            let count = remaining.get_mut(var.0).map_or(0, core::mem::take);
            *slot = count;
        }

        input_multiplicities.push(input_counts);
        output_multiplicities.push(output_counts);
    }

    debug_assert!(remaining.into_iter().all(|count| count == 0));
    (input_multiplicities, output_multiplicities)
}

fn public_multiplicities<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> Vec<Option<usize>>
where
    F: Field + Unit + PartialEq,
{
    let public = instance.allocator().public_vars();
    let mut mult = vec![None; instance.allocator().vars_count()];

    for (var, _) in public.iter() {
        mult[var.0] = Some(0);
    }

    for var in instance
        .constraints()
        .as_ref()
        .iter()
        .flat_map(|pair| pair.input.iter().chain(pair.output.iter()))
    {
        mult[var.0] = mult[var.0].map(|count| count + 1);
    }

    mult
}

fn lin_multiplicities<F>(lc: &LinearConstraintsInstance<F>) -> Vec<Option<usize>>
where
    F: Field + Unit + PartialEq,
{
    let vars_count = lc
        .as_ref()
        .iter()
        .flat_map(|equation| equation.linear_combination.iter().map(|(_, var)| var.0))
        .max()
        .map(|max_var| max_var + 1)
        .unwrap_or(0);
    let mut mult = vec![None; vars_count];

    for equation in lc.as_ref() {
        for (coeff, var) in &equation.linear_combination {
            if *coeff != <F as PrimeCharacteristicRing>::ZERO {
                mult[var.0] = Some(mult[var.0].unwrap_or(0) + 1);
            }
        }
    }

    mult
}

fn validate_linear_constraints<const LIN_WIDTH: usize, T, U>(
    lc: &LinearConstraints<T, U>,
    source: &str,
) {
    for (idx, equation) in lc.as_ref().iter().enumerate() {
        assert_eq!(
            equation.linear_combination.len(),
            LIN_WIDTH,
            "{source} linear equation {idx} must have exactly {LIN_WIDTH} terms",
        );
    }
}

fn target_len_with_linear<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> usize
where
    F: Field + Unit + PartialEq,
{
    instance
        .constraints()
        .as_ref()
        .len()
        .max(instance.public_vars().len())
        .max(instance.linear_constraints().as_ref().len())
        .next_power_of_two()
        .max(1)
}

fn hash_trace_target_len<H, F, const WIDTH: usize>(
    hash: &H,
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> usize
where
    H: HashInvocationAir<F, WIDTH>,
    F: Field + Unit + PartialEq,
{
    (instance.constraints().as_ref().len() * hash.trace_rows_per_invocation())
        .next_power_of_two()
        .max(1)
}

fn pad_witness_permutations<F, P, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    witness: &PermutationWitnessBuilder<P, WIDTH>,
    target_len: usize,
) where
    F: Field + Unit + PartialEq,
    P: Permutation<WIDTH, U = F>,
{
    let current_len = instance.constraints().as_ref().len();
    assert!(target_len.is_power_of_two());
    assert!(current_len <= target_len);
    let padding = target_len - current_len;
    if padding == 0 {
        return;
    }
    let zero_input = core::array::from_fn(|_| <F as PrimeCharacteristicRing>::ZERO);
    for _ in 0..padding {
        let _ = instance.allocate_permutation(&core::array::from_fn(|_| FieldVar(0)));
        let _ = witness.allocate_permutation(&zero_input);
    }
}

fn pad_instance_permutations<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    target_len: usize,
) where
    F: Field + Unit + PartialEq,
{
    let current_len = instance.constraints().as_ref().len();
    assert!(target_len.is_power_of_two());
    assert!(current_len <= target_len);
    let padding = target_len - current_len;
    for _ in 0..padding {
        let _ = instance.allocate_permutation(&core::array::from_fn(|_| FieldVar(0)));
    }
}

fn pad_dense_matrix_to_height<T: Clone + Default + Send + Sync>(
    mut matrix: DenseMatrix<T>,
    target_height: usize,
) -> DenseMatrix<T> {
    let width = matrix.width;
    let current_height = matrix.values.len() / width;
    if current_height < target_height {
        matrix.values.resize_with(target_height * width, T::default);
    }
    DenseMatrix::new(matrix.values, width)
}

fn trace_degree_bits<T: Clone + Send + Sync>(
    traces: &[DenseMatrix<T>],
    target_len: usize,
) -> Vec<usize> {
    traces
        .iter()
        .enumerate()
        .map(|(idx, trace)| {
            let trace_height = trace.height();
            assert!(trace_height.is_power_of_two());
            if idx == 0 {
                assert_eq!(trace_height, target_len);
            }
            trace_height.trailing_zeros() as usize
        })
        .collect()
}

fn log_ext_degrees<SC: StarkGenericConfig>(log_degrees: &[usize], config: &SC) -> Vec<usize> {
    log_degrees
        .iter()
        .map(|&degree| degree + config.is_zk())
        .collect()
}
