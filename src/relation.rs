//! STARK relation for permutation-evaluation circuits.
//!
//! # Assumptions
//!
//! The relation layer encodes symbolic [`FieldVar`] identifiers and lookup
//! multiplicities as base-field elements with `F::from_usize`.
//!
//! Soundness assumes these integers do not overflow:
//! every variable identifier used by the instance, and every
//! multiplicity computed for the `in-out`, `public-vars`, and
//! `linear-constraints` lookups, must be strictly smaller than the field
//! characteristic. Equivalently, relation sizes must stay below the modulus of
//! the backend field.
//!
//! The [`PermutationInstanceBuilder`] is also treated as a well-formed symbolic
//! relation. Reusing a [`FieldVar`] means reusing the same relation variable,
//! so callers should allocate fresh variables when independent values are
//! intended, and should reuse variables only when they intend to impose an
//! equality relation. Public assignments are interpreted as lookup-table rows;
//! each public variable should be assigned at most once, with one consistent
//! value.

use alloc::{boxed::Box, string::ToString, vec, vec::Vec};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};

use p3_air::{
    Air, AirBuilder, AirLayout, BaseAir, SymbolicAirBuilder, SymbolicExpressionExt, WindowAccess,
};
use p3_batch_stark::{BatchProof, ProverData, StarkInstance};
use p3_field::{integers::QuotientMap, Algebra, BasedVectorSpace, Field, PrimeCharacteristicRing};
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
    HashRelationBackend, QueryAnswerPair, RelationArithmetization, RelationChallenge, RelationField,
};

// --------------------------------------
// Constants for the protocol
// --------------------------------------

/// The first lookup, checking that outputs re-appear as inputs.
pub const IO_LOOKUP_NAME: &str = "in-out";
/// The second lookup, checking that public variables are correctly assigned.
pub const PUB_LOOKUP_NAME: &str = "public-vars";
/// The third lookup, checking linear relations between inputs and outputs.
pub const LIN_LOOKUP_NAME: &str = "linear-constraints";

/// Default supported maximum number of terms in one linear equation.
pub const MAX_LINEAR_WIDTH: usize = 16;

// The current security profiles stop FRI at a non-trivial final polynomial
// length. Very small trace domains make the PCS reject the batch before the
// relation constraints are meaningful, so every AIR gets at least this height.
const MIN_TRACE_LEN: usize = 32;

// A LogUp context with too many tuples has a high-degree denominator product.
// Group lanes to reduce auxiliary columns while keeping lookup constraint
// degree comfortably below the minimum trace height.
const LOOKUP_LANES_PER_CONTEXT: usize = 2;

// ----------------------------------
// AIR columns for the hash relation
// ----------------------------------

type LinearConstraintsInstance<F> = LinearConstraints<FieldVar, F>;
type LinearConstraintsWitness<F> = LinearConstraints<F, F>;
type PreparedRelationAir<B, const WIDTH: usize> = HashRelationAir<
    <B as HashRelationBackend<WIDTH>>::Air,
    RelationField<B, WIDTH>,
    WIDTH,
    MAX_LINEAR_WIDTH,
>;
type PreparedRelationTrace<B, const WIDTH: usize> = DenseMatrix<RelationField<B, WIDTH>>;

/// The (preprocessed, public) lookup columns.
#[repr(C)]
struct LookupCols<T, const WIDTH: usize> {
    /// The input wires
    input_vars: [T; WIDTH],
    /// The output wires
    output_vars: [T; WIDTH],
    /// How many times an output will appear.
    output_multiplicities: [T; WIDTH],
    /// How many times an input will appear.
    input_multiplicities: [T; WIDTH],
    /// The input wires that are public.
    input_public: [T; WIDTH],
    /// The input wires that are public.
    output_public: [T; WIDTH],
    /// The
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
    linear_combination: [T; LIN_WIDTH],
}

#[repr(C)]
struct LinearConstraintPreprocessedCols<T, const LIN_WIDTH: usize> {
    linear_coefficients: [T; LIN_WIDTH],
    linear_vars: [T; LIN_WIDTH],
    image_value: T,
    linear_multiplicities: [T; LIN_WIDTH],
}

/// Number of field elements in [`LookupCols`]
const fn num_lookup_cols<const WIDTH: usize>() -> usize {
    size_of::<LookupCols<u8, WIDTH>>()
}

/// Number of field elements in [`PublicLookupCols`]
const fn num_public_lookup_cols() -> usize {
    size_of::<PublicLookupCols<u8>>()
}

/// Number of field elements in [`LinearConstraintCols`]
const fn num_linear_main_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintCols<u8, LIN_WIDTH>>()
}

/// Number of field elements in [`LinearConstraintPreprocessedCols`]
const fn num_linear_preprocessed_cols<const LIN_WIDTH: usize>() -> usize {
    size_of::<LinearConstraintPreprocessedCols<u8, LIN_WIDTH>>()
}

//------------------------------
// AIRs for the hash relation
// -----------------------------

/// AIR for hash preimage relations.
#[derive(Clone)]
struct HashLookupAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    hash: H,
    builder: PermutationInstanceBuilder<F, WIDTH>,
    linear_constraints: LinearConstraintsInstance<F>,
    trace_len: usize,
}

/// AIR for public-variables lookup tables.
#[derive(Clone)]
struct PublicVarLookupAir<F, const WIDTH: usize> {
    instance: PermutationInstanceBuilder<F, WIDTH>,
    trace_len: usize,
}

/// AIR for linear-equations.
#[derive(Clone)]
struct LinearConstraintsAir<F, const WIDTH: usize, const LIN_WIDTH: usize> {
    constraints: LinearConstraintsInstance<F>,
    trace_len: usize,
    active_width: usize,
}

/// Combined AIR for the generic relation.
///
/// TODO: `Linear` can be any AIR that talks about variables.
#[derive(Clone)]
enum HashRelationAir<H, F, const WIDTH: usize, const LIN_WIDTH: usize> {
    Hash(Box<HashLookupAir<H, F, WIDTH, LIN_WIDTH>>),
    Public(PublicVarLookupAir<F, WIDTH>),
    Linear(LinearConstraintsAir<F, WIDTH, LIN_WIDTH>),
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> HashLookupAir<H, F, WIDTH, LIN_WIDTH> {
    fn new(
        hash: H,
        builder: PermutationInstanceBuilder<F, WIDTH>,
        linear_constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
    ) -> Self {
        Self {
            hash,
            builder,
            linear_constraints,
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
        constraints: LinearConstraintsInstance<F>,
        trace_len: usize,
        active_width: usize,
    ) -> Self {
        assert!(trace_len.is_power_of_two());
        assert!(constraints.as_ref().len() <= trace_len);
        assert!(active_width <= LIN_WIDTH);
        Self {
            constraints,
            trace_len,
            active_width,
        }
    }
}

// ----------------------------------------
// Relation definition and implementation
// ----------------------------------------

struct ValidatedLinear<F> {
    instance: LinearConstraintsInstance<F>,
    witness: LinearConstraintsWitness<F>,
    width: usize,
}

/// The (padded) hash relation ready to be proven.
pub struct PreparedRelation<B: HashRelationBackend<WIDTH>, const WIDTH: usize> {
    hash: B::Air,
    permutation: B::Permutation,
    instance: PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    linear_constraints: LinearConstraintsInstance<RelationField<B, { WIDTH }>>,
    linear_width: usize,
    original_constraints_len: usize,
    hash_log_len: usize,
    public_log_len: usize,
    linear_log_len: usize,
}

pub struct PreparedWitness<B: HashRelationBackend<WIDTH>, const WIDTH: usize> {
    witness: PermutationWitnessBuilder<B::Permutation, WIDTH>,
    linear_constraints: LinearConstraintsWitness<RelationField<B, { WIDTH }>>,
}

impl<B, const WIDTH: usize> PreparedRelation<B, WIDTH>
where
    B: HashRelationBackend<{ WIDTH }>,
    RelationField<B, { WIDTH }>: Field + Unit + PartialEq + Send + Sync,
    RelationChallenge<B, { WIDTH }>: BasedVectorSpace<RelationField<B, { WIDTH }>>,
    SymbolicExpressionExt<RelationField<B, { WIDTH }>, RelationChallenge<B, { WIDTH }>>:
        Algebra<RelationChallenge<B, { WIDTH }>>,
{
    pub fn new(
        backend: &B,
        instance: &PermutationInstanceBuilder<RelationField<B, { WIDTH }>, WIDTH>,
    ) -> Self {
        let hash = backend.air();
        let permutation = backend.permutation();
        let original_constraints_len = instance.constraints().as_ref().len();
        let instance = clone_instance_builder(instance);
        let linear = validate_and_pad_instance_linear(&instance);
        let hash_logical_len = hash_logical_target_len(&hash, &instance);
        pad_instance_permutations(&instance, hash_logical_len);
        validate_instance(&instance);
        // The hash AIR height is counted in trace rows, not logical hash invocations.
        let hash_log_len = (instance.constraints().as_ref().len()
            * hash.trace_rows_per_invocation())
        .next_power_of_two()
        .max(MIN_TRACE_LEN)
        .trailing_zeros() as usize;
        // The public lookup AIR is sized by the public-variable table, independently of hash rows.
        let public_log_len = instance
            .public_vars()
            .len()
            .next_power_of_two()
            .max(MIN_TRACE_LEN)
            .trailing_zeros() as usize;
        // The linear lookup AIR is always present, even when the linear relation is empty.
        let linear_log_len = linear
            .instance
            .as_ref()
            .len()
            .next_power_of_two()
            .max(MIN_TRACE_LEN)
            .trailing_zeros() as usize;

        Self {
            hash,
            permutation,
            instance,
            linear_constraints: linear.instance,
            linear_width: linear.width,
            original_constraints_len,
            hash_log_len,
            public_log_len,
            linear_log_len,
        }
    }

    pub fn prepare_witness(
        &self,
        witness: &PermutationWitnessBuilder<B::Permutation, WIDTH>,
    ) -> PreparedWitness<B, WIDTH> {
        let witness_len = witness.trace().as_ref().len();
        assert_eq!(
            witness_len, self.original_constraints_len,
            "instance/witness permutation count mismatch: instance has {}, witness has {}",
            self.original_constraints_len, witness_len,
        );
        let linear = validate_and_pad_linear(&self.instance, &witness.linear_constraints());
        let witness = clone_witness_builder(witness, self.permutation.clone());
        pad_witness_permutations(&witness, self.num_constraints());

        PreparedWitness {
            witness,
            linear_constraints: linear.witness,
        }
    }

    /// Generate a STARK proof that the witness satisfies this hash relation.
    pub fn prove(&self, backend: &B, witness: &PreparedWitness<B, WIDTH>) -> Vec<u8> {
        assert_eq!(
            witness.witness.trace().as_ref().len(),
            self.num_constraints(),
            "prepared witness trace length does not match prepared relation",
        );

        let (mut airs, traces) = self.generate_trace_rows(witness);
        let log_degrees = self.trace_degree_bits();
        assert_eq!(
            trace_degree_bits(&traces),
            log_degrees,
            "generated trace degrees do not match prepared relation",
        );
        // Transparent preprocessed commitments are public verifier-recomputed data, so they use the
        // deterministic verifier config. Witness-bearing commitments below use fresh prover config.
        let preprocessing_config = backend.verifier_config();
        let config = backend.prover_config();
        let log_ext_degrees = log_ext_degrees(&log_degrees, &config);
        let prover_data =
            ProverData::from_airs_and_degrees(&preprocessing_config, &mut airs, &log_ext_degrees);
        let common = &prover_data.common;
        let publics = vec![Vec::new(); airs.len()];
        let trace_refs = traces.iter().collect::<Vec<_>>();
        let instances = StarkInstance::new_multiple(&airs, &trace_refs, &publics, common);
        let proof = p3_batch_stark::prove_batch(&config, &instances, &prover_data);
        postcard::to_allocvec(&proof).expect("proof serialization should succeed")
    }

    /// Verify a STARK proof against this relation and backend.
    pub fn verify(&self, backend: &B, proof_bytes: &[u8]) -> VerificationResult<()> {
        let config = backend.verifier_config();
        let proof: BatchProof<B::Config> =
            postcard::from_bytes(proof_bytes).map_err(|_| VerificationError)?;
        let expected_degree_bits = log_ext_degrees(&self.trace_degree_bits(), &config);
        if proof.degree_bits != expected_degree_bits {
            return Err(VerificationError);
        }
        let mut airs = self.build_airs();
        let prover_data = ProverData::from_airs_and_degrees(&config, &mut airs, &proof.degree_bits);
        let publics = vec![Vec::new(); airs.len()];
        p3_batch_stark::verify_batch(&config, &airs, &proof, &publics, &prover_data.common)
            .map_err(|_| VerificationError)
    }

    fn build_airs(&self) -> Vec<PreparedRelationAir<B, WIDTH>> {
        let hash_air =
            HashLookupAir::<B::Air, RelationField<B, { WIDTH }>, WIDTH, MAX_LINEAR_WIDTH>::new(
                self.hash.clone(),
                self.instance.clone(),
                self.linear_constraints.clone(),
                1usize << self.hash_log_len,
            );
        vec![
            HashRelationAir::Hash(Box::new(hash_air)),
            HashRelationAir::Public(PublicVarLookupAir::new(
                self.instance.clone(),
                1usize << self.public_log_len,
            )),
            HashRelationAir::Linear(LinearConstraintsAir::<
                RelationField<B, { WIDTH }>,
                WIDTH,
                MAX_LINEAR_WIDTH,
            >::new(
                self.linear_constraints.clone(),
                1usize << self.linear_log_len,
                self.linear_width,
            )),
        ]
    }

    fn num_constraints(&self) -> usize {
        self.instance.constraints().as_ref().len()
    }

    fn trace_degree_bits(&self) -> Vec<usize> {
        vec![self.hash_log_len, self.public_log_len, self.linear_log_len]
    }

    fn generate_trace_rows(
        &self,
        witness: &PreparedWitness<B, WIDTH>,
    ) -> (
        Vec<PreparedRelationAir<B, WIDTH>>,
        Vec<PreparedRelationTrace<B, WIDTH>>,
    ) {
        let hash_trace = self.hash.build_trace(&witness.witness);
        let trace = pad_dense_matrix_to_height(hash_trace, 1usize << self.hash_log_len);
        let public_trace = build_public_lookup_main_trace::<RelationField<B, { WIDTH }>>(
            1usize << self.public_log_len,
        );
        let airs = self.build_airs();
        let mut traces = vec![trace, public_trace];
        traces.push(pad_dense_matrix_to_height(
            build_linear_constraints_trace::<RelationField<B, { WIDTH }>, MAX_LINEAR_WIDTH>(
                &witness.linear_constraints,
            ),
            1usize << self.linear_log_len,
        ));

        (airs, traces)
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> BaseAir<F>
    for HashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    H: RelationArithmetization<F, WIDTH> + Sync,
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
    H: RelationArithmetization<F, WIDTH> + Sync,
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
        let public_multiplicities = public_multiplicities(&self.builder);
        let (input_multiplicities, output_multiplicities) = hash_equality_multiplicities::<F, WIDTH>(
            input_outputs.as_ref(),
            vars_count,
            &public_multiplicities,
        );

        let mut ptrace = DenseMatrix::new(
            vec![<F as PrimeCharacteristicRing>::ZERO; num_lookup_cols::<WIDTH>() * self.trace_len],
            num_lookup_cols::<WIDTH>(),
        );
        let (linear_inputs, linear_outputs) = linear_lookup_multiplicities::<F, WIDTH>(
            input_outputs.as_ref(),
            &lin_multiplicities(&self.linear_constraints),
        );

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
            lookup.input_vars = pair.input.map(|var| field_from_usize_checked::<F>(var.0));
            lookup.output_vars = pair.output.map(|var| field_from_usize_checked::<F>(var.0));
            lookup.output_multiplicities = output_mult;
            lookup.input_multiplicities = input_mult;
            lookup.input_linear_constraints = linear_input;
            lookup.output_linear_constraints = linear_output;
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
        let trace = build_lin_lookup_trace::<F, LIN_WIDTH>(&self.constraints);
        Some(pad_dense_matrix_to_height(trace, self.trace_len))
    }
}

impl<AB, H, F, const WIDTH: usize, const LIN_WIDTH: usize> Air<AB>
    for HashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    AB: AirBuilder<F = F>,
    H: RelationArithmetization<F, WIDTH> + Sync,
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
    H: RelationArithmetization<F, WIDTH> + Sync,
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
            sum += prep.linear_coefficients[i] * local.linear_combination[i];
        }
        builder.assert_eq(sum, image_value);
    }
}

impl<H, F, const WIDTH: usize, const LIN_WIDTH: usize> LookupAir<F>
    for HashRelationAir<H, F, WIDTH, LIN_WIDTH>
where
    H: RelationArithmetization<F, WIDTH> + Sync,
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
    H: RelationArithmetization<F, WIDTH> + Sync,
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
        type Expr<F> = <SymbolicAirBuilder<F> as AirBuilder>::Expr;

        let chunks = WIDTH.div_ceil(LOOKUP_LANES_PER_CONTEXT);
        let mut lookups = Vec::with_capacity(chunks * 3);
        let lookup_column: &LookupCols<_, WIDTH> = (*lookup_row).borrow();

        for chunk_start in (0..WIDTH).step_by(LOOKUP_LANES_PER_CONTEXT) {
            let chunk_end = (chunk_start + LOOKUP_LANES_PER_CONTEXT).min(WIDTH);
            let chunk_width = chunk_end - chunk_start;
            let mut io_elements = Vec::with_capacity(2 * chunk_width);
            let mut io_multiplicities = Vec::with_capacity(2 * chunk_width);
            let mut public_elements = Vec::with_capacity(2 * chunk_width);
            let mut public_multiplicities = Vec::with_capacity(2 * chunk_width);
            let mut linear_elements = Vec::with_capacity(2 * chunk_width);
            let mut linear_multiplicities = Vec::with_capacity(2 * chunk_width);

            for i in chunk_start..chunk_end {
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

                io_elements.push(vec![input_var.into(), input.clone()]);
                io_multiplicities.push(selector.clone() * input_multiplicity);
                io_elements.push(vec![output_var.into(), output.clone()]);
                io_multiplicities.push(selector.clone() * output_multiplicity);

                public_elements.push(vec![output_var.into(), output.clone()]);
                public_multiplicities
                    .push(Direction::Send.multiplicity(selector.clone() * output_public));
                public_elements.push(vec![input_var.into(), input.clone()]);
                public_multiplicities
                    .push(Direction::Send.multiplicity(selector.clone() * input_public));

                linear_elements.push(vec![input_var.into(), input]);
                linear_multiplicities
                    .push(Direction::Send.multiplicity(selector.clone() * input_linear));
                linear_elements.push(vec![output_var.into(), output]);
                linear_multiplicities
                    .push(Direction::Send.multiplicity(selector.clone() * output_linear));
            }

            lookups.push(Lookup::new(
                Kind::Global(IO_LOOKUP_NAME.to_string()),
                io_elements,
                io_multiplicities,
                vec![lookups.len()],
            ));
            lookups.push(Lookup::new(
                Kind::Global(PUB_LOOKUP_NAME.to_string()),
                public_elements,
                public_multiplicities,
                vec![lookups.len()],
            ));
            lookups.push(Lookup::new(
                Kind::Global(LIN_LOOKUP_NAME.to_string()),
                linear_elements,
                linear_multiplicities,
                vec![lookups.len()],
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

        let mut entries = Vec::with_capacity(self.active_width);
        for i in 0..self.active_width {
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
        values[offset] = field_from_usize_checked::<F>(var.0);
        values[offset + 1] = *val;
        values[offset + 2] = field_from_usize_checked::<F>(multiplicity);
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

fn build_lin_lookup_trace<F, const LIN_WIDTH: usize>(
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

    for (row_idx, equation) in lc.as_ref().iter().enumerate() {
        let linear_coefficients = core::array::from_fn(|i| equation.linear_combination[i].0);
        let linear_vars = core::array::from_fn(|i| {
            let (coeff, var) = equation.linear_combination[i];
            if coeff == <F as PrimeCharacteristicRing>::ZERO {
                FieldVar(0)
            } else {
                var
            }
        });
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
        column.linear_coefficients = linear_coefficients;
        column.linear_vars = linear_vars.map(|var| field_from_usize_checked::<F>(var.0));
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
        let linear_values = core::array::from_fn(|i| equation.linear_combination[i].1);
        let offset = row_idx * width;
        let row = &mut values[offset..offset + width];
        let column: &mut LinearConstraintCols<F, LIN_WIDTH> = row.borrow_mut();
        column.linear_combination = linear_values;
    }

    DenseMatrix::new(values, width)
}

//-----------------------------------------------------
// Lookup helpers: compute multiplicities of each term
// ---------------------------------------------------
//
// The lookup will need to know the number of repetitions of each term
// These helper functions help computing them.

fn hash_equality_multiplicities<F, const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    vars_count: usize,
    public_multiplicities: &[Option<usize>],
) -> (Vec<[F; WIDTH]>, Vec<[F; WIDTH]>)
where
    F: PrimeCharacteristicRing,
{
    let mut counts = vec![0usize; vars_count];
    for pair in constraints {
        for var in pair.input.iter().chain(pair.output.iter()) {
            if public_multiplicities[var.0].is_none() {
                counts[var.0] += 1;
            }
        }
    }

    let mut seen = vec![0usize; vars_count];
    let mut input_multiplicities = Vec::with_capacity(constraints.len());
    let mut output_multiplicities = Vec::with_capacity(constraints.len());

    for pair in constraints {
        let input = pair
            .input
            .map(|var| hash_equality_multiplicity::<F>(var, &counts, &mut seen));
        let output = pair
            .output
            .map(|var| hash_equality_multiplicity::<F>(var, &counts, &mut seen));
        input_multiplicities.push(input);
        output_multiplicities.push(output);
    }

    debug_assert_eq!(seen, counts);
    (input_multiplicities, output_multiplicities)
}

fn hash_equality_multiplicity<F>(var: FieldVar, counts: &[usize], seen: &mut [usize]) -> F
where
    F: PrimeCharacteristicRing,
{
    let count = counts[var.0];
    if count == 0 {
        return <F as PrimeCharacteristicRing>::ZERO;
    }
    let seen_count = &mut seen[var.0];
    if count == 1 {
        *seen_count += 1;
        return <F as PrimeCharacteristicRing>::ZERO;
    }
    let multiplicity = if *seen_count == 0 {
        field_from_usize_checked::<F>(count - 1)
    } else {
        -<F as PrimeCharacteristicRing>::ONE
    };
    *seen_count += 1;
    multiplicity
}

fn linear_lookup_multiplicities<F, const WIDTH: usize>(
    constraints: &[QueryAnswerPair<FieldVar, WIDTH>],
    linear_counts: &[Option<usize>],
) -> (Vec<[F; WIDTH]>, Vec<[F; WIDTH]>)
where
    F: PrimeCharacteristicRing,
{
    let mut remaining = linear_counts
        .iter()
        .map(|count| count.unwrap_or(0))
        .collect::<Vec<_>>();
    let mut input_multiplicities = Vec::with_capacity(constraints.len());
    let mut output_multiplicities = Vec::with_capacity(constraints.len());

    for pair in constraints {
        let mut input_counts = [<F as PrimeCharacteristicRing>::ZERO; WIDTH];
        let mut output_counts = [<F as PrimeCharacteristicRing>::ZERO; WIDTH];

        for (slot, var) in input_counts.iter_mut().zip(pair.input.iter()) {
            let count = remaining.get_mut(var.0).map_or(0, core::mem::take);
            *slot = field_from_usize_checked::<F>(count);
        }
        for (slot, var) in output_counts.iter_mut().zip(pair.output.iter()) {
            let count = remaining.get_mut(var.0).map_or(0, core::mem::take);
            *slot = field_from_usize_checked::<F>(count);
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
        .flat_map(|equation| {
            equation
                .linear_combination
                .iter()
                .filter_map(|(coeff, var)| {
                    (*coeff != <F as PrimeCharacteristicRing>::ZERO).then_some(var.0)
                })
        })
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

fn validate_and_pad_instance_linear<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> ValidatedLinear<F>
where
    F: Field + Unit + PartialEq + Clone,
{
    let linear_constraints = instance.linear_constraints();
    validate_linear_constraint_vars(instance, &linear_constraints);
    let width = max_linear_width(&linear_constraints);
    assert!(
        width <= MAX_LINEAR_WIDTH,
        "linear equation width {width} exceeds supported maximum {MAX_LINEAR_WIDTH}",
    );
    ValidatedLinear {
        instance: pad_instance_linear_constraints(linear_constraints, MAX_LINEAR_WIDTH),
        witness: LinearConstraints::default(),
        width,
    }
}

fn validate_and_pad_linear<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    linear_witness: &LinearConstraintsWitness<F>,
) -> ValidatedLinear<F>
where
    F: Field + Unit + PartialEq + Clone,
{
    let linear_constraints = instance.linear_constraints();
    assert_eq!(
        linear_constraints.as_ref().len(),
        linear_witness.as_ref().len(),
        "instance/witness linear equation count mismatch: instance has {}, witness has {}",
        linear_constraints.as_ref().len(),
        linear_witness.as_ref().len(),
    );
    validate_linear_constraint_vars(instance, &linear_constraints);

    for (idx, (instance_eq, witness_eq)) in linear_constraints
        .as_ref()
        .iter()
        .zip(linear_witness.as_ref().iter())
        .enumerate()
    {
        assert_eq!(
            instance_eq.linear_combination.len(),
            witness_eq.linear_combination.len(),
            "instance/witness linear equation {idx} term count mismatch: instance has {}, witness has {}",
            instance_eq.linear_combination.len(),
            witness_eq.linear_combination.len(),
        );
        assert!(
            instance_eq.image == witness_eq.image,
            "instance/witness linear equation {idx} image mismatch",
        );
        for (term_idx, ((instance_coeff, _), (witness_coeff, _))) in instance_eq
            .linear_combination
            .iter()
            .zip(witness_eq.linear_combination.iter())
            .enumerate()
        {
            assert!(
                instance_coeff == witness_coeff,
                "instance/witness linear equation {idx} coefficient {term_idx} mismatch",
            );
        }
    }

    let width = max_linear_width(&linear_constraints);
    ValidatedLinear {
        instance: pad_instance_linear_constraints(linear_constraints, MAX_LINEAR_WIDTH),
        witness: pad_witness_linear_constraints(linear_witness.clone(), MAX_LINEAR_WIDTH),
        width,
    }
}

fn max_linear_width<T, U>(lc: &LinearConstraints<T, U>) -> usize {
    lc.as_ref()
        .iter()
        .map(|equation| equation.linear_combination.len())
        .max()
        .unwrap_or(0)
}

fn clone_instance_builder<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> PermutationInstanceBuilder<F, WIDTH>
where
    F: Clone + Unit + PartialEq,
{
    let cloned = PermutationInstanceBuilder::new();
    while cloned.allocator().vars_count() < instance.allocator().vars_count() {
        let _ = cloned.allocator().new_field_var();
    }
    for (var, value) in instance.public_vars() {
        if var == FieldVar(0) && value == F::ZERO {
            continue;
        }
        cloned.allocator().set_public_var(var, value);
    }
    for pair in instance.constraints().as_ref() {
        cloned.add_permutation(pair.input, pair.output);
    }
    for equation in instance.linear_constraints().as_ref() {
        cloned.add_equation(equation.clone());
    }

    cloned
}

fn clone_witness_builder<P, const WIDTH: usize>(
    witness: &PermutationWitnessBuilder<P, WIDTH>,
    permutation: P,
) -> PermutationWitnessBuilder<P, WIDTH>
where
    P: Permutation<WIDTH> + Clone,
{
    let cloned = PermutationWitnessBuilder::new(permutation);
    for pair in witness.trace().as_ref() {
        cloned.add_permutation(&pair.input, &pair.output);
    }
    for equation in witness.linear_constraints().as_ref() {
        cloned.add_equation(equation.clone());
    }

    cloned
}

/// Convert a usize to a field element, and panic if there's an oveflow.
///
/// `FieldVar`, as a wire identifier does not guarantee its associated usize
/// can be represented in a single field element. We make sure of that here.
fn field_from_usize_checked<F: PrimeCharacteristicRing>(value: usize) -> F {
    let value = <F::PrimeSubfield as QuotientMap<usize>>::from_canonical_checked(value)
        .expect("value must be smaller than the field characteristic");
    F::from_prime_subfield(value)
}

fn validate_instance<F, const WIDTH: usize>(instance: &PermutationInstanceBuilder<F, WIDTH>)
where
    F: Field + Unit + PartialEq,
{
    // check if any public var been allocated more than once.
    let vars_count = instance.allocator().vars_count();
    let mut assigned = vec![false; vars_count];
    for (var, _) in instance.public_vars() {
        validate_allocated_var::<F>(var, vars_count);
        assert!(
            !assigned[var.0],
            "public variable {} is assigned more than once",
            var.0,
        );
        assigned[var.0] = true;
    }
    // check if any secret var can be allocated more than once.
    let vars_count = instance.allocator().vars_count();
    for pair in instance.constraints().as_ref() {
        for var in pair.input.iter().chain(pair.output.iter()) {
            validate_allocated_var::<F>(*var, vars_count);
        }
    }
}

fn validate_allocated_var<F: PrimeCharacteristicRing>(var: FieldVar, vars_count: usize) {
    assert!(var.0 < vars_count, "unallocated variable {}", var.0,);
    let _ = field_from_usize_checked::<F>(var.0);
}

fn validate_linear_constraint_vars<F, const WIDTH: usize>(
    instance: &PermutationInstanceBuilder<F, WIDTH>,
    lc: &LinearConstraintsInstance<F>,
) where
    F: Field + Unit + PartialEq,
{
    let mut hash_vars = vec![false; instance.allocator().vars_count()];
    for var in instance
        .constraints()
        .as_ref()
        .iter()
        .flat_map(|pair| pair.input.iter().chain(pair.output.iter()))
    {
        if let Some(known_var) = hash_vars.get_mut(var.0) {
            *known_var = true;
        }
    }

    for (equation_idx, equation) in lc.as_ref().iter().enumerate() {
        for (term_idx, (coeff, var)) in equation.linear_combination.iter().enumerate() {
            if *coeff == <F as PrimeCharacteristicRing>::ZERO {
                continue;
            }
            assert!(
                hash_vars.get(var.0).copied().unwrap_or(false),
                "instance linear equation {equation_idx} term {term_idx} references variable {}, \
                 but nonzero linear terms must reference a hash input or output variable",
                var.0,
            );
        }
    }
}

//-----------------------
// Trace length helpers
// ----------------------

fn pad_instance_linear_constraints<F>(
    mut lc: LinearConstraintsInstance<F>,
    width: usize,
) -> LinearConstraintsInstance<F>
where
    F: PrimeCharacteristicRing,
{
    for equation in &mut lc.equations {
        equation
            .linear_combination
            .resize(width, (<F as PrimeCharacteristicRing>::ZERO, FieldVar(0)));
    }
    lc
}

fn pad_witness_linear_constraints<F>(
    mut lc: LinearConstraintsWitness<F>,
    width: usize,
) -> LinearConstraintsWitness<F>
where
    F: PrimeCharacteristicRing,
{
    for equation in &mut lc.equations {
        equation.linear_combination.resize(
            width,
            (
                <F as PrimeCharacteristicRing>::ZERO,
                <F as PrimeCharacteristicRing>::ZERO,
            ),
        );
    }
    lc
}

fn hash_logical_target_len<H, F, const WIDTH: usize>(
    hash: &H,
    instance: &PermutationInstanceBuilder<F, WIDTH>,
) -> usize
where
    H: RelationArithmetization<F, WIDTH>,
    F: Field + Unit + PartialEq,
{
    let rows_per_invocation = hash.trace_rows_per_invocation();
    let mut target_len = instance
        .constraints()
        .as_ref()
        .len()
        .next_power_of_two()
        .max(1);
    while (target_len * rows_per_invocation)
        .next_power_of_two()
        .max(1)
        < MIN_TRACE_LEN
    {
        target_len *= 2;
    }
    target_len
}

fn pad_witness_permutations<F, P, const WIDTH: usize>(
    witness: &PermutationWitnessBuilder<P, WIDTH>,
    target_len: usize,
) where
    F: Field + Unit + PartialEq,
    P: Permutation<WIDTH, U = F>,
{
    let witness_len = witness.trace().as_ref().len();
    assert!(target_len.is_power_of_two());
    assert!(witness_len <= target_len);

    let zero_input = core::array::from_fn(|_| <F as PrimeCharacteristicRing>::ZERO);
    for _ in 0..(target_len - witness_len) {
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

fn trace_degree_bits<T: Clone + Send + Sync>(traces: &[DenseMatrix<T>]) -> Vec<usize> {
    traces
        .iter()
        .map(|trace| {
            let trace_height = trace.height();
            assert!(trace_height.is_power_of_two());
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

// Trace rows are stored as flat `[T]` slices, but the AIR code is easier to
// read against typed column structs. This macro wires up `Borrow` and
// `BorrowMut` by reinterpreting one row slice as the corresponding `#[repr(C)]`
// column type. Callers must keep the slice length and layout in sync with the
// struct definition; the debug assertions catch mismatches while testing.
macro_rules! impl_borrow_for_column {
    ($ty:ident $(, const $const_name:ident : $const_ty:ty)*) => {
        impl<T, $(const $const_name: $const_ty,)*> core::borrow::Borrow<$ty<T, $($const_name,)*>>
            for [T]
        {
            fn borrow(&self) -> &$ty<T, $($const_name,)*> {
                let (prefix, columns, suffix) =
                    unsafe { self.align_to::<$ty<T, $($const_name,)*>>() };
                debug_assert!(prefix.is_empty());
                debug_assert!(suffix.is_empty());
                debug_assert_eq!(columns.len(), 1);
                &columns[0]
            }
        }

        impl<T, $(const $const_name: $const_ty,)*> core::borrow::BorrowMut<$ty<T, $($const_name,)*>>
            for [T]
        {
            fn borrow_mut(&mut self) -> &mut $ty<T, $($const_name,)*> {
                let (prefix, columns, suffix) =
                    unsafe { self.align_to_mut::<$ty<T, $($const_name,)*>>() };
                debug_assert!(prefix.is_empty());
                debug_assert!(suffix.is_empty());
                debug_assert_eq!(columns.len(), 1);
                &mut columns[0]
            }
        }
    };
}

impl_borrow_for_column!(LookupCols, const WIDTH: usize);
impl_borrow_for_column!(PublicLookupCols);
impl_borrow_for_column!(LinearConstraintCols, const LIN_WIDTH: usize);
impl_borrow_for_column!(LinearConstraintPreprocessedCols, const LIN_WIDTH: usize);
