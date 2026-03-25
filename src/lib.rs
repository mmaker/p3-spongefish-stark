#![cfg_attr(not(test), no_std)]

extern crate alloc;

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{StarkGenericConfig, Val};
use spongefish::Permutation;
use spongefish_circuit::permutation::PermutationWitnessBuilder;

#[cfg(feature = "keccak")]
pub mod keccak;
pub mod poseidon2;
pub mod relation;

#[cfg(test)]
mod tests;

pub use spongefish_circuit::permutation::QueryAnswerPair;

pub type RelationField<B> = Val<<B as StarkRelationBackend>::Config>;
pub type RelationChallenge<B> =
    <<B as StarkRelationBackend>::Config as StarkGenericConfig>::Challenge;

/// Backend adapter for exposing logical hash invocations to a STARK relation.
///
/// The relation layer only needs the logical `input` and `output` lanes for one
/// hash invocation. Implementations define the backend-specific local `Frame`
/// needed to recover that pair. For simple chips, this may be a single row; for
/// multi-row chips such as Keccak, it may be a wider window over the trace.
pub trait HashInvocationAir<F, const WIDTH: usize>: Clone {
    /// Backend-defined local trace view required to recover one hash invocation.
    type Frame<'a, Var>
    where
        Self: 'a,
        Var: 'a;

    /// Width of the main trace used by the inner hash AIR.
    fn main_width(&self) -> usize;

    /// Number of AIR rows used to realize one logical hash invocation.
    fn trace_rows_per_invocation(&self) -> usize {
        1
    }

    /// Evaluate the inner hash AIR constraints over the provided builder.
    fn eval<AB>(&self, builder: &mut AB)
    where
        AB: AirBuilder<F = F>;

    /// Wrap a backend-specific symbolic row into the frame used by
    /// [`Self::invocation`].
    fn row_frame<'a, Var>(&self, row: &'a [Var]) -> Self::Frame<'a, Var>;

    /// Build a concrete main trace from a witness trace of logical invocations.
    fn build_trace<P>(
        &self,
        witness: &PermutationWitnessBuilder<P, WIDTH>,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F>
    where
        P: Permutation<WIDTH, U = F>;

    /// Project one backend-specific invocation frame into its logical input and
    /// output expressions.
    fn invocation<AB>(&self, frame: &Self::Frame<'_, AB::Var>) -> QueryAnswerPair<AB::Expr, WIDTH>
    where
        AB: AirBuilder<F = F>;

    /// Selector for whether the current row should contribute to the outer
    /// relation lookups. Single-row chips return `1`; multi-row chips can gate
    /// lookups to their export/final row.
    fn lookup_selector<AB>(&self, _frame: &Self::Frame<'_, AB::Var>) -> AB::Expr
    where
        AB: AirBuilder<F = F>,
    {
        AB::Expr::ONE
    }
}

/// Backend configuration for the generic STARK relation layer.
///
/// The relation itself is generic over the logical hash AIR, but proving and
/// verification also need a concrete STARK backend: challenge field, PCS/FRI
/// configuration, challenger, and transcript hashing choices.
pub trait StarkRelationBackend: Clone {
    type Config: StarkGenericConfig;

    fn config(&self, seed: u64) -> Self::Config;
}
