//! Proof-system security profiles.
//!
//! Here, we configure Plonky3's FRI polynomial commitment scheme for the
//! STARK relation proofs in this crate.
//!
//! The relevant parameters are:
//! - The Reed-Solomon rate `rho = 2^-log_blowup`;
//! - The number of FRI queries `num_queries = t`
//!
//! The soundess error is `(1 - delta)^t`, with delta depending on `rho` in different ways
//! depending on the aggressive or the conservative parameter choice.
//!
//! The profiles below target roughly 128 bits after including query proof of
//! work. Plonky3's built-in `conjectured_soundness_bits` method only
//! accounts for query proof of work and the simpler ethSTARK-style
//! `rho^t = 2^(-log_blowup * t)` query term.
//!
//! The relation AIR currently groups two hash lanes per LogUp lookup context.
//! This reduces auxiliary columns, but raises the lookup transition degree; with
//! ZK randomization the resulting quotient degree is not compatible with
//! `log_blowup = 2`. The built-in profiles and sweep therefore keep
//! `log_blowup >= 3`.

use p3_fri::FriParameters;

/// Concrete FRI parameters used by a security profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityParameters {
    /// The inverse code rate: `rho = 2^-log_blowup`. A larger
    /// blowup gives more soundness per query and usually larger low-degree
    /// extensions. Relation proofs in this crate should use at least `3`
    /// because of the grouped LogUp lookup contexts described in the module
    /// documentation.
    pub log_blowup: usize,
    /// Early-stopping point for FRI folding.
    /// The final polynomial has length `2^log_final_poly_len`; stopping later can reduce
    /// the final message, while stopping earlier can reduce the number of folding
    /// oracles.
    pub log_final_poly_len: usize,
    ///  The largest FRI fold arity per round. The arity is
    /// `2^max_log_arity`, although Plonky3 may use a smaller arity in a round to
    /// align with input heights and the final polynomial length. Higher arity means
    /// fewer committed FRI layers, but wider round messages and openings.
    pub max_log_arity: usize,
    ///  The number `t` in the query error `(1 - delta)^t`.
    pub num_queries: usize,
    /// The grinding cost before sampling each batching challenge.
    /// It raises prover time and protects against grinding over
    /// those challenges.
    pub commit_proof_of_work_bits: usize,
    /// The grinding cost before sampling FRI queries.
    /// It raises prover time and directly subtracts from the remaining query
    /// security target in Plonky3's accounting.
    pub query_proof_of_work_bits: usize,
}

impl SecurityParameters {
    /// Build Plonky3 FRI parameters by attaching a concrete MMCS.
    pub fn fri_params_zk<Mmcs>(self, mmcs: Mmcs) -> FriParameters<Mmcs> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: self.max_log_arity,
            num_queries: self.num_queries,
            commit_proof_of_work_bits: self.commit_proof_of_work_bits,
            query_proof_of_work_bits: self.query_proof_of_work_bits,
            mmcs,
        }
    }
}

/// Type-level security profile for constructing zk FRI parameters.
pub trait SecurityProfile: Clone + Copy + Default + Send + Sync + 'static {
    /// Return the concrete FRI knobs used by this profile.
    fn security_parameters() -> SecurityParameters;
}

/// Conservative Johnson-bound profile.
///
/// The Johnson-bound setting assumes each oracle is within distance
/// `1 - sqrt(rho) - eta` of a Reed-Solomon codeword, with
/// `eta = sqrt(rho) / 20`.
///
/// Under this assumption the per-query failure term is
/// `1 - delta = sqrt(rho) + eta = 1.05 * sqrt(rho)`, so the query error is
/// `(1.05 * sqrt(rho))^t`. With `log_blowup = 3`, `rho = 1/8`,
/// `commit_proof_of_work_bits = 10`, and `query_proof_of_work_bits = 11`,
/// each query contributes `-log2(1.05 * sqrt(1/8)) ~= 1.4304` bits.
/// Therefore `t = 75` gives about `75 * 1.4304 + 21 = 128.3`
/// query-plus-PoW bits.
///
/// The relevant proximity-gap analysis is Theorem 1.5 of BCSS25, which improves
/// the exceptional-set term from the older BCI+20 `a = O(n^2 / eta^7)` bound to
/// `a = O(n / eta^5)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Conservative;

impl SecurityProfile for Conservative {
    fn security_parameters() -> SecurityParameters {
        SecurityParameters {
            log_blowup: 3,
            log_final_poly_len: 3,
            max_log_arity: 4,
            num_queries: 75,
            commit_proof_of_work_bits: 10,
            query_proof_of_work_bits: 11,
        }
    }
}

/// Aggressive capacity-bound profile.
///
/// The capacity-bound setting assumes each oracle is within distance
/// `1 - rho - eta` of a Reed-Solomon codeword, with `eta = rho / 20`.
///
/// Under this assumption the per-query failure term is
/// `1 - delta = rho + eta = 1.05 * rho`, so the query error is
/// `(1.05 * rho)^t`. With `log_blowup = 3`, `rho = 1/8`,
/// `commit_proof_of_work_bits = 10`, and `query_proof_of_work_bits = 14`,
/// each query contributes `-log2(1.05 / 8) ~= 2.9296` bits.
/// Therefore `t = 36` gives about `36 * 2.9296 + 23 = 128.5`
/// query-plus-PoW bits.
///
/// This is under the conjecture that Reed-Solomon codes
/// are decodable up to capacity and have correlated agreement,
/// up to capacity. It is the profile to use when proof size matters more than
/// relying only on the Johnson-bound analysis.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggressive;

impl SecurityProfile for Aggressive {
    fn security_parameters() -> SecurityParameters {
        SecurityParameters {
            log_blowup: 3,
            log_final_poly_len: 3,
            max_log_arity: 4,
            num_queries: 36,
            commit_proof_of_work_bits: 10,
            query_proof_of_work_bits: 13,
        }
    }
}
