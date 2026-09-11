//! Shannon entropy, chi-square uniformity testing, and windowed
//! streaming analysis over byte data — used both standalone
//! (`nocap-crypt entropy`/`inspect`) and by `nocap-crypt-keymgmt` for key
//! weakness checks.

pub mod chisquare;
pub mod shannon;
pub mod streaming;

pub use chisquare::{
    chi_square_critical_approx, chi_square_statistic, is_uniform, DEGREES_OF_FREEDOM,
};
pub use shannon::{shannon_entropy, shannon_entropy_ceiling};
pub use streaming::{analyze_stream, StreamEntropyReport, WindowScore};
