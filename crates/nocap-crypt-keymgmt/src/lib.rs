//! Key parsing, validation, representation, and generation.

pub mod format;
pub mod keygen;
pub mod represent;
pub mod validate;

pub use format::{detect_format, parse_key, KeyFormat, KeyParseError};
pub use keygen::{generate_key, write_key_file, KeyFileWriteError};
pub use represent::{fingerprint, hex_grouped, redacted};
pub use validate::{validate_key, KeyValidationError, KeyValidationReport, MIN_KEY_ENTROPY_BITS_PER_BYTE};
