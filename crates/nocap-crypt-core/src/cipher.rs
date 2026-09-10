//! Shared key-length error type for cipher construction.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("expected a {expected}-byte key, got {actual} bytes")]
    WrongLength { expected: usize, actual: usize },
}
