//! LUKS header detection + cipher-spec-string plumbing for
//! `nocap-crypt validate`/`inspect`. Full LUKS1/2 header parsing is
//! deferred (see `header.rs`) — the primary target is headerless
//! `plain64` volumes, covered fully by `structural.rs`.

pub mod header;
pub mod structural;

pub use header::{detect_luks_header, LuksVersion};
pub use structural::{parse_cipher_spec, validate_plain_structural, StructuralReport};
