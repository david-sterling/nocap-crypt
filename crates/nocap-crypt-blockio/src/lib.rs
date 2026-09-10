//! Aligned, random-access block I/O: O_DIRECT-aware file access with a
//! buffered fallback, sparse-hole output sizing, and the alignment math
//! shared by `nocap-crypt align check`/`align fix`.

pub mod alignment;
pub mod sectorio;

pub use alignment::{align_up, check_alignment, is_aligned, AlignedBuffer, AlignmentReport};
pub use sectorio::{create_sparse_output, SectorFile};
