//! Output reporting: the `Reporter` trait and every output-mode
//! persona (`Silent`, `Verbose`, `Didactic`, `Corporate`, `Ci`) that
//! implements it. `didactic` is one persona among five — see that
//! module for the actual "explain how this works" content.

pub mod ci;
pub mod corporate;
pub mod didactic;
pub mod event;
pub mod quotes;
pub mod silent;
pub mod verbose;

pub use ci::Ci;
pub use corporate::Corporate;
pub use didactic::sbox;
pub use didactic::{
    narrate::{
        explain_alignment_context, explain_bench_data_source, explain_bench_methodology,
        explain_bench_worker_count, explain_block_cipher_basics, explain_entropy_result_ciphertext,
        explain_entropy_result_generic, explain_entropy_result_key, explain_headerless_plain,
        explain_headerless_plain_reference, explain_iv_derivation, explain_key_generation,
        explain_keycheck_length, explain_plain64_tweak_is_not_secret, explain_xts_malleability,
        explain_xts_tweakability, narration_sample_note, xts_ascii_diagram, DIDACTIC_PRIMER,
    },
    sbox::{render_sbox_step, substitute, AES_SBOX, DEMO_SAMPLE_BYTE},
    Didactic,
};
pub use event::{Event, ProgressFlavor, Reporter};
pub use quotes::SATIRICAL_QUOTES;
pub use silent::Silent;
pub use verbose::Verbose;
