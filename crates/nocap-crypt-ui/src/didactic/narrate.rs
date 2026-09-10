//! Didactic-mode narration text: IV derivation walkthroughs and
//! check explanations. Kept as pure string-formatting functions,
//! independent of the `Reporter` trait, so they're trivially testable
//! and reusable (e.g. from a future `nocap-crypt inspect --explain`).
//!
//! Content only — never real key/plaintext/ciphertext bytes, per
//! `docs/didactic-mode-plan.md` §4. Real sector numbers and their
//! derived IVs are fine to show (they're not secret, that's the whole
//! point of §2.3 below); nothing here ever takes a key or plaintext
//! byte as input.

/// Printed once, before any `Event` output, only for [`crate::Didactic`].
/// Command-agnostic on purpose — fires before dispatch knows which
/// subcommand is running, so it can't promise anything command-specific.
pub const DIDACTIC_PRIMER: &str =
    "--didactic: lines starting with \u{2192} explain what's happening, with real numbers — never real key or plaintext bytes.";

/// §2.1: the absolute minimum needed before XTS makes sense. Fires
/// once, before cipher selection, for `image encrypt`/`decrypt`.
pub fn explain_block_cipher_basics() -> &'static str {
    "AES encrypts fixed 16-byte blocks: same key, same input, same output, every time. Apply \
     that raw across a disk (ECB mode) and identical plaintext blocks produce identical \
     ciphertext blocks — structure leaks straight through, which is why an ECB-\"encrypted\" \
     bitmap famously still looks like the same bitmap. XTS exists to break that pattern."
}

/// §2.2: why XTS specifically. Fires alongside `Event::CipherSelected`.
///
/// Rewritten after a real accuracy bug: the previous wording contrasted
/// "XTS has no chaining" against "CBC chains across a whole device" —
/// wrong, and wrong in a way that misrepresented this tool's *own*
/// `aes-cbc-essiv:sha256` support. Checked against `engine.rs`:
/// `cbc_essiv_crypt_range` calls `plain64_iv(sector_index)` fresh for
/// every sector, exactly like XTS's tweak does — sector independence
/// (the property parallel dispatch actually needs) holds for *both*
/// ciphers this tool implements, not just XTS. What's actually specific
/// to XTS is one level deeper: no chaining even *within* a sector,
/// block to block. CBC-ESSIV does chain those.
pub fn explain_xts_tweakability() -> &'static str {
    "XTS is a tweakable block cipher: every block is encrypted with the key AND a per-position \
     \"tweak\" derived from its sector number, so identical plaintext at different sector \
     positions produces different ciphertext. Sectors never chain to each other — that's what \
     makes reading or writing any sector independently correct, and it's true for both ciphers \
     this tool supports (CBC-ESSIV resets its IV every sector too). What's specific to XTS is one \
     level deeper: even the 16-byte blocks *within* one sector don't chain to each other — see the \
     diagram below, and the cost of that below it."
}

/// A from-scratch, programmatically-column-aligned diagram of one
/// sector's worth of XTS: 32 independent 16-byte blocks, each with its
/// own tweak (`T * alpha^j`, `j` = block offset within the sector).
/// Fires once alongside `explain_xts_tweakability`. Built as one array
/// element per line, joined with `\n`, rather than a `\`-continued
/// string literal: Rust strips *all* leading whitespace from the next
/// line after a `\` line-continuation, which silently ate this
/// diagram's own alignment spaces the first time this was written —
/// exactly the freehand-ASCII-art alignment trap this project has hit
/// before (see `nocap-crypt-cli::progress`'s meme frames), just via a
/// new mechanism. Each line here is its own complete, unambiguous
/// string literal, so nothing can eat its whitespace.
pub fn xts_ascii_diagram() -> String {
    [
        "PLAINTEXT SECTOR (512 bytes = 32 independent 16-byte blocks)",
        "",
        "  blk 0      blk 1      blk 2       ...      blk 31  ",
        "    |          |          |          |          |    ",
        "  T*a^0      T*a^1      T*a^2       ...      T*a^31     <- tweak = AES(Key2, sector) * alpha^j",
        "    |          |          |          |          |    ",
        "[ AES(Key1, block XOR tweak) XOR tweak ]  <- each block encrypted INDEPENDENTLY",
        "    |          |          |          |          |    ",
        "  blk 0      blk 1      blk 2       ...      blk 31  ",
        "",
        "CIPHERTEXT SECTOR",
        "",
        "no chaining between blocks: flip one ciphertext bit, and only the matching",
        "plaintext bit at that exact position flips back -- nothing else in the",
        "sector is affected, and nothing detects that it happened.",
    ]
    .join("\n")
}

/// The "you don't want XTS" caveats — verified against
/// <https://sockpuppet.org/blog/2014/04/30/you-dont-want-xts/> and
/// consistent with why NIST SP 800-38E itself scopes XTS-AES to
/// storage encryption only. Fires once alongside `xts_ascii_diagram`,
/// right after `explain_xts_tweakability` — the diagram shows *how*
/// per-block tweaking works; this explains the two properties that
/// fall out of it that a reader should not mistake for safety
/// features.
pub fn explain_xts_malleability() -> &'static str {
    "Two things fall out of that per-block independence — inherent to XTS itself, not a defect in \
     this tool, which is exactly why NIST restricts XTS to storage encryption and nothing else. \
     First: XTS is \"ECB-like\" at the 16-byte-block level — because \
     nothing chains blocks together, an attacker with write access to the ciphertext can flip \
     ciphertext bits and get a precise, predictable bit flip in the decrypted plaintext at that \
     exact position, with no error propagation to warn you. Second: since a block's tweak depends \
     only on (sector index, block-in-sector index) and never on *when* it was written, an attacker \
     who saved an old ciphertext block can splice it back in later and it decrypts validly to the \
     old content — XTS has no way to tell a current block from a replayed one. Both are why this \
     tool (like real dm-crypt in plain mode) provides confidentiality only: if you need tamper \
     detection or rollback protection, that has to come from a layer above this one (dm-verity, \
     dm-integrity, filesystem-level signing) — never assume XTS gives you that for free."
}

/// §2.3's safety framing sentence, printed once before the sample IV
/// derivation (not per-sector — see `narration_sample_note`).
pub fn explain_plain64_tweak_is_not_secret() -> &'static str {
    "The tweak below is just the sector number — publicly derivable, not secret. plain64's \
     security doesn't come from hiding it; it comes from XTS's construction. Don't confuse this \
     number with the key."
}

/// Appended after a sample `explain_iv_derivation` call — real files
/// have far too many sectors to narrate every one, so this explains
/// why only one (or a couple) are actually shown.
pub fn narration_sample_note() -> &'static str {
    "(this same derivation runs for every sector in the file — shown once here, not per sector, \
     so a real-sized file doesn't flood the log)"
}

/// §2.4, full version: fires once at the start of `validate`/`inspect`
/// under `--didactic`.
pub fn explain_headerless_plain() -> String {
    "plain64 writes zero header bytes: no magic number, no key slots, nothing on disk that says \
     \"this is encrypted\" or names the cipher. LUKS would have a parseable header here — this \
     tool only detects a LUKS header's magic bytes, it doesn't parse one, because headerless \
     plain64 is the actual target. That's why validation is structural (file size is a whole \
     number of sectors, the cipher spec string round-trips), not header parsing — there's no \
     header to parse. The honest cost: nothing on disk proves what key or cipher was used, or \
     that this file is even encrypted rather than random garbage. That has to be carried \
     out-of-band, which is why a --key-file dry-run decrypt (checking for a known filesystem \
     magic byte) is the strongest practical signal short of an actual mount."
        .to_string()
}

/// §2.4, brief version: referenced (not re-explained) from `image
/// encrypt`.
pub fn explain_headerless_plain_reference() -> &'static str {
    "no header is being written to the output — plain64 has none by design. See `nocap-crypt \
     validate --didactic` for what that means and what it costs."
}

/// Fires alongside `Event::EntropyScore` in `image encrypt`/`inspect`.
/// Don't reuse for key material (see `_key`/`_generic` below) — a
/// low-entropy ciphertext points at a bug in this tool, a low-entropy
/// key points at a vulnerability in the key itself; different claims.
pub fn explain_entropy_result_ciphertext(bits_per_byte: f64) -> String {
    format!(
        "this ciphertext scored {bits_per_byte:.4} bits/byte. Near 8.0 is necessary but not \
         sufficient: a forgotten unencrypted region or a padding bug would show up as a LOWER \
         score here — but XTS provides confidentiality only, no authentication, so an attacker \
         who flips ciphertext bits undetected isn't caught by entropy at all."
    )
}

/// §2.5, key-material variant: fires alongside `Event::EntropyScore`
/// in `keygen` and `keycheck` — the number being scored is raw key
/// bytes, not ciphertext, and the stakes are different in a way worth
/// spelling out explicitly rather than reusing ciphertext-flavored
/// wording that doesn't apply (a key has no "forgotten unencrypted
/// region," and nothing here has produced any ciphertext yet).
pub fn explain_entropy_result_key(bits_per_byte: f64, key_bytes: usize) -> String {
    // Same formula as `nocap_crypt_entropy::shannon_entropy_ceiling` —
    // inlined rather than pulling in that crate as a dependency just
    // for one log2, since this module is deliberately pure
    // string-formatting with no computation dependencies (see module
    // doc comment).
    let ceiling = (key_bytes.min(256) as f64).log2();
    format!(
        "this key scored {bits_per_byte:.4} bits/byte. That looks low next to the 8.0 maximum, \
         but for a {key_bytes}-byte sample it isn't: naive per-byte Shannon entropy can never \
         exceed about {ceiling:.2} bits/byte here, no matter how random the source is — there \
         simply aren't enough bytes to occupy all 256 possible values, so this metric is capped \
         by sample size long before it says anything about randomness quality. For key material \
         the stakes are simpler and higher than for a ciphertext: there's no cipher construction \
         to fall back on here — a key an attacker can guess or narrow down is a direct, \
         standalone break, full stop, regardless of how sound XTS itself is. This test only \
         catches gross statistical failure (a stuck RNG, a zeroed buffer, a short repeating \
         pattern) — it cannot prove the underlying generator was actually a CSPRNG rather than \
         something merely random-*looking*, which is why where this key came from (see the note \
         printed alongside key generation) matters more than this number does."
    )
}

/// §2.5, generic variant: fires alongside `Event::EntropyScore` in the
/// standalone `entropy` command, which works on arbitrary
/// files/stdin — it has no idea whether the input is ciphertext, a
/// key, compressed data, or something else, so (unlike the two
/// variants above) it must not presume a specific origin.
pub fn explain_entropy_result_generic(bits_per_byte: f64) -> String {
    format!(
        "this data scored {bits_per_byte:.4} bits/byte. Near 8.0 is consistent with encrypted or \
         compressed content, or genuine random data — entropy alone can't distinguish those, and \
         can't tell you whether this data is *correct*, only that it lacks obvious repeating \
         structure. If you expected this to be ciphertext, a LOW score here is the useful signal: \
         it usually means something upstream isn't actually encrypting what you think it is."
    )
}

/// Fires once in `keygen`, right after the key is written (and, for
/// symmetry, could apply to a key already on disk in `keycheck`, but
/// that command's own `explain_keycheck_length` covers the
/// structural side already) — explains *where the bytes come from*
/// and *what shape they take*, which the entropy score alone can't
/// convey (a byte stream can look statistically perfect and still be
/// worthless if it wasn't from a real CSPRNG — see
/// `explain_entropy_result_key`). `is_xts` distinguishes the two
/// cipher families this tool supports, since they use the key bytes
/// completely differently.
pub fn explain_key_generation(key_bytes: usize, is_xts: bool) -> String {
    let structure = if is_xts {
        let half = key_bytes / 2;
        format!(
            "these {key_bytes} bytes are two independent {half}-byte AES keys concatenated back \
             to back: the first half encrypts your data, the second half encrypts the per-sector \
             tweak — see `nocap-crypt image encrypt --didactic` for how those two keys actually \
             get used together"
        )
    } else {
        format!(
            "these {key_bytes} bytes are the single AES key CBC-ESSIV uses directly for both \
             roles — its per-sector IV isn't a second independent key, it's derived by hashing \
             this same key with SHA-256, so there is exactly one real secret here, not two"
        )
    };
    format!(
        "this key comes from your OS's cryptographically secure random number generator \
         (CSPRNG) — real kernel/hardware entropy, never a language's plain, non-cryptographic \
         `rand()`, and never derived from a password or any other guessable seed. {structure}."
    )
}

/// Fires once in `bench`, before the worker-count sweep begins.
/// `nocap-crypt bench` had no didactic content at all before this —
/// the primer alone doesn't explain what's specific about a
/// benchmark, and the numbers it produces are easy to misread as an
/// in-memory-only microbenchmark if nothing says otherwise. Verified
/// against the actual implementation
/// (`nocap-crypt-worker::process_ranges`, real `SectorFile`s under a
/// real temp directory) rather than assumed — see
/// `nocap-crypt-bench::runner::run`.
pub fn explain_bench_methodology() -> &'static str {
    "these numbers come from encrypting real data through the exact same file-backed dispatch \
     path `image encrypt`/`decrypt` use — real temp files, real O_DIRECT-or-buffered I/O, real \
     AES-XTS — not an in-memory-only microbenchmark that would flatter the cipher and hide I/O \
     cost."
}

/// Fires once in `bench`, alongside `explain_bench_methodology`. The
/// seeded generator is a type deliberately separate from real
/// keygen's CSPRNG, so a benchmark data path can never reach real key
/// material by accident.
pub fn explain_bench_data_source(seed: u64) -> String {
    format!(
        "the plaintext being encrypted is synthetic: a fast, seeded, NON-cryptographic \
         pseudo-random generator (seed {seed}) fills it deterministically, so re-running with \
         the same --seed reproduces byte-identical input — useful for catching a real \
         performance regression instead of noise from different random data each run. This \
         generator is a completely separate type from key generation's CSPRNG and could never \
         be reached for real key material by accident."
    )
}

/// Fires once per worker-count sweep iteration in `bench`, alongside
/// that iteration's `Event::PhaseTiming`. Each pass forces
/// `Concurrency::Fixed`, bypassing the adaptive default, so the sweep
/// isolates throughput-vs-parallelism specifically.
pub fn explain_bench_worker_count(worker_count: usize) -> String {
    let plural = if worker_count == 1 { "" } else { "s" };
    format!(
        "workers={worker_count}: this pass forces exactly {worker_count} worker thread{plural} \
         for the whole run, not the adaptive default `image encrypt` picks on its own — the whole \
         point of sweeping this number is isolating how throughput scales with parallelism, which \
         is only safe to measure at all because XTS sectors don't chain together (see `image \
         encrypt --didactic` for why that's true and not just a performance convenience)."
    )
}

/// §2.6: upgraded from a bare one-liner with the *why* silent
/// corruption is the failure mode worth auto-checking. Fires
/// alongside `Event::AlignmentStatus`.
pub fn explain_alignment_context() -> &'static str {
    "alignment here means O_DIRECT sector-size alignment (buffers/offsets matching the device's \
     512- or 4096-byte sector size), not compiled-binary layout. Getting it wrong means silent \
     corruption or a kernel EINVAL, not a crash you'd notice immediately — which is why it's \
     checked automatically here rather than trusted to the caller."
}

/// e.g. "sector 4096 -> IV = 0x1000000000000000 LE"
pub fn explain_iv_derivation(sector_512: u64, iv: &[u8; 16]) -> String {
    let mut hex = String::with_capacity(32);
    for byte in iv.iter().rev() {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("sector {sector_512} -> IV = 0x{hex} (little-endian sector number, zero-padded to 16 bytes)")
}

/// Fires in `keycheck`, alongside `explain_entropy_result_key` — that
/// one covers entropy, this covers length.
pub fn explain_keycheck_length() -> &'static str {
    "key length must match the cipher spec exactly — XTS doubles the AES key size (two \
     concatenated keys, one per role), CBC-ESSIV doesn't. Get the length wrong and this fails \
     before entropy is even checked."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explains_sector_zero() {
        let text = explain_iv_derivation(0, &[0u8; 16]);
        assert!(text.contains("sector 0"));
    }

    #[test]
    fn explains_sector_4096() {
        let mut iv = [0u8; 16];
        iv[1] = 0x10;
        let text = explain_iv_derivation(4096, &iv);
        assert!(text.contains("sector 4096"));
        assert!(text.to_lowercase().contains("1000"));
    }

    #[test]
    fn keycheck_length_explanation_is_nonempty_and_does_not_repeat_the_entropy_point() {
        let text = explain_keycheck_length();
        assert!(!text.is_empty());
        // The entropy half of key validity is `explain_entropy_result_key`'s
        // job (fires alongside this, with the actual number) — this
        // function should stick to length, not restate "low-entropy."
        assert!(!text.to_lowercase().contains("low-entropy"));
    }

    #[test]
    fn primer_mentions_the_narration_arrow_and_never_promises_real_key_bytes() {
        assert!(DIDACTIC_PRIMER.contains('\u{2192}'));
        assert!(!DIDACTIC_PRIMER.to_lowercase().contains("shows the key"));
    }

    #[test]
    fn xts_diagram_shows_all_32_blocks_and_the_tweak_formula() {
        let d = xts_ascii_diagram();
        assert!(d.contains("blk 0"));
        assert!(d.contains("blk 31"));
        assert!(d.contains("T*a^0"));
        assert!(d.contains("T*a^31"));
        assert!(d.contains("AES(Key1"));
    }

    #[test]
    fn xts_diagram_columns_stay_aligned() {
        // Structural guard against a repeat of the freehand-ASCII-art
        // alignment mistake: every line above/below the tweak-formula
        // line (which carries a trailing comment and is intentionally
        // longer) must be the same width.
        let diagram = xts_ascii_diagram();
        let lines: Vec<&str> = diagram.lines().collect();
        let block_row_width = lines[2].chars().count();
        assert_eq!(lines[3].chars().count(), block_row_width, "connector row width drifted");
        assert_eq!(lines[8].chars().count(), block_row_width, "second block row width drifted");
    }

    #[test]
    fn xts_malleability_explains_both_properties_without_naming_a_cve() {
        let text = explain_xts_malleability();
        assert!(text.to_lowercase().contains("bit flip") || text.to_lowercase().contains("bit-level"));
        assert!(text.to_lowercase().contains("replayed") || text.to_lowercase().contains("splice"));
        assert!(text.contains("confidentiality only"));
    }

    #[test]
    fn new_topic_functions_are_all_nonempty() {
        assert!(!explain_block_cipher_basics().is_empty());
        assert!(!explain_xts_tweakability().is_empty());
        assert!(!xts_ascii_diagram().is_empty());
        assert!(!explain_xts_malleability().is_empty());
        assert!(!explain_plain64_tweak_is_not_secret().is_empty());
        assert!(!narration_sample_note().is_empty());
        assert!(!explain_headerless_plain().is_empty());
        assert!(!explain_headerless_plain_reference().is_empty());
        assert!(!explain_alignment_context().is_empty());
        assert!(!explain_bench_methodology().is_empty());
    }

    #[test]
    fn entropy_result_variants_include_the_real_number_passed_in() {
        assert!(explain_entropy_result_ciphertext(7.9991).contains("7.9991"));
        assert!(explain_entropy_result_key(7.9991, 64).contains("7.9991"));
        assert!(explain_entropy_result_generic(7.9991).contains("7.9991"));
    }

    /// Regression test for a real, user-reported confusion: `keycheck`
    /// on a genuinely random 64-byte key reported ~5.7 bits/byte with
    /// no context, reading as "this looks broken" when it's actually
    /// the expected value — naive per-byte Shannon entropy on a
    /// 64-byte sample is mathematically capped at log2(64) = 6.0,
    /// nowhere near the 8.0 maximum, regardless of randomness quality.
    #[test]
    fn key_entropy_explanation_states_the_sample_size_ceiling_not_just_the_score() {
        let text = explain_entropy_result_key(5.7070, 64);
        assert!(text.contains("64-byte"), "should name the actual sample size: {text:?}");
        assert!(text.contains("6.00"), "should state the real ceiling for this length (log2(64)=6.0): {text:?}");
        assert!(
            text.to_lowercase().contains("capped"),
            "should make clear the low number is a sample-size cap, not a weak-RNG signal: {text:?}"
        );

        let smaller = explain_entropy_result_key(5.0, 32);
        assert!(smaller.contains("32-byte"));
        assert!(smaller.contains("5.00"), "log2(32)=5.0: {smaller:?}");
    }

    #[test]
    fn entropy_result_variants_do_not_bleed_into_each_others_reasoning() {
        // The actual bug this guards against: the key/generic variants
        // used to be one function that opened with "this ciphertext
        // scored..." regardless of context, and reused
        // ciphertext-specific reasoning ("a forgotten unencrypted
        // region," "an attacker who flips ciphertext bits undetected")
        // for data that was never ciphertext at all. The key variant
        // is still allowed to *contrast itself* against ciphertext
        // reasoning by name (that's intentional, useful pedagogy) —
        // what it must never do is open by calling the subject a
        // ciphertext, or repeat the ciphertext-specific claims.
        let ciphertext = explain_entropy_result_ciphertext(7.9).to_lowercase();
        let key = explain_entropy_result_key(7.9, 64).to_lowercase();
        let generic = explain_entropy_result_generic(7.9).to_lowercase();

        assert!(ciphertext.starts_with("this ciphertext"));
        assert!(key.starts_with("this key"), "key entropy text should open by naming a key, not a ciphertext: {key:?}");
        assert!(
            generic.starts_with("this data"),
            "generic entropy text should not presume a specific origin: {generic:?}"
        );

        for wrong_claim in ["forgotten unencrypted region", "attacker who flips ciphertext bits undetected"] {
            assert!(!key.contains(wrong_claim), "key text repeats ciphertext-specific reasoning: {wrong_claim:?}");
            assert!(!generic.contains(wrong_claim), "generic text repeats ciphertext-specific reasoning: {wrong_claim:?}");
        }
    }

    #[test]
    fn key_generation_explains_csprng_sourcing_for_both_cipher_families() {
        let xts = explain_key_generation(64, true);
        assert!(xts.to_lowercase().contains("csprng"));
        assert!(xts.contains("32-byte"), "XTS variant should name the actual per-key half size: {xts:?}");
        assert!(xts.to_lowercase().contains("tweak"));

        let cbc = explain_key_generation(32, false);
        assert!(cbc.to_lowercase().contains("csprng"));
        assert!(cbc.to_lowercase().contains("sha-256"));
        assert!(!cbc.contains("32-byte AES keys"), "CBC-ESSIV has one key, not two: {cbc:?}");
    }

    #[test]
    fn key_generation_never_claims_a_password_derived_source() {
        // The whole point of this narration is that key material must
        // NOT come from something guessable — assert it says so.
        for text in [explain_key_generation(64, true), explain_key_generation(32, false)] {
            assert!(text.to_lowercase().contains("never derived from a password"));
        }
    }

    #[test]
    fn bench_methodology_says_this_is_real_io_not_a_microbenchmark() {
        let text = explain_bench_methodology().to_lowercase();
        assert!(text.contains("real"));
        assert!(text.contains("microbenchmark"));
    }

    #[test]
    fn bench_data_source_includes_the_real_seed_and_disclaims_cryptographic_use() {
        let text = explain_bench_data_source(42);
        assert!(text.contains('4') && text.contains('2'), "seed value should appear: {text:?}");
        assert!(text.to_lowercase().contains("non-cryptographic"));
        assert!(text.to_lowercase().contains("csprng"), "should contrast against real key generation: {text:?}");
    }

    #[test]
    fn bench_worker_count_pluralizes_correctly_and_names_the_count() {
        let one = explain_bench_worker_count(1);
        assert!(one.contains("workers=1"));
        assert!(!one.contains("1 worker threads"), "should not pluralize for count 1: {one:?}");

        let four = explain_bench_worker_count(4);
        assert!(four.contains("workers=4"));
        assert!(four.contains("4 worker threads"));
    }

    #[test]
    fn headerless_plain_never_claims_luks_parsing_is_supported() {
        let text = explain_headerless_plain();
        // Must acknowledge LUKS headers exist without implying this
        // tool parses them — only magic-byte detection is implemented.
        assert!(text.contains("doesn't parse"));
    }

    #[test]
    fn no_narration_function_takes_key_or_plaintext_bytes() {
        // Structural guard, not a runtime check: every function here
        // takes at most a sector number / pre-computed IV / entropy
        // score / byte count (all non-secret), never a `key: &[u8]` or
        // `plaintext: &[u8]` parameter. This test exists so a future
        // change that adds one is at least forced to touch this file
        // and its module-level safety-boundary doc comment.
        let _: fn(u64, &[u8; 16]) -> String = explain_iv_derivation;
        let _: fn(f64) -> String = explain_entropy_result_ciphertext;
        let _: fn(f64, usize) -> String = explain_entropy_result_key;
        let _: fn(f64) -> String = explain_entropy_result_generic;
        let _: fn(usize, bool) -> String = explain_key_generation;
        let _: fn(u64) -> String = explain_bench_data_source;
        let _: fn(usize) -> String = explain_bench_worker_count;
    }
}
