//! Live progress display driven by real, in-flight work. A shared
//! atomic counter is incremented by
//! `nocap-crypt-worker::process_ranges`/`nocap-crypt-bench::run` as each
//! sector range actually finishes; a side thread polls that counter
//! and drives both the real `indicatif` metrics (percent, elapsed,
//! bytes/sec, ETA — all genuine, computed from real completed bytes)
//! and a cosmetic cycling animation on top (agency cap + pose, escalating
//! through a "hands up" and "cap lift" reveal near completion) — flavor
//! text only, same spirit as `--redpill`, never a substitute for real
//! numbers. The animation frames themselves live in [`ascii_frames`];
//! the [`nocap_crypt_ui::ProgressFlavor::Didactic`] rotating captions
//! live in [`didactic_lines`] — split out so this file stays about the
//! actual progress mechanism, not the flavor content layered on it.

mod ascii_frames;
mod didactic_lines;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use nocap_crypt_ui::ProgressFlavor;
use rand::seq::SliceRandom;

use ascii_frames::{cosmetic_percent_cap, final_reveal, frame_for, tinfoil_hat, HANDS_UP_TAGS, TOTAL_MIN_ANIMATION_TICKS};
use didactic_lines::{didactic_line_for, DIDACTIC_FINISH_LINE};

const POLL_INTERVAL: Duration = Duration::from_millis(120);

#[derive(Clone, Copy)]
enum FinalEnding {
    BareHead,
    TinfoilHat,
}

pub struct LiveProgress {
    counter: Arc<AtomicU64>,
    bar: ProgressBar,
    handle: Option<JoinHandle<()>>,
    flavor: ProgressFlavor,
    no_color: bool,
    /// Picked once in `start()` and reused at `finish()`, so the same
    /// quote stays fixed for the whole run rather than re-rolling on
    /// every frame. Independent of the animation thread's hands-up
    /// tag (a local in `start()`, not stored here) — see
    /// `ascii_frames::HANDS_UP_TAGS`'s doc comment for why.
    punchline_quote: &'static str,
    final_ending: FinalEnding,
}

impl LiveProgress {
    /// Start a live bar over `total_bytes`, labeled with `context`
    /// (e.g. `"encrypt / aes-xts-plain64"`) as the ALGORITHM/technical
    /// line (or, under [`ProgressFlavor::Sterile`], as the bar's own
    /// label). Returns `None` (no display, no thread spawned) when
    /// `enabled` is false — e.g. under `-q`, where the silent-mode
    /// contract forbids any output — or when there's nothing to show
    /// progress on.
    ///
    /// `flavor` selects the presentation (see [`ProgressFlavor`]).
    /// `no_color` (`--no-color`) keeps whichever flavor was chosen but
    /// strips every ANSI color code from it — the content stays, only
    /// the color does not.
    pub fn start(
        total_bytes: u64,
        context: impl Into<String>,
        enabled: bool,
        flavor: ProgressFlavor,
        no_color: bool,
    ) -> Option<Self> {
        if !enabled || total_bytes == 0 {
            return None;
        }

        let mut rng = rand::thread_rng();
        let hands_up_tag = *HANDS_UP_TAGS.choose(&mut rng).expect("HANDS_UP_TAGS is never empty");
        let punchline_quote = *nocap_crypt_ui::SATIRICAL_QUOTES
            .choose(&mut rng)
            .expect("SATIRICAL_QUOTES is never empty");
        let final_ending = if rand::random::<bool>() {
            FinalEnding::BareHead
        } else {
            FinalEnding::TinfoilHat
        };

        let counter = Arc::new(AtomicU64::new(0));
        let bar = ProgressBar::new(total_bytes);
        let context = context.into();

        match flavor {
            ProgressFlavor::Sterile => {
                if let Ok(style) =
                    ProgressStyle::with_template("{prefix}: [{bar:40}] {percent}% (Completed in {elapsed_precise})")
                {
                    bar.set_style(style.progress_chars("#>-"));
                }
                bar.set_prefix(context);
            }
            ProgressFlavor::Meme => {
                let template = if no_color {
                    "{msg}\n\n{bar:50} {percent}%\n[{elapsed_precise}] {bytes_per_sec} | ETA: {eta} | ALGORITHM: {prefix}"
                } else {
                    "{msg}\n\n{bar:50.green/dim} {percent}%\n[{elapsed_precise}] {bytes_per_sec} | ETA: {eta} | ALGORITHM: {prefix}"
                };
                if let Ok(style) = ProgressStyle::with_template(template) {
                    bar.set_style(style.progress_chars("██░"));
                }
                bar.set_prefix(context);
                bar.set_message(colorize(frame_for(0.0, 0, hands_up_tag), no_color));
            }
            ProgressFlavor::Didactic => {
                let template = if no_color {
                    "ALGORITHM: {prefix}\n\n{bar:50} {percent}%\n[{elapsed_precise}] {bytes_per_sec} | ETA: {eta}\n\n{msg}"
                } else {
                    "ALGORITHM: {prefix}\n\n{bar:50.green/dim} {percent}%\n[{elapsed_precise}] {bytes_per_sec} | ETA: {eta}\n\n{msg}"
                };
                if let Ok(style) = ProgressStyle::with_template(template) {
                    bar.set_style(style.progress_chars("██░"));
                }
                bar.set_prefix(context);
                bar.set_message(colorize(didactic_line_for(0).to_string(), no_color));
            }
        }

        let handle = {
            let counter = Arc::clone(&counter);
            let bar = bar.clone();
            let tag = hands_up_tag;
            std::thread::spawn(move || {
                let mut tick: u64 = 0;
                loop {
                    let done = counter.load(Ordering::Relaxed).min(total_bytes);
                    let real_percent = (done as f64 / total_bytes as f64) * 100.0;
                    bar.set_position(done);
                    match flavor {
                        ProgressFlavor::Meme => {
                            let display_percent = real_percent.min(cosmetic_percent_cap(tick));
                            bar.set_message(colorize(frame_for(display_percent, tick, tag), no_color));
                        }
                        ProgressFlavor::Didactic => {
                            bar.set_message(colorize(didactic_line_for(tick).to_string(), no_color));
                        }
                        ProgressFlavor::Sterile => {}
                    }
                    // The minimum-tick wait is a Meme-only concern (it
                    // exists purely so the hands-up/cap-lift frames get
                    // seen) — Sterile and Didactic have no such reveal
                    // to protect, so they finish the instant real work
                    // does, same as before this fix.
                    let min_ticks_satisfied = flavor != ProgressFlavor::Meme || tick >= TOTAL_MIN_ANIMATION_TICKS;
                    if done >= total_bytes && min_ticks_satisfied {
                        break;
                    }
                    tick += 1;
                    std::thread::sleep(POLL_INTERVAL);
                }
            })
        };

        Some(Self {
            counter,
            bar,
            handle: Some(handle),
            flavor,
            no_color,
            punchline_quote,
            final_ending,
        })
    }

    /// The counter to hand to `process_ranges`/`bench::run` as the
    /// `progress` argument.
    pub fn counter(&self) -> &Arc<AtomicU64> {
        &self.counter
    }

    /// Call once the real work is done: waits for the display thread to
    /// notice completion (at most one poll interval) and finalizes the
    /// bar. [`ProgressFlavor::Sterile`] and [`ProgressFlavor::Didactic`]
    /// both just finish the bar (the latter with a short closing line);
    /// [`ProgressFlavor::Meme`] gets the reveal ending (randomly chosen
    /// at `start()`) plus that run's hands-up punchline quote.
    pub fn finish(mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        match self.flavor {
            ProgressFlavor::Sterile => {
                self.bar.finish();
            }
            ProgressFlavor::Didactic => {
                self.bar
                    .finish_with_message(colorize(DIDACTIC_FINISH_LINE.to_string(), self.no_color));
            }
            ProgressFlavor::Meme => {
                let ending = match self.final_ending {
                    FinalEnding::BareHead => final_reveal(),
                    FinalEnding::TinfoilHat => tinfoil_hat(),
                };
                self.bar.finish_with_message(colorize(
                    format!(
                        "{ending}\n\n[\u{2713}] GLOWIES EVADED.\n[\u{2713}] KERNEL BYPASSED.\n[\u{2713}] USERSPACE SECURED.\n\n{quote}",
                        quote = self.punchline_quote
                    ),
                    self.no_color,
                ));
            }
        }
    }
}

/// Strip every `\x1b[...m` ANSI color/style code from `text` when
/// `no_color` is set, leaving the content (ASCII art shape, letters)
/// untouched — `--no-color` removes color, not the animation itself.
fn colorize(text: String, no_color: bool) -> String {
    if no_color {
        strip_ansi(&text)
    } else {
        text
    }
}

fn strip_ansi(s: &str) -> String {
    console::strip_ansi_codes(s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punchline_quotes_pool_is_nonempty_and_has_no_blank_entries() {
        assert!(!nocap_crypt_ui::SATIRICAL_QUOTES.is_empty());
        for quote in nocap_crypt_ui::SATIRICAL_QUOTES {
            assert!(!quote.trim().is_empty());
        }
    }

    #[test]
    fn colorize_strips_ansi_when_no_color_is_set() {
        let frame = frame_for(93.0, 0, "FBI"); // hands-up band: the tag argument is actually used here
        assert!(frame.contains('\u{1b}'), "fixture should actually contain ANSI codes");
        let stripped = colorize(frame, true);
        assert!(!stripped.contains('\u{1b}'));
        assert!(stripped.contains("[ FBI ]"));
    }

    #[test]
    fn colorize_leaves_ansi_untouched_when_no_color_is_false() {
        let frame = frame_for(93.0, 0, "FBI");
        assert_eq!(colorize(frame.clone(), false), frame);
    }
}
