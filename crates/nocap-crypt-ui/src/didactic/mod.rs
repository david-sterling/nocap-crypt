//! The actual "didactic" content: narration text explaining how
//! `plain64`/XTS-AES work (`narrate`), an AES S-box visualization
//! (`sbox`), and the [`Didactic`] reporter that surfaces them. This is
//! the module the rest of the crate — output plumbing for every other
//! audience (`Silent`/`Verbose`/`Corporate`/`Ci`) — is not about.

pub mod narrate;
pub mod sbox;

use crate::event::{emit, Event, ProgressFlavor, Reporter};

pub struct Didactic {
    pub json: bool,
}

impl Reporter for Didactic {
    fn report(&self, event: Event) {
        // Narration is a human-only affordance — under --log-format
        // json it's suppressed here the same way progress bars and
        // boot banners already stay out of the machine-parseable
        // stream, rather than serialized as noise a JSON consumer
        // never asked for.
        if self.json && matches!(event, Event::Narration { .. }) {
            return;
        }
        emit(&event, self.json);
    }

    fn narrates(&self) -> bool {
        true
    }

    // No boot banner: the MUGA/4chan meme banner is `Verbose`'s thing
    // (it amuses); `Didactic` explains instead, via `didactic_primer`
    // below. Mixing the two was exactly the inconsistency this mode
    // exists to avoid — same reasoning as `progress_flavor` dropping
    // the Pepe animation.

    fn didactic_primer(&self) -> Option<&'static str> {
        Some(narrate::DIDACTIC_PRIMER)
    }

    fn progress_flavor(&self) -> ProgressFlavor {
        ProgressFlavor::Didactic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn didactic_narrates() {
        assert!(Didactic { json: false }.narrates());
    }
}
