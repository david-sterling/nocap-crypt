use crate::event::{emit, Event, Reporter};

pub struct Verbose {
    pub json: bool,
}

impl Reporter for Verbose {
    fn report(&self, event: Event) {
        if matches!(event, Event::Narration { .. }) {
            return;
        }
        emit(&event, self.json);
    }

    fn boot_banner(&self) -> Option<&'static str> {
        Some(MUGA_BOOT_BANNER)
    }
}

/// Shared with [`crate::Didactic`], which has the same tone for
/// everything except narration.
pub(crate) const MUGA_BOOT_BANNER: &str = "\
[!] INITIATING OPERATION: N O C A P
[\u{2713}] Auditing Ring 0 Bureaucracy ... [ SWAMP DETECTED ]
[\u{2713}] Bypassing dm-crypt cabal ...... [ BYPASSED ]
[\u{2713}] Revoking CAP_SYS_ADMIN ........ [ PRIVILEGES STRIPPED ]
[\u{2713}] MAKE USERSPACE GREAT AGAIN .... [ PATRIOT MODE ENGAGED ]";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_does_not_narrate() {
        assert!(!Verbose { json: false }.narrates());
    }
}
