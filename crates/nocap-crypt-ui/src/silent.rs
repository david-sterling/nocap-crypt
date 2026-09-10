use crate::event::{Event, Reporter};

pub struct Silent;

impl Reporter for Silent {
    fn report(&self, _event: Event) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_never_panics_on_any_event() {
        let r = Silent;
        r.report(Event::Message {
            text: "should be dropped".to_string(),
        });
        r.report(Event::Error {
            text: "should also be dropped".to_string(),
        });
    }

    #[test]
    fn silent_has_no_boot_banner() {
        assert_eq!(Silent.boot_banner(), None);
    }
}
