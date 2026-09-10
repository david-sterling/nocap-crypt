//! `nocap-crypt info` — hardware accel, backend, build info. No data
//! touched.

use nocap_crypt_ui::{Event, Reporter};

use crate::exitcode::ExitCode;

pub fn run(reporter: &dyn Reporter, json: bool) -> ExitCode {
    let info = nocap_crypt_sysinfo::collect();

    if json {
        if let Ok(text) = serde_json::to_string_pretty(&info) {
            reporter.report(Event::Message { text });
        }
        return ExitCode::Success;
    }

    reporter.report(Event::HardwareAccelPath {
        description: info.hw_accel.active_path_description.clone(),
    });
    reporter.report(Event::Message {
        text: format!(
            "arch: {}, cpu AES extensions: {}, backend hardware path active: {}",
            info.hw_accel.target_arch,
            info.hw_accel.cpu_supports_aes_extensions,
            info.hw_accel.crypto_backend_uses_hardware
        ),
    });
    reporter.report(Event::Message {
        text: format!(
            "crypto backend: {} (ciphers: {})",
            info.crypto_backend.backend,
            info.crypto_backend.cipher_specs_compiled_in.join(", ")
        ),
    });
    reporter.report(Event::Message {
        text: format!(
            "build: nocap-crypt {} ({}-{}) — git {}",
            info.build.package_version, info.build.target_arch, info.build.target_os, info.build.git_sha
        ),
    });

    ExitCode::Success
}
