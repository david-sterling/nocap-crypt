# 🧢 nocap: Make Userspace Great Again (MUGA)

> **Blazingly fast, unprivileged AES-XTS volume encryption.**

Ever tried to run `cryptsetup` inside a Docker container for your embedded CI/CD pipeline, only to be slapped with `Operation not permitted`? 

The kernel elites have been lying to you. They want you to believe you need `--privileged`. They want you to beg for `CAP_SYS_ADMIN`. They want to trap your CI/CD pipelines in bloated `dm-crypt` bureaucracy. 

**Not anymore. We say: No CAP.**

`nocap` is a pure userspace tool that does XTS plain AES ciphering of volumes (`squashfs`, `ext4`) with a LUKS wrapper. It rips volume encryption out of Ring 0 and puts it where it belongs: unprivileged userspace.

## 🦅 Features & Terminal UX

`nocap` isn't just a cryptographic wrapper; it's a terminal experience engineered to flex raw hardware dominance.

* 🚀 **Zero Kernel Dependencies:** Bypasses `dm-crypt` entirely. Runs in totally unprivileged Docker/Podman containers.
* 🌪️ **Raw Hardware Power:** Detects your architecture and leverages CPU instructions directly.
* 🦀 **Blazingly Fast:** Written in Rust, utilizing `rayon` for multi-core, parallel data ciphering.
* 🇺🇸 **Drain The Kernel Swamp:** Keep your cryptography in Ring 3.

### The Console Experience

**1. The "Drain the Swamp" Boot Sequence**
Upon execution, `nocap` audits your system and aggressively strips kernel privileges.
```text
[!] INITIATING OPERATION: N O C A P
[✓] Auditing Ring 0 Bureaucracy ... [ SWAMP DETECTED ]
[✓] Bypassing dm-crypt cabal ...... [ BYPASSED ]
[✓] Revoking CAP_SYS_ADMIN ........ [ PRIVILEGES STRIPPED ]
[✓] MAKE USERSPACE GREAT AGAIN .... [ PATRIOT MODE ENGAGED ]

