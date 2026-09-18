# Security Policy

`nocap-crypt` performs volume encryption. Cryptographic correctness bugs, key-handling bugs, and memory-safety issues are treated as security issues even if they don't look exploitable at first glance.

## Reporting a Vulnerability

Please **do not** open a public issue for a suspected security vulnerability.

Instead, use GitHub's private reporting for this repository: go to the **Security** tab → **Report a vulnerability**, or use [this link](https://github.com/david-sterling/nocap-crypt/security/advisories/new) directly. This opens a private advisory visible only to the maintainers until a fix is ready.

Please include:

- The affected version/commit.
- Cipher mode and key size involved, if relevant (`aes-xts-plain64`, `aes-cbc-essiv:sha256`).
- Steps to reproduce, or a minimal test case (known-answer vector, malformed input, etc.).
- The impact you believe this has (e.g. key recovery, plaintext recovery, ciphertext malleability beyond the documented XTS limitations).

## Scope

In scope:

- `nocap-crypt-core` (cipher engine, IV/tweak derivation)
- `nocap-crypt-keymgmt` (key generation, parsing, validation)
- `nocap-crypt-luks` / structural validation
- Anything that could cause silent data corruption or a weaker-than-documented cipher configuration to be accepted

Out of scope:

- The cosmetic UI/ASCII-art layers (`nocap-crypt-ui`) unless the issue causes a security-relevant misrepresentation (e.g. reporting success when encryption actually failed)
- Denial of service via oversized inputs on a machine you control

## Response

We'll acknowledge reports as soon as we can and aim to have a fix or mitigation plan before any public disclosure. Credit is given in the advisory unless you ask otherwise.
