# meta-nocap-crypt

A Yocto layer with one recipe:

- `recipes-security/nocap-crypt/nocap-crypt_git.bb` — builds the
  `nocap-crypt` CLI (this project's headerless, `aes-xts-plain64`/
  `aes-cbc-essiv:sha256` sector-encryption tool) for target, and —
  because of `BBCLASSEXTEND = "native nativesdk"` — as
  `nocap-crypt-native`, usable as a build-time tool from any other
  recipe (`DEPENDS += "nocap-crypt-native"`, then invoke
  `${STAGING_BINDIR_NATIVE}/nocap-crypt` directly).

No `.bbclass`. There used to be one here (`nocap-crypt.bbclass`,
exposing a reusable `nocap_crypt_encrypt_image` shell function) — it's
gone because BitBake's `inherit` only resolves against `.bbclass`
files; there's no way to `inherit` functions from another recipe
directly. `require`/`include` can textually splice in an arbitrary
file, but that still means a second shared file every consuming recipe
depends on — not meaningfully different from the class this was
supposed to avoid. So: one recipe, and the commands a consuming recipe
would actually need (`keygen`, `image encrypt`, both under `--ci` for
loud non-zero-exit/grep-able-`NC-###` failure) are demonstrated in the
recipe's own `do_selftest_nocap_crypt` task instead of exposed as a
reusable class function — see that task body in the `.bb` file for the
exact invocation shape to copy into a real consuming recipe.

## Status

**Not yet build-tested against a real Yocto/Poky checkout** — this
environment doesn't have one available. Before relying on this layer:

1. Fill in the two `TODO`/`CHANGEME` placeholders in the recipe:
   `HOMEPAGE`/`SRC_URI` (no public repo exists yet) and
   `LIC_FILES_CHKSUM` (a `LICENSE` file now exists upstream at the
   repo root — run `md5sum LICENSE` there and paste the real hash in;
   the placeholder is intentionally wrong so BitBake refuses to build
   until it's fixed for real).
2. Add a Rust-toolchain layer ahead of this one in `bblayers.conf` —
   [meta-rust](https://github.com/meta-rust/meta-rust) (builds rustc
   from source) or
   [meta-rust-bin](https://github.com/rust-embedded/meta-rust-bin)
   (fetches a prebuilt toolchain, much faster) — either provides the
   `cargo` bbclass this recipe's `inherit cargo` depends on.
3. For a fully offline/hermetic build (every transitive crate
   fetched and checksummed by BitBake itself, not by `cargo` reaching
   the network mid-build), run
   [`cargo-bitbake`](https://github.com/meta-rust/cargo-bitbake)
   against the workspace's `Cargo.lock` and merge the generated
   `crate://` `SRC_URI` entries into the recipe — deliberately left as
   an explicit TODO rather than hand-fabricated (dozens of transitive
   dependencies, and guessing their checksums would be worse than
   leaving this undone).
4. `bitbake nocap-crypt` (target) and `bitbake nocap-crypt-native`
   (build-time tool, which also runs `do_selftest_nocap_crypt`) should
   then both build; report back what actually breaks so the recipe can
   be corrected against real BitBake output rather than guessed at
   further. The `:class-native`-override task-skipping pattern in
   `do_selftest_nocap_crypt` specifically is unverified against a real
   BitBake invocation.

## Using nocap-crypt as a build-time tool from another recipe

```bitbake
DEPENDS += "nocap-crypt-native"

do_encrypt_rootfs() {
    "${STAGING_BINDIR_NATIVE}/nocap-crypt" image encrypt \
        --input "${IMAGE_ROOTFS}.ext4" \
        --output "${DEPLOY_DIR_IMAGE}/${IMAGE_NAME}.ext4.enc" \
        --key-file "${DEPLOY_DIR_IMAGE}/my-volume.key" \
        --ci
}
addtask encrypt_rootfs after do_image_ext4 before do_image_complete
```

The resulting `*.ext4.enc` is byte-for-byte what real `cryptsetup
--type plain --cipher aes-xts-plain64` would have produced — mount it
for real on target with:

```sh
cryptsetup open --type plain --cipher aes-xts-plain64 \
    --key-size 512 -d my-volume.key my-volume.ext4.enc my-volume
mount /dev/mapper/my-volume /mnt/wherever
```
