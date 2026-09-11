//! Known-answer tests against IEEE P1619/D16 (May 2007), Annex B "Test
//! Vectors" — an independent, published specification of XTS-AES, not
//! affiliated with this project, `cryptsetup`, or the `xts-mode` crate
//! we depend on.
//!
//! Why these and not `xts-mode`'s own test fixtures: that crate's
//! fixtures use an always-zero tweak (an OpenSSL CLI quirk), not the
//! per-sector-incrementing plain64 tweak dm-crypt actually uses. These
//! vectors instead exercise the exact real-world shape: one AES-XTS
//! data unit of 512 bytes (our `SECTOR_SIZE`) at a chosen sector index,
//! which is precisely how `SectorEngine::encrypt_range` is called for
//! one sector.
//!
//! Provenance: hex extracted programmatically from
//! `pdftotext -layout` output of the official draft PDF (no manual
//! transcription of the hex payloads), cross-checked against a
//! vision-based read of the same PDF page for Vector 1 (not included
//! here — that one's an 32-byte non-sector-sized unit, less relevant
//! than these three). IEEE's "Data Unit Sequence Number" is exactly
//! our plain64 absolute sector index; "Key1" is the data-encryption
//! key, "Key2" the tweak-encryption key — concatenated (Key1 || Key2)
//! they are exactly the on-disk key material `SectorEngine` expects
//! for `aes-xts-plain64`.

use nocap_crypt_core::{CipherSpec, SectorEngine};

// Vector 4: XTS-AES-128, Data Unit Sequence Number = 0, 512-byte unit.
const VECTOR4_KEY1: &str = "27182818284590452353602874713526";
const VECTOR4_KEY2: &str = "31415926535897932384626433832795";
const VECTOR4_SECTOR: u64 = 0;
const VECTOR4_PTX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const VECTOR4_CTX: &str = "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89cc78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad02655ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f4341332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203ebb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18deb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568";

// Vector 9: XTS-AES-128, Data Unit Sequence Number = ff, 512-byte unit.
const VECTOR9_KEY1: &str = "27182818284590452353602874713526";
const VECTOR9_KEY2: &str = "31415926535897932384626433832795";
const VECTOR9_SECTOR: u64 = 0xff;
const VECTOR9_PTX: &str = "72efc1ebfe1ee25975a6eb3aa8589dda2b261f1c85bdab442a9e5b2dd1d7c3957a16fc08e526d4b1223f1b1232a11af274c3d70dac57f83e0983c498f1a6f1aecb021c3e70085a1e527f1ce41ee5911a82020161529cd82773762daf5459de94a0a82adae7e1703c808543c29ed6fb32d9e004327c1355180c995a07741493a09c21ba01a387882da4f62534b87bb15d60d197201c0fd3bf30c1500a3ecfecdd66d8721f90bcc4c17ee925c61b0a03727a9c0d5f5ca462fbfa0af1c2513a9d9d4b5345bd27a5f6e653f751693e6b6a2b8ead57d511e00e58c45b7b8d005af79288f5c7c22fd4f1bf7a898b03a5634c6a1ae3f9fae5de4f296a2896b23e7ed43ed14fa5a2803f4d28f0d3ffcf24757677aebdb47bb388378708948a8d4126ed1839e0da29a537a8c198b3c66ab00712dd261674bf45a73d67f76914f830ca014b65596f27e4cf62de66125a5566df9975155628b400fbfb3a29040ed50faffdbb18aece7c5c44693260aab386c0a37b11b114f1c415aebb653be468179428d43a4d8bc3ec38813eca30a13cf1bb18d524f1992d44d8b1a42ea30b22e6c95b199d8d182f8840b09d059585c31ad691fa0619ff038aca2c39a943421157361717c49d322028a74648113bd8c9d7ec77cf3c89c1ec8718ceff8516d96b34c3c614f10699c9abc4ed0411506223bea16af35c883accdbe1104eef0cfdb54e12fb230a";
const VECTOR9_CTX: &str = "3260ae8dad1f4a32c5cafe3ab0eb95549d461a67ceb9e5aa2d3afb62dece0553193ba50c75be251e08d1d08f1088576c7efdfaaf3f459559571e12511753b07af073f35da06af0ce0bbf6b8f5ccc5cea500ec1b211bd51f63b606bf6528796ca12173ba39b8935ee44ccce646f90a45bf9ccc567f0ace13dc2d53ebeedc81f58b2e41179dddf0d5a5c42f5d8506c1a5d2f8f59f3ea873cbcd0eec19acbf325423bd3dcb8c2b1bf1d1eaed0eba7f0698e4314fbeb2f1566d1b9253008cbccf45a2b0d9c5c9c21474f4076e02be26050b99dee4fd68a4cf890e496e4fcae7b70f94ea5a9062da0daeba1993d2ccd1dd3c244b8428801495a58b216547e7e847c46d1d756377b6242d2e5fb83bf752b54e0df71e889f3a2bb0f4c10805bf3c590376e3c24e22ff57f7fa965577375325cea5d920db94b9c336b455f6e894c01866fe9fbb8c8d3f70a2957285f6dfb5dcd8cbf54782f8fe7766d4723819913ac773421e3a31095866bad22c86a6036b2518b2059b4229d18c8c2ccbdf906c6cc6e82464ee57bddb0bebcb1dc645325bfb3e665ef7251082c88ebb1cf203bd779fdd38675713c8daadd17e1cabee432b09787b6ddf3304e38b731b45df5df51b78fcfb3d32466028d0ba36555e7e11ab0ee0666061d1645d962444bc47a38188930a84b4d561395c73c087021927ca638b7afc8a8679ccb84c26555440ec7f10445cd";

// Vector 10: XTS-AES-256, Data Unit Sequence Number = ff, 512-byte
// unit — matches our actual default cipher (`aes-xts-plain64` at
// 256-bit AES).
const VECTOR10_KEY1: &str = "2718281828459045235360287471352662497757247093699959574966967627";
const VECTOR10_KEY2: &str = "3141592653589793238462643383279502884197169399375105820974944592";
const VECTOR10_SECTOR: u64 = 0xff;
const VECTOR10_PTX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const VECTOR10_CTX: &str = "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed43851ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";

fn run_vector(
    key1_hex: &str,
    key2_hex: &str,
    aes_bits: u16,
    sector: u64,
    ptx_hex: &str,
    ctx_hex: &str,
) {
    let key1 = hex::decode(key1_hex).unwrap();
    let key2 = hex::decode(key2_hex).unwrap();
    let mut key = key1.clone();
    key.extend_from_slice(&key2);

    let ptx = hex::decode(ptx_hex).unwrap();
    let ctx = hex::decode(ctx_hex).unwrap();
    assert_eq!(
        ptx.len(),
        512,
        "vector data unit must be exactly one 512-byte sector"
    );
    assert_eq!(ctx.len(), 512);

    let spec = CipherSpec::parse("aes-xts-plain64")
        .unwrap()
        .with_aes_bits(aes_bits)
        .unwrap();
    let engine = SectorEngine::new(spec, &key).unwrap();

    let mut encrypted = ptx.clone();
    engine.encrypt_range(sector, &mut encrypted);
    assert_eq!(
        encrypted, ctx,
        "encryption did not match the IEEE 1619 known-answer ciphertext"
    );

    let mut decrypted = ctx.clone();
    engine.decrypt_range(sector, &mut decrypted);
    assert_eq!(
        decrypted, ptx,
        "decryption did not recover the IEEE 1619 known-answer plaintext"
    );
}

#[test]
fn kat_ieee1619_vector4_aes128_sector0() {
    run_vector(
        VECTOR4_KEY1,
        VECTOR4_KEY2,
        128,
        VECTOR4_SECTOR,
        VECTOR4_PTX,
        VECTOR4_CTX,
    );
}

#[test]
fn kat_ieee1619_vector9_aes128_sector_ff() {
    run_vector(
        VECTOR9_KEY1,
        VECTOR9_KEY2,
        128,
        VECTOR9_SECTOR,
        VECTOR9_PTX,
        VECTOR9_CTX,
    );
}

#[test]
fn kat_ieee1619_vector10_aes256_sector_ff() {
    run_vector(
        VECTOR10_KEY1,
        VECTOR10_KEY2,
        256,
        VECTOR10_SECTOR,
        VECTOR10_PTX,
        VECTOR10_CTX,
    );
}
