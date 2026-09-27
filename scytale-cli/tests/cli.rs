//! The binary, end to end: every family round-trips through the
//! command line, wrong input is refused with the right status, and
//! where openssl is on the machine the formats agree with it.
//!
//! The binary is run as a process, which wasm has no way to do; the
//! unit tests inside it still run there.
#![cfg(not(target_family = "wasm"))]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_scytale");

/// A directory of this test's own, under the target directory.
fn dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `scytale` with `args`, `stdin` on its standard input.
fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

/// Runs and requires success, returning standard output.
fn ok(args: &[&str], stdin: &[u8]) -> Vec<u8> {
    let out = run(args, stdin);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Runs and requires the exit status `code`.
fn fails(args: &[&str], stdin: &[u8], code: i32) -> String {
    let out = run(args, stdin);
    assert_eq!(out.status.code(), Some(code), "{args:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap().trim_end().to_owned()
}

const KEY16: &str = "hex:000102030405060708090a0b0c0d0e0f";
const KEY32: &str =
    "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV: &str = "hex:0f0e0d0c0b0a09080706050403020100";
const NONCE: &str = "hex:000000000000000000000001";

#[test]
fn hash_matches_the_vectors() {
    let out = text(ok(&["hash", "-a", "sha256"], b"abc"));
    assert_eq!(
        out,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -"
    );
    let out = text(ok(&["hash", "-a", "sha3-256"], b""));
    assert!(out.starts_with("a7ffc6f8bf1ed76651c14756a061d662"));
    let out = text(ok(&["hash", "-a", "shake128", "--length", "16"], b""));
    assert_eq!(out, "7f9c2ba4e88f827d616045507605853e  -");
    let out = ok(&["hash", "--binary"], b"abc");
    assert_eq!(out.len(), 32);
    fails(&["hash", "-a", "md5"], b"", 2);
    fails(&["hash", "-a", "shake256"], b"", 2);
}

#[test]
fn keys_are_checked_before_anything_runs() {
    // Wrong length, refused with the sizes and without the bytes.
    let err = fails(
        &[
            "aead",
            "encrypt",
            "-a",
            "aes-256-gcm",
            "-k",
            KEY16,
            "-n",
            NONCE,
        ],
        b"x",
        2,
    );
    assert!(err.contains("32 bytes, got 16"), "{err}");
    assert!(!err.contains("0001020304"), "{err}");
    // No prefix, odd hex, a bad prefix, a text key.
    for bad in ["00", "hex:0", "bin:00", "str:password"] {
        let err = fails(
            &[
                "aead",
                "encrypt",
                "-a",
                "aes-128-gcm",
                "-k",
                bad,
                "-n",
                NONCE,
            ],
            b"x",
            2,
        );
        assert!(!err.is_empty());
    }
    // The other sources of a key.
    let d = dir("keys");
    let path = d.join("k");
    fs::write(&path, [0u8; 16]).unwrap();
    let file = format!("file:{}", path.display());
    let a = ok(&["mac", "-a", "cmac-aes-128", "-k", &file], b"m");
    let b = ok(
        &[
            "mac",
            "-a",
            "cmac-aes-128",
            "-k",
            &format!("hex:{}", "00".repeat(16)),
        ],
        b"m",
    );
    assert_eq!(a, b);
}

#[test]
fn aead_round_trips_and_detects_tampering() {
    for alg in [
        "aes-128-gcm",
        "aes-128-gcm-siv",
        "aes-128-ccm",
        "chacha20-poly1305",
    ] {
        let key = if alg == "chacha20-poly1305" {
            KEY32
        } else {
            KEY16
        };
        let message = b"the quick brown fox".repeat(1000);
        let enc = [
            "aead",
            "encrypt",
            "-a",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:header",
        ];
        let mut sealed = ok(&enc, &message);
        assert_eq!(sealed.len(), message.len() + 16);
        let dec = [
            "aead",
            "decrypt",
            "-a",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:header",
        ];
        assert_eq!(ok(&dec, &sealed), message);
        // A flipped bit, the wrong aad, and a short input.
        sealed[5] ^= 1;
        let out = run(&dec, &sealed);
        assert_eq!(out.status.code(), Some(1), "{alg}");
        assert!(out.stdout.is_empty(), "{alg}: plaintext leaked");
        sealed[5] ^= 1;
        let wrong = [
            "aead",
            "decrypt",
            "-a",
            alg,
            "-k",
            key,
            "-n",
            NONCE,
            "--aad",
            "str:other",
        ];
        fails(&wrong, &sealed, 1);
        fails(&dec, &sealed[..8], 2);
    }
    // XPN: a 24-byte nonce.
    let nonce = "hex:000000000000000000000001000000000000000000000002";
    let enc = [
        "aead",
        "encrypt",
        "-a",
        "aes-256-xpn",
        "-k",
        KEY32,
        "-n",
        nonce,
    ];
    let dec = [
        "aead",
        "decrypt",
        "-a",
        "aes-256-xpn",
        "-k",
        KEY32,
        "-n",
        nonce,
    ];
    let sealed = ok(&enc, b"xpn");
    assert_eq!(ok(&dec, &sealed), b"xpn");
    // GCM with a truncated tag.
    let enc = [
        "aead",
        "encrypt",
        "-a",
        "aes-128-gcm",
        "-k",
        KEY16,
        "-n",
        NONCE,
        "--tag-length",
        "12",
    ];
    let dec = [
        "aead",
        "decrypt",
        "-a",
        "aes-128-gcm",
        "-k",
        KEY16,
        "-n",
        NONCE,
        "--tag-length",
        "12",
    ];
    let sealed = ok(&enc, b"short tag");
    assert_eq!(sealed.len(), 9 + 12);
    assert_eq!(ok(&dec, &sealed), b"short tag");
}

#[test]
fn gcm_matches_the_nist_vector() {
    // GCM test case 2 from the GCM specification: zero key, zero IV,
    // one zero block.
    let zero_key = format!("hex:{}", "00".repeat(16));
    let zero_nonce = format!("hex:{}", "00".repeat(12));
    let out = ok(
        &[
            "aead",
            "encrypt",
            "-a",
            "aes-128-gcm",
            "-k",
            &zero_key,
            "-n",
            &zero_nonce,
        ],
        &[0u8; 16],
    );
    assert_eq!(
        hex(&out),
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    );
}

#[test]
fn every_cipher_mode_round_trips() {
    let message: Vec<u8> = (0..100_003u32).map(|i| (i * 7) as u8).collect();
    for alg in [
        "aes-128-ecb",
        "aes-192-cbc",
        "aes-256-ctr",
        "aes-128-cfb1",
        "aes-128-cfb8",
        "aes-256-cfb128",
        "aes-128-ofb",
    ] {
        let mut enc = vec!["cipher", "encrypt", "-a", alg, "-k"];
        let key = match &alg[4..7] {
            "128" => KEY16.to_owned(),
            "192" => format!("hex:{}", "01".repeat(24)),
            _ => KEY32.to_owned(),
        };
        enc.push(&key);
        if alg != "aes-128-ecb" {
            enc.extend(["--iv", IV]);
        }
        let mut dec = enc.clone();
        dec[1] = "decrypt";
        let ciphertext = ok(&enc, &message);
        let padded =
            matches!(alg, "aes-128-ecb" | "aes-192-cbc" | "aes-256-cfb128");
        if padded {
            assert_eq!(
                ciphertext.len(),
                (message.len() / 16 + 1) * 16,
                "{alg}"
            );
        } else {
            assert_eq!(ciphertext.len(), message.len(), "{alg}");
        }
        assert_eq!(ok(&dec, &ciphertext), message, "{alg}");
        assert_ne!(&ciphertext[..message.len()], &message[..], "{alg}");
    }
    // Without padding, a partial block is refused; a whole one passes.
    let enc = [
        "cipher",
        "encrypt",
        "-a",
        "aes-128-cbc",
        "-k",
        KEY16,
        "--iv",
        IV,
        "--padding",
        "none",
    ];
    fails(&enc, &message, 2);
    assert_eq!(ok(&enc, &message[..32]).len(), 32);
    // Padding stripped on decrypt that does not check is status 1.
    let dec = [
        "cipher",
        "decrypt",
        "-a",
        "aes-128-cbc",
        "-k",
        KEY16,
        "--iv",
        IV,
    ];
    fails(&dec, &[0u8; 32], 1);
    // ECB refuses an IV; CBC needs one.
    fails(
        &[
            "cipher",
            "encrypt",
            "-a",
            "aes-128-ecb",
            "-k",
            KEY16,
            "--iv",
            IV,
        ],
        b"",
        2,
    );
    fails(
        &["cipher", "encrypt", "-a", "aes-128-cbc", "-k", KEY16],
        b"",
        2,
    );
}

#[test]
fn xts_kw_chacha20_and_fpe() {
    // XTS takes both keys at once, and they must differ.
    let two = format!("hex:{}{}", &KEY16[4..], "ff".repeat(16));
    let enc = [
        "cipher",
        "encrypt",
        "-a",
        "aes-128-xts",
        "-k",
        &two,
        "--iv",
        IV,
    ];
    let dec = [
        "cipher",
        "decrypt",
        "-a",
        "aes-128-xts",
        "-k",
        &two,
        "--iv",
        IV,
    ];
    let sector = [0x5au8; 520];
    let c = ok(&enc, &sector);
    assert_eq!(c.len(), 520);
    assert_eq!(ok(&dec, &c), sector);
    fails(
        &[
            "cipher",
            "encrypt",
            "-a",
            "aes-128-xts",
            "-k",
            KEY16,
            "--iv",
            IV,
        ],
        &sector,
        2,
    );

    // Key wrap: RFC 3394 4.1.
    let kek = "hex:000102030405060708090A0B0C0D0E0F";
    let wrapped = ok(
        &["cipher", "encrypt", "-a", "aes-128-kw", "-k", kek],
        &hex_bytes("00112233445566778899AABBCCDDEEFF"),
    );
    assert_eq!(
        hex(&wrapped),
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    );
    let back = ok(
        &["cipher", "decrypt", "-a", "aes-128-kw", "-k", kek],
        &wrapped,
    );
    assert_eq!(hex(&back), "00112233445566778899aabbccddeeff");
    let kwp = ok(
        &["cipher", "encrypt", "-a", "aes-256-kwp", "-k", KEY32],
        b"12345",
    );
    assert_eq!(kwp.len(), 16);
    let back = ok(
        &["cipher", "decrypt", "-a", "aes-256-kwp", "-k", KEY32],
        &kwp,
    );
    assert_eq!(back, b"12345");

    // ChaCha20: RFC 8439 2.4.2 uses a counter of 1.
    let key =
        "hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce = "hex:000000000000004a00000000";
    let out = ok(
        &[
            "cipher",
            "encrypt",
            "-a",
            "chacha20",
            "-k",
            key,
            "--nonce",
            nonce,
            "--counter",
            "1",
        ],
        b"Ladies and Gentlemen of the class of '99: If I could offer you \
          only one tip for the future, sunscreen would be it.",
    );
    assert!(hex(&out).starts_with("6e2e359a2568f98041ba0728dd0d6981"));

    // FF1 over digits, one line at a time.
    let enc = ["cipher", "encrypt", "-a", "ff1-aes-128", "-k", KEY16];
    let dec = ["cipher", "decrypt", "-a", "ff1-aes-128", "-k", KEY16];
    let c = text(ok(&enc, b"4000123456789010\n0123456789\n"));
    let lines: Vec<&str> = c.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].len(), 16);
    assert!(lines[0].bytes().all(|b| b.is_ascii_digit()));
    assert_ne!(lines[0], "4000123456789010");
    let back = text(ok(&dec, format!("{c}\n").as_bytes()));
    assert_eq!(back, "4000123456789010\n0123456789");
    fails(&enc, b"12a4\n", 2);
    // FF3-1 with a 7-byte tweak and a custom alphabet.
    let enc = [
        "cipher",
        "encrypt",
        "-a",
        "ff3-1-aes-256",
        "-k",
        KEY32,
        "--tweak",
        "hex:00000000000000",
        "--alphabet",
        "abcdefghijklmnopqrstuvwxyz",
    ];
    let c = text(ok(&enc, b"helloworld\n"));
    assert_eq!(c.len(), 10);
    assert!(c.bytes().all(|b| b.is_ascii_lowercase()));
}

#[test]
fn mac_and_kdf() {
    // RFC 4231 test case 2.
    let out = text(ok(
        &["mac", "-a", "hmac-sha256", "-k", "hex:4a656665"],
        b"what do ya want for nothing?",
    ));
    assert_eq!(
        out,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    let verify = ["mac", "-a", "hmac-sha256", "-k", "hex:4a656665", "--verify"];
    let tag = format!("hex:{out}");
    let mut good = verify.to_vec();
    good.push(&tag);
    ok(&good, b"what do ya want for nothing?");
    fails(&good, b"what do ya want for something?", 1);
    // CMAC, KMAC and Poly1305 run and have the right sizes.
    assert_eq!(
        text(ok(&["mac", "-a", "cmac-aes-256", "-k", KEY32], b"")).len(),
        32
    );
    let kmac = ok(
        &[
            "mac",
            "-a",
            "kmac128",
            "-k",
            KEY32,
            "--length",
            "8",
            "--customization",
            "str:x",
        ],
        b"m",
    );
    assert_eq!(text(kmac).len(), 16);
    assert_eq!(
        text(ok(&["mac", "-a", "poly1305", "-k", KEY32], b"m")).len(),
        32
    );
    fails(&["mac", "-a", "poly1305", "-k", KEY16], b"m", 2);

    // RFC 5869 test case 1.
    let ikm = format!("hex:{}", "0b".repeat(22));
    let out = text(ok(
        &[
            "kdf",
            "hkdf",
            "--ikm",
            &ikm,
            "--salt",
            "hex:000102030405060708090a0b0c",
            "--info",
            "hex:f0f1f2f3f4f5f6f7f8f9",
            "--length",
            "42",
        ],
        b"",
    ));
    assert_eq!(
        out,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865"
    );
    // RFC 6070 test case 2.
    let out = text(ok(
        &[
            "kdf",
            "pbkdf2",
            "-H",
            "sha1",
            "--password",
            "str:password",
            "--salt",
            "str:salt",
            "--iterations",
            "2",
            "--length",
            "20",
        ],
        b"",
    ));
    assert_eq!(out, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    fails(
        &[
            "kdf",
            "pbkdf2",
            "--password",
            "str:p",
            "--salt",
            "str:s",
            "-i",
            "0",
            "-l",
            "8",
        ],
        b"",
        2,
    );
}

#[test]
fn random_is_random() {
    let a = text(ok(&["random", "32"], b""));
    let b = text(ok(&["random", "32"], b""));
    assert_eq!(a.len(), 64);
    assert_ne!(a, b);
    assert_eq!(ok(&["random", "70000", "--binary"], b"").len(), 70000);
}

#[test]
fn every_key_algorithm_signs_agrees_or_encapsulates() {
    let d = dir("pk");
    let message = b"a message to sign";
    for alg in [
        "ed25519",
        "ecdsa-p256",
        "ecdsa-p384",
        "rsa-1024",
        "ml-dsa-44",
        "slh-dsa-shake-128f",
    ] {
        let private = d.join(format!("{alg}.pem"));
        let public = d.join(format!("{alg}.pub"));
        let (private, public) =
            (private.to_str().unwrap(), public.to_str().unwrap());
        ok(&["key", "generate", "-a", alg, "-o", private], b"");
        assert!(
            fs::read_to_string(private)
                .unwrap()
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );
        ok(&["key", "public", "--in", private, "-o", public], b"");
        assert!(
            fs::read_to_string(public)
                .unwrap()
                .starts_with("-----BEGIN PUBLIC KEY-----\n")
        );
        let shown = text(ok(&["key", "show", "--in", private], b""));
        assert!(shown.contains("private key"), "{shown}");
        let sig = ok(&["sig", "sign", "-k", private], message);
        let sig_hex = format!("hex:{}", hex(&sig));
        ok(&["sig", "verify", "-p", public, "-s", &sig_hex], message);
        fails(
            &["sig", "verify", "-p", public, "-s", &sig_hex],
            b"another",
            1,
        );
        // The private key is refused where the public one is wanted.
        fails(
            &["sig", "verify", "-p", private, "-s", &sig_hex],
            message,
            2,
        );
        if alg.starts_with("ecdsa") {
            let raw = ok(&["sig", "sign", "-k", private, "--raw"], message);
            let raw_hex = format!("hex:{}", hex(&raw));
            ok(
                &["sig", "verify", "-p", public, "-s", &raw_hex, "--raw"],
                message,
            );
            fails(&["sig", "verify", "-p", public, "-s", &raw_hex], message, 2);
        }
        if alg == "rsa-1024" {
            let pkcs1 = ok(
                &["sig", "sign", "-k", private, "--rsa-scheme", "pkcs1"],
                message,
            );
            let pkcs1_hex = format!("hex:{}", hex(&pkcs1));
            ok(
                &[
                    "sig",
                    "verify",
                    "-p",
                    public,
                    "-s",
                    &pkcs1_hex,
                    "--rsa-scheme",
                    "pkcs1",
                ],
                message,
            );
            fails(
                &["sig", "verify", "-p", public, "-s", &pkcs1_hex],
                message,
                1,
            );
            assert!(
                text(ok(&["key", "show", "--in", public], b""))
                    .contains("1024 bits")
            );
            // RSA-OAEP too.
            let c = ok(
                &["pke", "encrypt", "-p", public, "--label", "str:l"],
                b"secret",
            );
            assert_eq!(c.len(), 128);
            assert_eq!(
                ok(&["pke", "decrypt", "-k", private, "--label", "str:l"], &c),
                b"secret"
            );
            fails(&["pke", "decrypt", "-k", private], &c, 1);
        }
    }
    // Context strings on the algorithms that take them.
    let private = d.join("ed25519.pem").to_str().unwrap().to_owned();
    let public = d.join("ed25519.pub").to_str().unwrap().to_owned();
    let sig = ok(
        &["sig", "sign", "-k", &private, "--context", "str:ctx"],
        message,
    );
    let sig_hex = format!("hex:{}", hex(&sig));
    ok(
        &[
            "sig",
            "verify",
            "-p",
            &public,
            "-s",
            &sig_hex,
            "--context",
            "str:ctx",
        ],
        message,
    );
    fails(
        &["sig", "verify", "-p", &public, "-s", &sig_hex],
        message,
        1,
    );

    // Key agreement: both sides reach the same secret.
    for alg in ["x25519", "ecdh-p256", "ecdh-p384"] {
        let a = d.join(format!("{alg}-a.pem"));
        let b = d.join(format!("{alg}-b.pem"));
        let (a, b) = (a.to_str().unwrap(), b.to_str().unwrap());
        let a_pub = format!("{a}.pub");
        let b_pub = format!("{b}.pub");
        ok(&["key", "generate", "-a", alg, "-o", a], b"");
        ok(&["key", "generate", "-a", alg, "-o", b], b"");
        ok(&["key", "public", "--in", a, "-o", &a_pub], b"");
        ok(&["key", "public", "--in", b, "-o", &b_pub], b"");
        let ab = ok(&["kex", "agree", "-k", a, "-p", &b_pub, "--hex"], b"");
        let ba = ok(&["kex", "agree", "-k", b, "-p", &a_pub, "--hex"], b"");
        assert_eq!(ab, ba, "{alg}");
        assert_eq!(text(ab).len(), if alg == "ecdh-p384" { 96 } else { 64 });
    }
    let x = d.join("x25519-a.pem").to_str().unwrap().to_owned();
    let p = format!("{}.pub", d.join("ecdh-p256-b.pem").display());
    fails(&["kex", "agree", "-k", &x, "-p", &p], b"", 2);

    // Encapsulation: the secret written aside equals the one
    // decapsulated.
    for alg in ["ml-kem-512", "ml-kem-1024"] {
        let private = d.join(format!("{alg}.pem"));
        let public = d.join(format!("{alg}.pub"));
        let secret = d.join(format!("{alg}.ss"));
        let (private, public, secret) = (
            private.to_str().unwrap(),
            public.to_str().unwrap(),
            secret.to_str().unwrap(),
        );
        ok(&["key", "generate", "-a", alg, "-o", private], b"");
        ok(&["key", "public", "--in", private, "-o", public], b"");
        let ciphertext = ok(
            &[
                "kem",
                "encapsulate",
                "-p",
                public,
                "--secret-out",
                secret,
                "--hex",
            ],
            b"",
        );
        let ciphertext = hex_bytes(&text(ciphertext));
        let ss =
            ok(&["kem", "decapsulate", "-k", private, "--hex"], &ciphertext);
        assert_eq!(text(ss), text(fs::read(secret).unwrap()));
        fails(&["kem", "decapsulate", "-k", private], &ciphertext[..10], 2);
    }
    // A key of the wrong family, and a file that is not a key.
    let kem = d.join("ml-kem-512.pem").to_str().unwrap().to_owned();
    fails(&["sig", "sign", "-k", &kem], message, 2);
    let junk = d.join("junk");
    fs::write(&junk, "not a key").unwrap();
    fails(&["sig", "sign", "-k", junk.to_str().unwrap()], message, 2);
    fails(&["key", "generate", "-a", "dsa"], b"", 2);
}

#[test]
fn list_names_only_what_runs() {
    let all = text(ok(&["list"], b""));
    assert!(all.lines().count() > 100);
    for family in ["cipher", "aead", "hash", "mac", "key"] {
        let names = text(ok(&["list", family], b""));
        assert!(names.lines().count() > 3, "{family}");
        for name in names.lines() {
            assert!(all.contains(&format!("{family} {name}")));
        }
    }
    fails(&["list", "kdf"], b"", 2);
    // Every named cipher and aead at least gets past the name check.
    for name in text(ok(&["list", "cipher"], b"")).lines() {
        let err =
            fails(&["cipher", "encrypt", "-a", name, "-k", "hex:00"], b"", 2);
        assert!(!err.contains("unknown"), "{name}: {err}");
    }
    for name in text(ok(&["list", "aead"], b"")).lines() {
        let err = fails(
            &["aead", "encrypt", "-a", name, "-k", "hex:00", "-n", NONCE],
            b"",
            2,
        );
        assert!(!err.contains("unknown"), "{name}: {err}");
    }
    for name in text(ok(&["list", "mac"], b"")).lines() {
        let err = fails(&["mac", "-a", name, "-k", "00"], b"", 2);
        assert!(!err.contains("unknown"), "{name}: {err}");
    }
}

#[test]
fn agrees_with_openssl_where_it_is_present() {
    let openssl = |args: &[&str], stdin: &[u8]| -> Option<Vec<u8>> {
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take()?.write_all(stdin).ok()?;
        let out = child.wait_with_output().ok()?;
        out.status.success().then_some(out.stdout)
    };
    let message = b"fourteen bytes".repeat(37);
    let Some(theirs) = openssl(
        &["enc", "-aes-128-cbc", "-K", &KEY16[4..], "-iv", &IV[4..]],
        &message,
    ) else {
        eprintln!("openssl not found; skipping");
        return;
    };
    let ours = ok(
        &[
            "cipher",
            "encrypt",
            "-a",
            "aes-128-cbc",
            "-k",
            KEY16,
            "--iv",
            IV,
        ],
        &message,
    );
    assert_eq!(ours, theirs, "CBC with PKCS#7");
    let back = ok(
        &[
            "cipher",
            "decrypt",
            "-a",
            "aes-128-cbc",
            "-k",
            KEY16,
            "--iv",
            IV,
        ],
        &theirs,
    );
    assert_eq!(back, message);

    // A key openssl made, read here; a key made here, read there.
    let d = dir("openssl");
    let key = d.join("ec.pem");
    if let Some(pem) = openssl(
        &["ecparam", "-genkey", "-name", "prime256v1", "-noout"],
        b"",
    ) {
        fs::write(&key, pem).unwrap();
        let shown =
            text(ok(&["key", "show", "--in", key.to_str().unwrap()], b""));
        assert_eq!(shown, "P-256 private key");
        let public = d.join("ec.pub");
        ok(
            &[
                "key",
                "public",
                "--in",
                key.to_str().unwrap(),
                "-o",
                public.to_str().unwrap(),
            ],
            b"",
        );
        let sig = ok(&["sig", "sign", "-k", key.to_str().unwrap()], &message);
        let sig_path = d.join("ec.sig");
        fs::write(&sig_path, &sig).unwrap();
        let verified = openssl(
            &[
                "dgst",
                "-sha256",
                "-verify",
                public.to_str().unwrap(),
                "-signature",
                sig_path.to_str().unwrap(),
            ],
            &message,
        );
        assert!(verified.is_some(), "openssl rejected our ECDSA signature");
    }
    let ours = d.join("ed.pem");
    ok(
        &[
            "key",
            "generate",
            "-a",
            "ed25519",
            "-o",
            ours.to_str().unwrap(),
        ],
        b"",
    );
    let theirs =
        openssl(&["pkey", "-in", ours.to_str().unwrap(), "-pubout"], b"");
    if let Some(theirs) = theirs {
        let public =
            ok(&["key", "public", "--in", ours.to_str().unwrap()], b"");
        assert_eq!(public, theirs);
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
