<!-- Generated from scytale.1 by scripts/man-md; edit that. -->

# scytale(1)

## NAME

scytale - cryptographic command line tool

## SYNOPSIS

**scytale** *command* \[*subcommand*\] \[*options*\] \[*file*\]  
**scytale list** \[*family*\]  
**scytale** *command* **--help**

## DESCRIPTION

**scytale** runs the operations of the scytale library from the command
line, one command per module of the library: **hash**, **mac**,
**aead**, **cipher**, **kdf**, **key**, **sig**, **kex**, **kem**,
**pke** and **random**.

Input is standard input, or the *file* named last on the command line.
Output is standard output, or the file named by **-o**. A file that
holds a secret, whether a generated key, a shared secret or a derived
key, is created readable by its owner alone.

Every option that carries bytes, such as a key, IV, nonce, tag, salt,
signature or label, is written with a prefix that says how to read it
(see **VALUES**). The algorithm fixes the length of a key, IV or nonce,
and a value of another length is refused: nothing is padded or cut to
fit.

## VALUES

**hex:***digits*  
Hex, in either case: no **0x**, no separators, and an even count of
digits.

**file:***path*  
The raw bytes of the file, all of them.

**fd:***n*  
The raw bytes read to the end of descriptor *n*, for **3\<** *keyfile*
in a script.

**env:***name*  
The value of the environment variable *name*, as hex.

**str:***text*  
The text itself. Allowed for additional data, labels, salts, contexts
and passwords; refused for a key, since a key typed as text is a
password without a key derivation.

A value without a prefix is an error. A key given as **hex:** on the
command line is visible to every process on the machine through
**ps**(1) and stays in the shell's history, so **file:** or **fd:** is
the better form for one; there is nothing wrong with **hex:** for a
nonce or a salt, or in a script that already holds the key that way.

## OPTIONS

Every option has a long form, and the long form is what the text below
refers to. The short forms, where a command has them:

**-a**, **--algorithm**  
The algorithm, by the names **scytale list** prints.

**-k**, **--key**  
A key value, or for the public-key commands a private key file.

**-p**, **--public**  
A public key file; for **kex agree** the option is **--peer**.

**-s**, **--signature**  
A signature value.

**-n**, **--nonce**  
A nonce value.

**-H**, **--hash**  
A hash, by name.

**-l**, **--length**  
An output length in bytes.

**-i**, **--iterations**  
An iteration count.

**-o**, **--out**  
The output file, in place of standard output.

**--in**  
The input key file, for **key public** and **key show**, in place of
standard input.

**-h**, **--help**  
The help for a command, ending with the value syntax and the exit codes.

**-V**, **--version**  
The version.

## COMMANDS

## list

**scytale list** \[*family*\]

Prints the algorithm names each command takes, one per line, for a
script to check. With a *family* (one of **cipher**, **aead**, **hash**,
**xof**, **mac**, **key**) the names alone; without one, every name
prefixed by its family.

## random

**scytale random** \[*--binary*\] \[*-o file*\] *count*

*count* bytes from the system-seeded CTR_DRBG, as hex with a newline, or
raw with **--binary**.

## hash

**scytale hash** \[*-a algorithm*\] \[*-l length*\] \[*--function-name
value*\] \[*--customization value*\] \[*--binary*\] \[*file...*\]

A digest of each file, or of standard input, as hex followed by two
spaces and the file's name, in the layout of **sha256sum**(1); standard
input is named **-**. With **--binary** the raw digest alone.

**-a, --algorithm ***name*  
The hash; **sha256** by default. One of **sha1**, **sha224**,
**sha256**, **sha384**, **sha512**, **sha512-224**, **sha512-256**,
**sha3-224**, **sha3-256**, **sha3-384**, **sha3-512**, or an
extendable-output function, **shake128**, **shake256**, **cshake128** or
**cshake256**.

**-l, --length ***bytes*  
The output length, required for an extendable-output function and
refused otherwise.

**--function-name ***value***, --customization ***value*  
The cSHAKE function name and customization string, as **VALUES**; empty
without them.

## mac

**scytale mac** **-a ***algorithm* **-k ***key* \[*--verify tag*\] \[*-l
length*\] \[*--customization value*\] \[*--binary*\] \[*file*\]

A tag over the input, as hex, or raw with **--binary**. With
**--verify** the input is checked against *tag* instead: nothing is
printed, and the exit status says whether it matched.

**-a, --algorithm ***name*  
One of **hmac-***hash* for any hash above (**hmac-sha256**,
**hmac-sha3-512**, ...), **cmac-aes-128**, **cmac-aes-192**,
**cmac-aes-256**, **kmac128**, **kmac256** or **poly1305**.

**-k, --key ***value*  
The key. HMAC and KMAC take any length; CMAC takes the cipher's, and
Poly1305 32 bytes. A Poly1305 key is for one message only.

**-l, --length ***bytes*  
The tag length, for KMAC: 32 bytes for **kmac128** and 64 for
**kmac256** without it.

**--customization ***value*  
The KMAC customization string.

## aead encrypt, aead decrypt

**scytale aead** {**encrypt**\|**decrypt**} **-a ***algorithm* **-k
***key* **-n ***nonce* \[*--aad value*\] \[*--tag-length bytes*\] \[*-o
file*\] \[*file*\]

Authenticated encryption. Encryption writes the ciphertext and then the
tag; decryption reads ciphertext and tag as one input, checks the tag,
and writes the plaintext only if it checked. A message that fails leaves
standard output empty and exits with status 1. Encryption with GCM and
ChaCha20-Poly1305 streams; decryption reads the whole input first, since
plaintext handed out before the tag is checked is plaintext an attacker
chose.

**-a, --algorithm ***name*  
One of **aes-128-gcm**, **aes-192-gcm**, **aes-256-gcm**,
**aes-128-gcm-siv**, **aes-256-gcm-siv**, **aes-128-ccm**,
**aes-192-ccm**, **aes-256-ccm**, **aes-128-xpn**, **aes-192-xpn**,
**aes-256-xpn**, **chacha20-poly1305**.

**-k, --key ***value*  
The key, of the width the name says: 16, 24 or 32 bytes for AES, 32 for
ChaCha20-Poly1305.

**-n, --nonce ***value*  
The nonce. Twelve bytes, except that GCM takes any length, CCM takes 7
to 13, and XPN takes 24: the 12-byte salt followed by the 12-byte frame.
A nonce must never repeat under one key.

**--aad ***value*  
Additional data, authenticated but not encrypted; the same value must be
given to decrypt. Empty without it.

**--tag-length ***bytes*  
The tag length, 16 by default. GCM and XPN take 4 to 16, CCM an even
number from 4 to 16; GCM-SIV and ChaCha20-Poly1305 take 16 only.

## cipher encrypt, cipher decrypt

**scytale cipher** {**encrypt**\|**decrypt**} **-a ***algorithm* **-k
***key* \[*--iv value*\] \[*-n nonce*\] \[*--counter n*\] \[*--padding
pkcs7\|none*\] \[*--alphabet chars*\] \[*--tweak value*\] \[*-o file*\]
\[*file*\]

The unauthenticated modes. Nothing here checks that a message is what
was encrypted; a script that needs to know that wants **aead**. These
are for a protocol that brings its own MAC, a disk, a key to wrap, or a
format to preserve.

**-a, --algorithm ***name*  
**aes-***width***-***mode* for a *width* of 128, 192 or 256 and a *mode*
of **ecb**, **cbc**, **ctr**, **cfb1**, **cfb8**, **cfb128**, **ofb**,
**xts**, **kw** or **kwp**; **chacha20**; **ff1-aes-***width* or
**ff3-1-aes-***width* for the format-preserving modes.

**-k, --key ***value*  
The key, of the cipher's width. XTS takes two keys of that width, one
after the other, as **openssl**(1) does, and they must differ.

**--iv ***value*  
One block: the IV for CBC, CFB and OFB, the initial counter block for
CTR, the tweak for XTS. Required by those modes and refused by ECB, KW
and KWP.

**-n, --nonce ***value***, --counter ***n*  
The 12-byte nonce and the initial block counter (0 without it) for
ChaCha20, which encrypts and decrypts with the one operation.

**--padding ***pkcs7***\|***none*  
For ECB, CBC and CFB128, which take whole blocks. PKCS#7 padding is
added on encryption and removed on decryption unless **none** is given,
in which case an input that is not whole blocks is refused. PKCS#7 is
what **openssl enc** and CMS use. Padding that does not check on
decryption exits with status 1 and prints nothing; a script must not
report that difference to anyone who can submit ciphertexts.

**--alphabet ***chars***, --tweak ***value*  
For FF1 and FF3-1, which read and write lines of text in the alphabet,
one message per line. The alphabet is the string of characters that are
the numerals, in order; the decimal digits without it. The tweak is any
length for FF1 and exactly 7 bytes for FF3-1; empty for FF1 without it.
These modes are not constant time.

KW wraps a key of any whole number of 8-byte blocks, at least two; KWP
wraps any length. Both add 8 bytes. CTR, OFB and CFB take any length and
stream; CBC, CFB128 and ECB stream a block at a time; CFB1, XTS, KW and
KWP read the whole input.

## kdf hkdf

**scytale kdf hkdf** \[*-H hash*\] **--ikm ***value* \[*--salt value*\]
\[*--info value*...\] **-l ***bytes* \[*--binary*\] \[*-o file*\]

HKDF (RFC 5869): keys from keying material that is already unguessable,
such as a shared secret. The input keying material may not be given as
**str:**. **--info** may repeat; the values are concatenated in order.
Output as hex, or raw with **--binary**.

## kdf pbkdf2

**scytale kdf pbkdf2** \[*-H hash*\] **--password ***value* **--salt
***value* **-i ***iterations* **-l ***bytes* \[*--binary*\] \[*-o
file*\]

PBKDF2 (RFC 8018): a key from a password, which is guessable, at a cost
per guess set by the iteration count. The password and salt may be given
as **str:**.

## key generate

**scytale key generate** **-a ***algorithm* \[*-o file*\]

A new private key, as a PEM **PRIVATE KEY** block (PKCS#8), to standard
output or to *file*, created readable by its owner alone. The algorithm
is one of **ed25519**, **x25519**, **ecdsa-p256**, **ecdsa-p384**,
**ecdh-p256**, **ecdh-p384**, **rsa-***bits* for any *bits* from 1024 to
8192, **ml-kem-512**, **ml-kem-768**, **ml-kem-1024**, **ml-dsa-44**,
**ml-dsa-65**, **ml-dsa-87**, or **slh-dsa-***hash***-***size***s** and
**slh-dsa-***hash***-***size***f** for a *hash* of **sha2** or **shake**
and a *size* of 128, 192 or 256. Keys on P-256 and P-384 serve both
ECDSA and ECDH; an RSA key serves both signatures and encryption.

## key public

**scytale key public** \[*--in file*\] \[*-o file*\]

The public half of a private key, as a PEM **PUBLIC KEY** block.

## key show

**scytale key show** \[*--in file*\]

Prints what a key file holds: its algorithm, which half it is, and for
RSA the modulus length.

Every command that takes a key file reads PEM: the **PRIVATE KEY** and
**PUBLIC KEY** blocks that **openssl**(1) and everything else write, and
the bare **RSA PRIVATE KEY**, **RSA PUBLIC KEY** and **EC PRIVATE KEY**
forms as well. The algorithm is read out of the file, so it is never
named on the command line.

## sig sign

**scytale sig sign** **-k ***private* \[*-H hash*\] \[*--context
value*\] \[*--rsa-scheme pss\|pkcs1*\] \[*--raw*\] \[*--hex*\] \[*-o
file*\] \[*file*\]

Signs the input with the private key in *private*, writing the signature
raw, or as hex with **--hex**.

## sig verify

**scytale sig verify** **-p ***public* **-s ***signature* \[*-H hash*\]
\[*--context value*\] \[*--rsa-scheme pss\|pkcs1*\] \[*--raw*\]
\[*file*\]

Checks *signature* (a value, as **VALUES**) over the input under the
public key in *public*. Nothing is printed; the exit status is 0 if it
verified and 1 if not. A private key file is refused here; **key
public** makes the public one.

**-H, --hash ***name*  
The hash for ECDSA and RSA, **sha256** by default; Ed25519, ML-DSA and
SLH-DSA hash internally and ignore it.

**--context ***value*  
The context string for Ed25519 (which then signs in the Ed25519ctx
form), ML-DSA and SLH-DSA; up to 255 bytes. Empty without it, which for
Ed25519 is the plain form.

**--rsa-scheme ***pss***\|***pkcs1*  
RSASSA-PSS, salted with a hash's worth of random bytes, or the
deterministic RSASSA-PKCS1-v1_5; **pss** by default.

**--raw**  
An ECDSA signature as the fixed-width *r* followed by *s*, rather than
the DER SEQUENCE that **openssl dgst** writes. Ed25519, ML-DSA and
SLH-DSA signatures are always the fixed-width bytes their standards
define, and RSA signatures the modulus length.

## kex agree

**scytale kex agree** **-k ***private* **-p ***peer* \[*--hex*\] \[*-o
file*\]

The shared secret between the private key in *private* and the peer's
public key in *peer*, which must be on the same curve: X25519, P-256 or
P-384. Raw bytes, or hex with **--hex**. A shared secret is keying
material, not a key; derive keys from it with **kdf hkdf**.

## kem encapsulate

**scytale kem encapsulate** **-p ***public* **--secret-out ***file*
\[*--hex*\] \[*-o file*\]

A ciphertext for the ML-KEM public key in *public*, to standard output
or **-o**, and the shared secret it carries to *file*, created readable
by its owner alone. The peer recovers the secret from the ciphertext
with the private key.

## kem decapsulate

**scytale kem decapsulate** **-k ***private* \[*--hex*\] \[*-o file*\]
\[*file*\]

The shared secret an ML-KEM ciphertext carries. A ciphertext that was
not made for the key yields a secret that matches nothing, rather than
an error, as FIPS 203 requires.

## pke encrypt, pke decrypt

**scytale pke** {**encrypt**\|**decrypt**} {**-p public**\|**-k
private**} \[*-H hash*\] \[*--label value*\] \[*-o file*\] \[*file*\]

RSA-OAEP: a short message, at most the modulus length less twice the
hash length less two bytes, under an RSA public key. The hash is
**sha256** by default, the label empty; both must match to decrypt. A
ciphertext that does not decrypt exits with status 1 and says nothing
more.

## ALGORITHM NAMES

**scytale list** prints every name. Names are lower case with hyphens,
and name the whole construction, key width included: **aes-256-gcm**,
**hmac-sha3-256**, **ml-dsa-65**. A key of another width than the name
says is refused rather than taken as a hint.

## EXIT STATUS

**0**  
Success, including a verification that passed.

**1**  
A tag, signature or padding did not verify: the message is not what was
made under this key.

**2**  
The request could not be carried out as asked: an unknown name, an
option the algorithm does not take, a value in the wrong form, a key of
the wrong length, a file that is not a key.

**3**  
Anything else: a file that would not open, a generator that would not
seed.

Errors go to standard error as **scytale:** followed by the message, and
never contain key material.

## EXAMPLES

Encrypt a file to a key held in a file, with a header authenticated
alongside it, and decrypt it again:

    scytale random 32 --binary -o session.key
    scytale random 12 > nonce.hex
    scytale aead encrypt -a aes-256-gcm -k file:session.key \
        -n hex:$(cat nonce.hex) --aad str:v1 report.pdf -o report.sealed
    scytale aead decrypt -a aes-256-gcm -k file:session.key \
        -n hex:$(cat nonce.hex) --aad str:v1 report.sealed -o report.pdf

Sign a release with a post-quantum key and check the signature:

    scytale key generate -a ml-dsa-65 -o release.pem
    scytale key public --in release.pem -o release.pub
    scytale sig sign -k release.pem release.tar -o release.sig
    scytale sig verify -p release.pub -s file:release.sig release.tar

Agree a key with a peer and derive session keys from it:

    scytale key generate -a x25519 -o me.pem
    scytale key public --in me.pem -o me.pub
    scytale kex agree -k me.pem -p peer.pub -o shared.bin
    scytale kdf hkdf --ikm file:shared.bin --salt str:session-1 \
        --info str:encrypt --length 32

Read a key from a descriptor rather than the command line:

    scytale mac -a hmac-sha256 -k fd:3 message.txt 3< mac.key

Decrypt what **openssl enc** encrypted:

    openssl enc -aes-128-cbc -K $KEY -iv $IV < plain > cipher
    scytale cipher decrypt -a aes-128-cbc -k hex:$KEY --iv hex:$IV < cipher

## SEE ALSO

**openssl**(1), **sha256sum**(1).

The library's documentation, at https://docs.rs/scytale, describes each
algorithm, its limits and its security properties; the tool adds nothing
to them.

## AUTHOR

Michael Paddon.
