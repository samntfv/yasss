# YASSS

YASSS (Yet Another Shamir's Secret Sharing) is a command-line tool
that encrypts a file with AES-256-GCM and splits the
encryption key into Shamir secret-sharing shares over GF(2^16),
supporting up to 65,535 shares. Each share is then digitally signed using Ed25519 so
that forged or tampered shares can be detected and rejected during
reconstruction.

Despite the number of Shamir's secret shsaring implementations out there, this one differs
in that it doesn't implement the scheme as a plug-in module, but it provides
an opinionated end-to-end workflow and is intended mainly as a CLI tool.

## How it works

### Encryption (`encrypt`)

1. A fresh random AES-256 key and a 12-byte GCM nonce are generated
   separately. The nonce is generated first so it can be included in the
   authenticated header (see step 4).
2. A one-time **Ed25519 keypair** is generated. Its public key is embedded
   in the encrypted file's header; the private key is
   used only in memory to sign the shares below and is never written to
   disk.
3. The header (magic, version, public key, threshold, total shares, nonce)
   is serialised and used as **GCM Additional Authenticated Data (AAD)**,
   binding the ciphertext to this exact header. Any modification to the
   public key, threshold, or nonce causes decryption to fail with an
   authentication error.
4. The input file is encrypted with **AES-256-GCM** using the key, nonce,
   and header AAD.
5. The 32-byte AES key is treated as 16 elements of **GF(2^16)** and split
   into `N` shares using **Shamir's Secret Sharing**, with a configurable
   threshold `T`. The leading polynomial coefficient for each element is guaranteed
   non-zero, preserving the strict degree-(T-1) property required for the
   threshold guarantee.
6. Each share is **signed with the Ed25519 private key** and written
   atomically to its own file in the shares directory.

### Reconstruction (`reconstruct`)

1. The encrypted file's header is read, giving the embedded Ed25519 public
   key, threshold, nonce, and the raw header bytes (which are re-used as
   the GCM AAD during decryption).
2. Every file in the shares directory is parsed and its **signature is
   verified** against the embedded public key. Duplicate share indices are also
   detected and counted separately.
3. **Strict mode (`-strict`, on by default):** if *any* share fails
   signature verification reconstruction is aborted immediately, even if 
   enough genuine shares are present to meet the threshold on their own. 
   A bad share is treated as a sign that something in the environment is wrong.
   Pass `-strict=false` to allow reconstruction to proceed as long as enough valid
   shares remain.
4. If at least `T` valid, non-duplicate shares remain (and strict mode
   didn't already abort), the AES key is reconstructed via Lagrange
   interpolation over GF(2^16).
5. The file is decrypted with AES-256-GCM. The same header bytes are
   passed as AAD, so any modification to the header or ciphertext will cause 
   GCM authentication to fail with an explicit error.

### Validation (`validate`)

`validate` checks the Ed25519 signature of every share file in a directory
against the public key embedded in the encrypted file's header, without
reconstructing the key or touching the ciphertext at all. It's a
lightweight way to audit a share (or a whole set of them) -- for example
letting a single custodian confirm their own share is genuine and
untampered, without needing a quorum of shares or the encrypted payload's
contents. It reports how many shares are valid, how many failed
verification, how many were unreadable, and how many were duplicates, and
exits with an error if any share failed verification.

## Why GF(2^16)?

Each AES-256 key is 32 bytes = 16 × 2byte elements. Representing each
element as a member of GF(2^16) (rather than the more common GF(2^8) used
in classic SSS implementations) means **share indices can range from 1 to
65,535**, supporting very large numbers of shares, while still requiring
only 16 polynomial evaluations per share.

The field is implemented using the irreducible polynomial
`x^16 + x^12 + x^3 + x + 1` (0x1100B).

The core multiplication function (`gfMul`) uses branchless bitmasking
so the execution path does not vary with the values being multiplied. 
This eliminates timing side-channels on key material during Lagrange interpolation.
(Though this should hardly be a concern given this is intended as a CLI tool, I still
felt it would be a nice to have if you ever decide to run it or part of it as a service)

## Why "wasting" more than half the size of the share on signature?

Using a **signature scheme** means only the party who ran `encrypt` (and
held the one-time private key, momentarily, in memory) could have produced
valid signatures. The public key travels with the encrypted file header, while forging a
share that passes verification would require the discarded private key.
This means share custodians can independently verifyany share is genuine
without needing the other shares, but just the encrypted file header.

## Building

Requires Go 1.22+.

```sh
cd yasss
go build -o yasss .
```

## Running the tests

```sh
go test ./...
```

The test suite includes:
- Exhaustive GF(2^16) field-axiom checks (`gf65536_test.go`)
- Shamir split/combine round-trip and threshold-security checks (`shamir_test.go`)
- Full end-to-end encrypt/reconstruct pipeline tests (`integration_test.go`)

## Usage

### Encrypt a file

```sh
./yasss encrypt \
  -in secret.pdf \
  -out secret.pdf.enc \
  -sharesdir ./shares \
  -shares 5 \
  -threshold 3
```

This produces:
- `secret.pdf.enc` -> the encrypted file (safe to store/transmit; useless
  without enough shares).
- `./shares/share-00001.shr` ... `./shares/share-00005.shr` -> five key
  shares. Distribute these to different custodians/locations. Any 3 of
  them, together with `secret.pdf.enc`, can recover the original file.

Flags:

| Flag          | Default | Description                                              |
|---------------|---------|----------------------------------------------------------|
| `-in`         | //      | Path to the file to encrypt (required)                   |
| `-out`        | //      | Path to write the encrypted file (required)              |
| `-sharesdir`  | //      | Directory to write key shares into (required, created)   |
| `-shares`     | 5       | Total number of shares to generate (1–65535)             |
| `-threshold`  | 3       | Number of shares required to reconstruct (≥2, ≤ `-shares`)|

### Reconstruct the original file

```sh
./yasss reconstruct \
  -in secret.pdf.enc \
  -sharesdir ./recovered-shares \
  -out secret.pdf
```

Put **any subset of the share files** (at least `threshold` of them, valid
and unmodified) into `./recovered-shares`. The tool will:

- Verify each share's signature
- Reconstruct the AES key
- Decrypt `secret.pdf.enc` into `secret.pdf`, failing with an explicit
  authentication error if the encrypted file's header has been tampered
  with.
 
Flags:

| Flag          | Default | Description                                        |
|---------------|---------|-----------------------------------------------------|
| `-in`         | //      | Path to the encrypted file (required)               |
| `-sharesdir`  | //      | Directory containing key share files (required)     |
| `-out`        | //      | Path to write the decrypted (original) file (required)|
| `-strict`     | `true`  | Abort if any share fails signature verification, even if enough genuine shares remain. Set to `false` to discard invalid shares and proceed as long as enough valid ones are left. |

### Validate a set of shares

```sh
./yasss validate \
  -in secret.pdf.enc \
  -sharesdir ./some-custodians-shares
```

This reads and signature-checks every file in `./some-custodians-shares`
against the public key embedded in `secret.pdf.enc`, prints a summary, and
exits non-zero if any share failed verification.

Flags:

| Flag          | Default | Description                                                         |
|---------------|---------|-----------------------------------------------------------------------|
| `-in`         | //      | Path to the encrypted file, used as the trust anchor for the shares' public key (required) |
| `-sharesdir`  | //      | Directory containing key share files to validate (required)         |

## File formats

### Encrypted file (`*.enc`)

| Offset | Size | Field                                          |
|--------|------|------------------------------------------------|
| 0      | 4    | Magic `"SSE1"`                                 |
| 4      | 1    | Version (currently `1`)                        |
| 5      | 32   | Ed25519 public key (trust anchor for shares)   |
| 37     | 2    | Threshold (big-endian uint16)                  |
| 39     | 2    | Total shares generated (big-endian uint16)     |
| 41     | 12   | AES-GCM nonce                                  |
| 53     | …    | AES-256-GCM ciphertext (includes 16-byte tag)  |

The entire 53-byte header (offsets 0–52) is authenticated as GCM Additional
Authenticated Data (AAD). Any modification to any header field 
will cause decryption to fail.

### Share file (`*.shr`)

| Offset | Size | Field                                                    |
|--------|------|----------------------------------------------------------|
| 0      | 4    | Magic `"SSH1"`                                           |
| 4      | 2    | Share index / x-coordinate (big-endian uint16, 1–65535) |
| 6      | 32   | 16 GF(2^16) elements (big-endian uint16 each); the actual share of the AES-256 key |
| 38     | 64   | Ed25519 signature over bytes 0–37                        |

## Disclaimer

While great care has been taken to make this tool secure, using standard primitives (AES-256-GCM, Ed25519, crypto/rand),
this tool has not been independently audited and it is provided as-is without warranties of any kind.
The developer is not a professional cryptographer and will not assume any responsibility for damage of any kind
resulting from the use of the tool.
You are responsible for judging wether this tool meets the security requirements of your use case.
