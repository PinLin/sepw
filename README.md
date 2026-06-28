# sepw

Keep passwords and other secrets in your Mac's Secure Enclave, and let scripts read them back behind a Touch ID prompt. No accounts, no cloud, no dependencies — just Apple's own frameworks and a single Swift file.

## Requirements

An Apple Silicon Mac and the Xcode command line tools (`swiftc`).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/PinLin/sepw/main/install.sh | bash
```

No root? Drop it in your home directory instead:

```bash
curl -fsSL https://raw.githubusercontent.com/PinLin/sepw/main/install.sh | PREFIX="$HOME/.local" bash
```

The installer builds from source — a Secure Enclave binary has to be compiled and signed on the machine it runs on.

## Usage

```bash
sepw init              # create the Secure Enclave key (optional; add does it too)
sepw add github-pw     # prompts for the value (hidden); creates the key the first time
sepw get github-pw     # prints it back after Touch ID (or your login password)
sepw totp github-2fa   # generate a TOTP code from a stored secret (after Touch ID)
sepw ls                # list entry names
sepw rm github-pw      # remove an entry
```

### TOTP (two-factor codes)

Store a TOTP secret like any other entry — either a bare base32 seed or the whole
`otpauth://` URI from a QR code — then ask for a code:

```bash
sepw add github-2fa            # paste the base32 seed or otpauth:// URI
sepw totp github-2fa           # 6-digit code, after Touch ID
sepw totp github-2fa --digits 8
```

The secret is decrypted inside the Secure Enclave and the code is computed in
process — only the digits reach stdout, never the seed. When the stored value is
an `otpauth://` URI, its `digits`, `period` and `algorithm` are honored; CLI flags
override them.

```
--digits N       Code length, 6-8 (default 6)
--period S       Time step in seconds (default 30)
--algorithm X    SHA1, SHA256 or SHA512 (default SHA1)
```

Creating the key requires an unlocked, logged-in desktop session and a login
password on the Mac (Touch ID recommended) — it can't be done over SSH or on a
locked screen. Running `sepw init` once at a real keyboard gets this out of the
way; after that, `add` and `get` behave as above. If you see
`Failed to create Secure Enclave key … unable to generate key`, that's the
machine refusing to mint a user-presence key in a headless or locked state.

It's built for pipes and command substitution: secrets go in on stdin, come out on stdout, and everything else stays on stderr.

```bash
echo "$TOKEN" | sepw add deploy-token
export GITHUB_TOKEN=$(sepw get deploy-token)
```

## How it works

`sepw` generates a P-256 key inside the Secure Enclave. The private key never leaves the chip — all that lands on disk is a chip-wrapped blob and the matching public key.

- **Writing** is offline and needs no auth: each secret is sealed to the public key with ECIES (ECDH → HKDF-SHA256 → AES-GCM).
- **Reading** runs the ECDH on the Enclave itself, and the key is created with `.userPresence`, so every read demands Touch ID — or your login password on a Mac without a sensor.

The symmetric key is re-derived for each operation and never stored.

## Limitations

- **Tied to one chip.** A stolen disk is useless, and a `key.blob` copied to another Mac won't decrypt. The flip side: secrets don't sync — every Mac gets its own key and its own entries.
- **Local only.** That Touch ID prompt is a GUI dialog, so `sepw get` can't run over SSH or in any headless session.
