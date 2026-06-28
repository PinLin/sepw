import Foundation
import CryptoKit
import Security
import LocalAuthentication

// === Configuration ===
let storeDir = ("~/.sepw" as NSString).expandingTildeInPath
let keyBlobPath = storeDir + "/key.blob"   // SE key wrapped by the chip (the key itself never leaves it)
let keyPubPath = storeDir + "/key.pub"     // Matching public key (not secret; used to encrypt, no auth)
let hkdfSalt = "sepw.v1".data(using: .utf8)!

func die(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

// Status messages go to stderr so stdout carries only `get`/`ls` output (pipe-friendly).
func info(_ msg: String) {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
}

func ensureStoreDir() {
    try? FileManager.default.createDirectory(
        atPath: storeDir, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
}

func validateName(_ name: String) {
    let ok = name.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil
    if !ok || name == "." || name == ".." || name == "key" {
        die("Name may only contain letters, digits and . _ - , and cannot be . / .. / key")
    }
}

func cipherPath(_ name: String) -> String { storeDir + "/" + name + ".bin" }

func writeFile(_ path: String, _ data: Data) {
    do {
        try data.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    } catch { die("Failed to write \(path): \(error)") }
}

// === Secure Enclave key ===
// Create the key only if absent; otherwise return immediately. Creation needs no auth.
func ensureKey() {
    if FileManager.default.fileExists(atPath: keyBlobPath) { return }
    guard SecureEnclave.isAvailable else { die("This Mac has no Secure Enclave; cannot continue.") }
    guard let ac = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .userPresence], nil) else {
        die("Failed to create access control")
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        ensureStoreDir()
        writeFile(keyBlobPath, key.dataRepresentation)
        writeFile(keyPubPath, key.publicKey.rawRepresentation)
        info("Created a key in this Mac's Secure Enclave.")
    } catch let error as NSError {
        // -25308 errSecInteractionNotAllowed: the Secure Enclave could not satisfy
        // the user-presence requirement because no GUI auth UI is available.
        if error.code == errSecInteractionNotAllowed {
            die("""
            Failed to create Secure Enclave key: user interaction is not allowed.
            The key must be created from a logged-in desktop session, not over SSH
            or a locked screen, and this Mac must have a login password set
            (Touch ID recommended). Unlock the Mac, open Terminal there, and rerun.
            Underlying error: \(error)
            """)
        }
        die("Failed to create Secure Enclave key: \(error)")
    }
}

// Explicit `init`: create the key (or report it already exists). Useful for setting
// up the key while the Mac is unlocked, before any `add`.
func initKey() {
    if FileManager.default.fileExists(atPath: keyBlobPath) {
        info("Already initialized: a Secure Enclave key exists at \(keyBlobPath).")
        return
    }
    ensureKey()
}

func loadPublicKey() -> P256.KeyAgreement.PublicKey {
    guard let raw = FileManager.default.contents(atPath: keyPubPath),
          let pub = try? P256.KeyAgreement.PublicKey(rawRepresentation: raw) else {
        die("Public key missing or corrupt")
    }
    return pub
}

// Rebuild the SE private key (no auth here); Touch ID is triggered later, during ECDH.
func loadPrivateKey(prompt: String) -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    guard let blob = FileManager.default.contents(atPath: keyBlobPath) else {
        die("Decryption failed")
    }
    let ctx = LAContext()
    ctx.localizedReason = prompt
    do {
        return try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: ctx)
    } catch {
        die("Failed to load Secure Enclave key: \(error)")
    }
}

// === ECIES (P-256 ECDH + HKDF-SHA256 + AES-GCM) ===
func encryptToSE(_ plaintext: Data) -> Data {
    let pub = loadPublicKey()
    let eph = P256.KeyAgreement.PrivateKey()
    guard let shared = try? eph.sharedSecretFromKeyAgreement(with: pub) else { die("Key agreement failed") }
    let ephPub = eph.publicKey.rawRepresentation  // 64 bytes
    let sym = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: hkdfSalt, sharedInfo: ephPub, outputByteCount: 32)
    guard let sealed = try? AES.GCM.seal(plaintext, using: sym), let combined = sealed.combined else {
        die("Encryption failed")
    }
    return ephPub + combined
}

func decryptWithSE(_ data: Data, prompt: String) -> Data {
    guard data.count > 64,
          let ephKey = try? P256.KeyAgreement.PublicKey(rawRepresentation: data.prefix(64)) else {
        die("Malformed ciphertext")
    }
    let priv = loadPrivateKey(prompt: prompt)
    guard let shared = try? priv.sharedSecretFromKeyAgreement(with: ephKey) else {
        die("Decryption failed (authentication may have been cancelled)")
    }
    let sym = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: hkdfSalt, sharedInfo: Data(data.prefix(64)), outputByteCount: 32)
    guard let box = try? AES.GCM.SealedBox(combined: data.dropFirst(64)),
          let pt = try? AES.GCM.open(box, using: sym) else {
        die("Decryption failed (corrupt data or wrong key)")
    }
    return pt
}

// === TOTP (RFC 6238 / RFC 4226) ===
enum TOTPAlgorithm { case sha1, sha256, sha512 }

func parseAlgorithm(_ s: String) -> TOTPAlgorithm {
    switch s.uppercased() {
    case "SHA1": return .sha1
    case "SHA256": return .sha256
    case "SHA512": return .sha512
    default: die("Unsupported algorithm: \(s) (use SHA1, SHA256 or SHA512)")
    }
}

// RFC 4648 base32 decode. Case-insensitive; spaces, tabs, newlines and '='
// padding are ignored. Returns nil on any non-base32 character.
func base32Decode(_ input: String) -> Data? {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    var map = [Character: Int]()
    for (i, c) in alphabet.enumerated() { map[c] = i }
    var value = 0, bits = 0
    var out = [UInt8]()
    for c in input.uppercased() {
        if c == " " || c == "\t" || c == "\n" || c == "\r" || c == "=" { continue }
        guard let v = map[c] else { return nil }
        value = (value << 5) | v
        bits += 5
        if bits >= 8 {
            bits -= 8
            out.append(UInt8((value >> bits) & 0xff))
        }
    }
    return out.isEmpty ? nil : Data(out)
}

func generateTOTP(secret: Data, time: UInt64, period: UInt64, digits: Int, algorithm: TOTPAlgorithm) -> String {
    let counter = (time / period).bigEndian
    let message = withUnsafeBytes(of: counter) { Data($0) }   // 8-byte big-endian counter
    let key = SymmetricKey(data: secret)
    let mac: Data
    switch algorithm {
    case .sha1:   mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
    case .sha256: mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
    case .sha512: mac = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
    }
    let offset = Int(mac[mac.count - 1] & 0x0f)               // dynamic truncation
    let binary = (UInt32(mac[offset] & 0x7f) << 24)
               | (UInt32(mac[offset + 1]) << 16)
               | (UInt32(mac[offset + 2]) << 8)
               | UInt32(mac[offset + 3])
    var mod: UInt32 = 1
    for _ in 0..<digits { mod *= 10 }
    return String(format: "%0\(digits)d", binary % mod)
}

// Parse the parameters we care about from an otpauth://totp/...?secret=...&... URI.
func parseOtpauth(_ uri: String) -> (secret: String, digits: Int?, period: UInt64?, algorithm: TOTPAlgorithm?)? {
    guard let items = URLComponents(string: uri)?.queryItems else { return nil }
    var secret: String? = nil, digits: Int? = nil, period: UInt64? = nil, algorithm: TOTPAlgorithm? = nil
    for item in items {
        guard let v = item.value else { continue }
        switch item.name.lowercased() {
        case "secret":    secret = v
        case "digits":    digits = Int(v)
        case "period":    period = UInt64(v)
        case "algorithm": algorithm = parseAlgorithm(v)
        default: break
        }
    }
    guard let s = secret else { return nil }
    return (s, digits, period, algorithm)
}

// Resolve a stored value (bare base32 secret or otpauth:// URI) plus optional CLI
// overrides into a TOTP code. Precedence: CLI flag > otpauth URI > default.
func totpCode(from stored: String, at unixTime: UInt64,
              cliDigits: Int?, cliPeriod: UInt64?, cliAlgorithm: TOTPAlgorithm?) -> String {
    var secretB32 = stored.trimmingCharacters(in: .whitespacesAndNewlines)
    var uriDigits: Int? = nil, uriPeriod: UInt64? = nil, uriAlgorithm: TOTPAlgorithm? = nil
    if secretB32.lowercased().hasPrefix("otpauth://") {
        guard let p = parseOtpauth(secretB32) else { die("Malformed otpauth:// URI (no secret found)") }
        secretB32 = p.secret
        uriDigits = p.digits; uriPeriod = p.period; uriAlgorithm = p.algorithm
    }
    let digits = cliDigits ?? uriDigits ?? 6
    let period = cliPeriod ?? uriPeriod ?? 30
    let algorithm = cliAlgorithm ?? uriAlgorithm ?? .sha1
    guard digits >= 6 && digits <= 8 else { die("digits must be between 6 and 8") }
    guard period > 0 else { die("period must be a positive number of seconds") }
    guard !secretB32.isEmpty else { die("No TOTP secret found") }
    guard let key = base32Decode(secretB32) else { die("Secret is not valid base32") }
    return generateTOTP(secret: key, time: unixTime, period: period, digits: digits, algorithm: algorithm)
}

// Parse `--digits N`, `--period S`, `--algorithm X` from the trailing arguments.
func parseTotpFlags(_ rest: ArraySlice<String>) -> (digits: Int?, period: UInt64?, algorithm: TOTPAlgorithm?) {
    var digits: Int? = nil, period: UInt64? = nil, algorithm: TOTPAlgorithm? = nil
    var iter = Array(rest).makeIterator()
    while let tok = iter.next() {
        switch tok {
        case "--digits":
            guard let v = iter.next(), let n = Int(v) else { die("--digits requires a number") }
            digits = n
        case "--period":
            guard let v = iter.next(), let n = UInt64(v) else { die("--period requires a number") }
            period = n
        case "--algorithm":
            guard let v = iter.next() else { die("--algorithm requires a value") }
            algorithm = parseAlgorithm(v)
        default:
            die("Unknown option: \(tok)")
        }
    }
    return (digits, period, algorithm)
}

func totpItem(name: String, cliDigits: Int?, cliPeriod: UInt64?, cliAlgorithm: TOTPAlgorithm?) {
    validateName(name)
    guard let cipher = FileManager.default.contents(atPath: cipherPath(name)),
          FileManager.default.fileExists(atPath: keyBlobPath) else {
        die("Item not found: \(name)")
    }
    let stored = String(data: decryptWithSE(cipher, prompt: "Authenticate to generate TOTP for \"\(name)\""),
                        encoding: .utf8) ?? ""
    let now = UInt64(Date().timeIntervalSince1970)
    print(totpCode(from: stored, at: now,
                   cliDigits: cliDigits, cliPeriod: cliPeriod, cliAlgorithm: cliAlgorithm))
}

// Read with no echo when interactive; read stdin (stripping trailing newline) when piped.
func readSecretInput() -> String {
    if isatty(0) != 0 {
        guard let c = getpass("Enter the value to store (hidden): ") else { die("Failed to read input") }
        return String(cString: c)
    }
    var s = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? ""
    while s.hasSuffix("\n") || s.hasSuffix("\r") { s.removeLast() }
    return s
}

// === Items ===
func addItem(name: String) {
    validateName(name)
    ensureKey()   // implicit init
    let secret = readSecretInput()
    if secret.isEmpty { die("Empty input, aborted.") }
    ensureStoreDir()
    writeFile(cipherPath(name), encryptToSE(secret.data(using: .utf8)!))
    info("Stored: \(name)")
}

func getItem(name: String) {
    validateName(name)
    guard let cipher = FileManager.default.contents(atPath: cipherPath(name)),
          FileManager.default.fileExists(atPath: keyBlobPath) else {
        die("Item not found: \(name)")
    }
    print(String(data: decryptWithSE(cipher, prompt: "Authenticate to read \"\(name)\""), encoding: .utf8) ?? "")
}

func listItems() {
    guard let items = try? FileManager.default.contentsOfDirectory(atPath: storeDir) else { return }
    items.filter { $0.hasSuffix(".bin") }.map { String($0.dropLast(4)) }.sorted().forEach { print($0) }
}

func removeItem(name: String) {
    validateName(name)
    guard FileManager.default.fileExists(atPath: cipherPath(name)) else {
        die("Item not found: \(name)")
    }
    try? FileManager.default.removeItem(atPath: cipherPath(name))
    info("Removed: \(name)")
}

// asError: a misuse (unknown command / missing argument) prints to stderr and exits 1.
// Otherwise it's an explicit help request, printed to stdout with exit 0.
func usage(asError: Bool = true) -> Never {
    let text = """
    Usage:
      sepw init          Create the Secure Enclave key (run on an unlocked desktop)
      sepw add <name>    Add an entry (input hidden; key is created on first use)
      sepw get <name>    Decrypt and print (requires Touch ID or login password)
      sepw totp <name>   Generate a TOTP code from a stored secret (requires Touch ID)
      sepw ls            List entry names
      sepw rm <name>     Remove an entry

    Options for `totp` (override values from a stored otpauth:// URI):
      --digits N         Code length, 6-8 (default 6)
      --period S         Time step in seconds (default 30)
      --algorithm X      SHA1, SHA256 or SHA512 (default SHA1)

    Pipe-friendly:
      echo "$SECRET" | sepw add github-pw
      PASS=$(sepw get github-pw)
    """
    if asError { info(text); exit(1) } else { print(text); exit(0) }
}

// === Entry point ===
let args = CommandLine.arguments
guard args.count >= 2 else { usage(asError: false) }   // no args → show help, exit 0

switch args[1] {
case "init":
    initKey()
case "add":
    guard args.count >= 3 else { usage() }
    addItem(name: args[2])
case "get":
    guard args.count >= 3 else { usage() }
    getItem(name: args[2])
case "totp":
    guard args.count >= 3 else { usage() }
    let f = parseTotpFlags(args[3...])
    totpItem(name: args[2], cliDigits: f.digits, cliPeriod: f.period, cliAlgorithm: f.algorithm)
case "_totp":
    // Hidden test seam: compute a code straight from a base32 secret or otpauth://
    // URI at a fixed time, bypassing the Secure Enclave (which needs Touch ID and
    // can't run unattended). Used by test_totp.sh against RFC 6238 vectors.
    guard args.count >= 4, let t = UInt64(args[3]) else { usage() }
    let f = parseTotpFlags(args[4...])
    print(totpCode(from: args[2], at: t,
                   cliDigits: f.digits, cliPeriod: f.period, cliAlgorithm: f.algorithm))
case "ls":
    listItems()
case "rm":
    guard args.count >= 3 else { usage() }
    removeItem(name: args[2])
case "-h", "--help", "help":
    usage(asError: false)
default:
    usage()
}
