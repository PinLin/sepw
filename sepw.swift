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
      sepw ls            List entry names
      sepw rm <name>     Remove an entry

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
