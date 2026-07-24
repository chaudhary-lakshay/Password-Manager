# Password Manager (Educational)

> **⚠️ Educational project — not a real password manager.** This is a small teaching example of the Java AES API, kept deliberately tiny so it can be read in one sitting. It contains known security flaws, documented below on purpose. **Do not use it to store real passwords** — use an established manager like Bitwarden or KeePassXC.

## What it does

Console app: add site/password pairs, retrieve them. Passwords are AES-encrypted and held in memory while the program runs.

## Known flaws (these are the lesson)

| Flaw | Why it's a problem | Production-grade fix |
|---|---|---|
| ~~Hardcoded key in source code~~ **Fixed** | Anyone with the code can decrypt everything | Key is now derived from a master password via PBKDF2-HMAC-SHA256 with a random salt — see [`CryptoUtil`](src/PasswordManager/CryptoUtil.java) |
| ~~`Cipher.getInstance("AES")` defaults to ECB mode~~ **Fixed** | ECB leaks patterns — identical plaintexts produce identical ciphertexts | Now uses `AES/GCM/NoPadding` with a random IV per entry — see [`CryptoUtil`](src/PasswordManager/CryptoUtil.java) |
| ~~No salt or IV~~ **Fixed** | Same input always encrypts to the same output | Random salt (key derivation) and random IV (per encryption) are now generated and stored alongside the ciphertext — see [`CryptoUtil`](src/PasswordManager/CryptoUtil.java) |
| ~~In-memory `HashMap` only~~ **Fixed** | Nothing is saved — all entries are lost when the program exits | Entries now persist to a `Properties` vault file with the PBKDF2 salt in its header — see [`PasswordManager`](src/PasswordManager/PasswordManager.java) |
| ~~No master-password verification~~ **Fixed** | Loading a vault with a mistyped password derived a wrong key silently, and the next added entry rewrote the file with rows under two different keys | A verifier blob is stored in the vault header; on unlock it is decrypted and GCM's authentication tag check rejects a wrong password — see [`CryptoUtil.verify`](src/PasswordManager/CryptoUtil.java) |
| ~~Vault file written with default permissions~~ **Fixed** | Any other user on the machine could read the vault. The contents are encrypted, but that is not a reason to leave it world-readable | Vault files are created with owner-only permissions (`0600`) on POSIX filesystems, with a best-effort owner read/write fallback on non-POSIX filesystems such as Windows |

Want to fix one? See the open [good first issues](https://github.com/chaudhary-lakshay/Password-Manager/issues).

## Run it

```bash
git clone https://github.com/chaudhary-lakshay/Password-Manager.git
cd Password-Manager/src
javac PasswordManager/PasswordManager.java
java PasswordManager.PasswordManager
```

## More of my work

This repo is a learning artifact. For production-grade projects, see:

- [CarCatalog](https://github.com/chaudhary-lakshay/CarCatalog) — Spring Boot vehicle catalog & rental API: JWT auth, Flyway migrations, Stripe PaymentIntents
- [VitaLink](https://github.com/chaudhary-lakshay/vitalink) — remote patient monitoring backend: HL7 ADT, MQTT device ingest, live ECG streaming (TimescaleDB + STOMP), FHIR R4
- [VitaLink Android](https://github.com/chaudhary-lakshay/vitalink-android) — Jetpack Compose clinician app for the above

## License

MIT

## Contributing

Issues here are **first come, first merged**. Assignment is not reservation: if an issue is assigned to someone and you open a working PR first, yours is the one that gets merged. Commenting "I'd like to work on this" is welcome and I'll assign it, but it does not hold the issue against a PR that arrives sooner. If you want an issue, the reliable way to get it is to open the PR.
