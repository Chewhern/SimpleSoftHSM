# SimpleSoftHSM
This library uses libsodium's guarded heap allocation, ED25519/ED448 challenge and respond as authentication and experimental domain separation encryption/decryption to mimic HSM in a secure manner.

Steps:
1. Create an ED448 keypair or ED25519 keypair via bouncycastle or libsodium.
2. Load ED448 or ED25519 public key into the library. (Can't replace the existed public key unless the time is more than 30 minutes)
3. Request challenge from initialization.
4. Sign the challenge via ED448 or ED25519. (The signed challenge needs to be in the form of Signature+Challenge)
5. Send signed challenge to authorize function. (Keep in mind, the signed challenge or valid authorization period lasts for no more than 8 minutes)
6. Load ED448 or ED25519 signing private key into the library. (Copies the private key and forcefully apply permission on it for details refer to libsodium's guarded heap allocation and permission)
7. Load any randomly generated encryption/secret key into the library.
8. Load any randomly generated MAC key into library.
9. Encrypt or decrypt data. 
10. Clear the secret key.

**Starting from version 0.0.6, the experimental domain separation within secret key encryption/decryption now has basic key commitment via digital signature signing and verification.**
