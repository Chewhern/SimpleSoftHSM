# SimpleSoftHSM
This library uses libsodium's guarded heap allocation, ED25519/ED448 challenge and respond as authentication and experimental domain separation encryption/decryption to mimic HSM in a secure manner.

Steps:
1. Create an ED448 keypair or ED25519 keypair via bouncycastle or libsodium.
2. Load ED448 or ED25519 public key into the library. (Can't replace the existed public key unless the time is more than 30 minutes [Customizable])
3. Request challenge from initialization.
4. Sign the challenge via ED448 or ED25519. (The signed challenge needs to be in the form of Signature+Challenge)
5. Send signed challenge to authorize function. (Keep in mind, the signed challenge or valid authorization period lasts for no more than 8 minutes [Customizable])
6. Create another ED448 keypair or ED25519 keypair via bouncycastle or libsodium.
7. Load another ED448 or ED25519 keypair signing private key into the library. (Copies the private key and forcefully apply permission on it for details refer to libsodium's guarded heap allocation and permission) or load another ED448 or ED25519 keypair signature verification public key into the library [A must do from 0.0.9 and onwards]. 
8. Load any randomly generated encryption/secret key into the library. (Similar description as stated in 6th)
9. Load any randomly generated MAC key into library. (Similar description as stated in 6th)
10. Encrypt or decrypt data. 
11. Clear the secret keys or private key.

**Starting from version 0.0.6, the experimental domain separation within secret key encryption/decryption now has basic key commitment via digital signature signing and verification.**

**As key commitment was involved in symmetric encryption, the only uniqueness in this software based HSM may be its secretless based approach in authentication. The current unclear use case may be limited to only secure communication between 2 parties when key commitment was not an issue from the sender side.**
