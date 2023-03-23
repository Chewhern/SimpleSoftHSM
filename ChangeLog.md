Version 0.0.1 (Unlisted)
- Classes and some methods should be static but I made some mistakes.

Version 0.0.2 (Unlisted)
- Classes and some methods are now static. 
- Wrong logical comparison in loading public key method.

Version 0.0.3
- Implement correct logical comparison in loading public key method.

Version 0.0.4 (Unlisted)
- Implement simple domain separation to encrypt/decrypt data and compute MAC
- Implement basic key commiting along with domain separation
- Added private key and public key signing/verification

Version 0.0.5 (Unlisted)
- Fixed partial bugs

Version 0.0.6
- Fixed bugs

Version 0.0.7 (Unlisted)
- Allowing replacing duration of the public key to be customized
- Allowing authorization duration to be customized
- Some bugs in implementing the customization
- After 1st initializing, the 2nd initializing or 1st replacing of public key now clear and deallocate the pointer memory of secret keys and private keys.

Version 0.0.8
- Fixed bugs

Version 0.0.9
- Changed **PrivateKeySigningOperation** into **DigitalSignatureOperation**.
- The input of public key in **DigitalSignatureOperation** is now compulsory from users/developers. 
