using ASodium;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SimpleSoftHSM
{
    public static class SecretKeyOperation
    {
        private static IntPtr EncryptionKeyIntPtr;
        private static IntPtr MACKeyIntPtr;
        private static Boolean IsEncryptionKeyInitialized;
        private static Boolean IsMACKeyInitialized;
        private static Boolean HasSodiumInitialized;
        private static int Count;
        private static Boolean HasEKeyCleared;
        private static Boolean HasMACKeyCleared;

        public static void LoadSecretKey(Byte[] Key) 
        {
            if (Key == null || Key.Length==0) 
            {
                throw new ArgumentException("Error: Key can't be null or empty");
            }
            if (Key.Length != 32) 
            {
                throw new ArgumentException("Error: Key length must be 32 bytes or 256 bits in length");
            }
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else 
            {
                Boolean IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Boolean IsZero = false;
                    if (HasSodiumInitialized == false)
                    {
                        SodiumInit.Init();
                        HasSodiumInitialized = true;
                    }
                    if (IsEncryptionKeyInitialized == true && HasEKeyCleared==false)
                    {
                        SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(EncryptionKeyIntPtr);
                    }
                    else
                    {
                        EncryptionKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                        Count = 0;
                        while (IsZero == true && Count < 10)
                        {
                            EncryptionKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                            Count += 1;
                        }
                        if (Count == 10 && IsZero == true)
                        {
                            throw new SystemException("Error: Failed to create a libsodium storage pointer");
                        }
                    }
                    Marshal.Copy(Key, 0, EncryptionKeyIntPtr, 32);
                    IsEncryptionKeyInitialized = true;
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else 
                {
                    throw new ArgumentException("Error: Access Denied");
                }
                HasEKeyCleared = false;
            }
        }

        public static void LoadMACKey(Byte[] MACKey)
        {
            if (MACKey == null || MACKey.Length == 0)
            {
                throw new ArgumentException("Error: MAC Key can't be null or empty");
            }
            if (MACKey.Length != 32)
            {
                throw new ArgumentException("Error: MAC Key length must be 32 bytes or 256 bits in length");
            }
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                Boolean IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Boolean IsZero = false;
                    if (HasSodiumInitialized == false)
                    {
                        SodiumInit.Init();
                        HasSodiumInitialized = true;
                    }
                    if (IsMACKeyInitialized == true && HasMACKeyCleared == false)
                    {
                        SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(MACKeyIntPtr);
                    }
                    else
                    {
                        MACKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                        Count = 0;
                        while (IsZero == true && Count < 10)
                        {
                            MACKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                            Count += 1;
                        }
                        if (Count == 10 && IsZero == true) 
                        {
                            throw new SystemException("Error: Failed to create a libsodium storage pointer");
                        }
                    }
                    Marshal.Copy(MACKey, 0, MACKeyIntPtr, 32);
                    IsMACKeyInitialized = true;
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    SodiumSecureMemory.SecureClearBytes(MACKey);
                }
                else
                {
                    throw new ArgumentException("Error: Access Denied");
                }
                HasMACKeyCleared = false;
            }
        }

        public static Boolean GetIsEKeyInitialized() 
        {
            return IsEncryptionKeyInitialized;
        }

        public static Boolean GetIsMACKeyInitialized() 
        {
            return IsMACKeyInitialized;
        }

        public static Byte[] EDSBKMXChaCha20Poly1305Encrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXChaCha20Poly1305Decrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[16];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXSalsa20Poly1305Encrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXSalsa20Poly1305Decrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[16];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXChaCha20HMACEncrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXChaCha20HMACDecrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[32];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXSalsa20HMACEncrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXSalsa20HMACDecrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[32];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXChaCha20Poly1305Encrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXChaCha20Poly1305Decrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[16];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];

                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXSalsa20Poly1305Encrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXSalsa20Poly1305Decrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[16];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXChaCha20HMACEncrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXChaCha20HMACDecrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[32];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXSalsa20HMACEncrypt(Byte[] Message)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXSalsa20HMACDecrypt(Byte[] MergedCipherText)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[32];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXChaCha20Poly1305Encrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXChaCha20Poly1305Decrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[16];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXSalsa20Poly1305Encrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXSalsa20Poly1305Decrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[16];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXChaCha20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXChaCha20HMACDecrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[32];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSBKMXSalsa20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    SignedHashedCD = DigitalSignatureOperation.Sign(HashedCD);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return SignedHashedCD.Concat(MAC).Concat(CipherText).ToArray();
        }

        public static Byte[] EDSBKMXSalsa20HMACDecrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            Byte[] ConcatedData = new Byte[] { };
            Byte[] HashedCD = new Byte[] { };
            Byte[] DHashedCD = new Byte[] { };
            Byte[] SignedHashedCD = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    ConcatedData = Nonce.Concat(EKey).Concat(MACKey).ToArray();
                    HashedCD = SodiumGenericHash.ComputeHash(64, ConcatedData);
                    SodiumSecureMemory.SecureClearBytes(ConcatedData);
                    if (DigitalSignatureOperation.GetPrivateKeyLength() == 57)
                    {
                        SignedHashedCD = new Byte[64 + 114];
                    }
                    else
                    {
                        SignedHashedCD = new Byte[64 + 64];
                    }
                    CipherText = new Byte[MergedCipherText.Length - SignedHashedCD.Length - 16];
                    MAC = new Byte[32];
                    Buffer.BlockCopy(MergedCipherText, 0, SignedHashedCD, 0, SignedHashedCD.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, SignedHashedCD.Length + MAC.Length, CipherText, 0, CipherText.Length);
                    DHashedCD = DigitalSignatureOperation.Verify(SignedHashedCD);
                    GCHandle HashedCDHandle = GCHandle.Alloc(HashedCD, GCHandleType.Pinned);
                    GCHandle DHashedCDHandle = GCHandle.Alloc(DHashedCD, GCHandleType.Pinned);
                    try
                    {
                        SodiumHelper.Sodium_Memory_Compare(HashedCDHandle.AddrOfPinnedObject(), DHashedCDHandle.AddrOfPinnedObject(), 64);
                    }
                    catch
                    {
                        throw new CryptographicException("Error: The hash has been tampered");
                    }
                    DHashedCDHandle.Free();
                    HashedCDHandle.Free();
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXChaCha20Poly1305Encrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXChaCha20Poly1305Decrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[16];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];

                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXSalsa20Poly1305Encrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumOneTimeAuth.ComputePoly1305MAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXSalsa20Poly1305Decrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[16];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXChaCha20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXChaCha20.XChaCha20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXChaCha20HMACDecrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[32];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXChaCha20.XChaCha20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static Byte[] EDSXSalsa20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    CipherText = SodiumStreamCipherXSalsa20.XSalsa20Encrypt(Message, Nonce, EKey, true);
                    MAC = SodiumHMACSHA512256.ComputeMAC(CipherText, MACKey, true);
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return MAC.Concat(CipherText).ToArray();
        }

        public static Byte[] EDSXSalsa20HMACDecrypt(Byte[] MergedCipherText, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] MAC = new Byte[] { };
            Boolean AbleToVerifyMAC = false;
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true && DigitalSignatureOperation.GetIsInitialized() == true && IsEncryptionKeyInitialized == true && IsMACKeyInitialized == true)
                {
                    Byte[] EKey = new Byte[32];
                    Byte[] MACKey = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(EncryptionKeyIntPtr);
                    Marshal.Copy(EncryptionKeyIntPtr, EKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(MACKeyIntPtr);
                    Marshal.Copy(MACKeyIntPtr, MACKey, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MACKeyIntPtr);
                    MAC = new Byte[32];
                    CipherText = new Byte[MergedCipherText.Length - MAC.Length];
                    Buffer.BlockCopy(MergedCipherText, 0, MAC, 0, MAC.Length);
                    Buffer.BlockCopy(MergedCipherText, MAC.Length, CipherText, 0, CipherText.Length);
                    AbleToVerifyMAC = SodiumHMACSHA512256.VerifyMAC(MAC, CipherText, MACKey, true);
                    if (AbleToVerifyMAC == true)
                    {
                        Message = SodiumStreamCipherXSalsa20.XSalsa20Decrypt(CipherText, Nonce, EKey, true);
                    }
                    else
                    {
                        throw new CryptographicException("Error: The MAC failed to verify");
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Not Authorized, private key(signing),encryption key and MACKey not initialized");
                }
            }
            return Message;
        }

        public static void ClearKeys()
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            if (Duration.TotalMinutes > Initialization.GetAuthorizationDuration())
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    SodiumGuardedHeapAllocation.Sodium_Free(EncryptionKeyIntPtr);
                    SodiumGuardedHeapAllocation.Sodium_Free(MACKeyIntPtr);
                    HasEKeyCleared = true;
                    HasMACKeyCleared = true;
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
        }
    }
}
