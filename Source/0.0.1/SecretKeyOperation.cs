using ASodium;
using System.Runtime.InteropServices;

namespace SimpleSoftHSM
{
    public class SecretKeyOperation
    {
        private static IntPtr SecretKeyIntPtr;
        private static Boolean IsInitialized;
        private static Boolean HasSodiumInitialized;
        private static int Count;

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
            if (Duration.TotalMinutes > 8)
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
                    if (IsInitialized == true)
                    {
                        SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SecretKeyIntPtr);
                    }
                    else
                    {
                        SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                        Count = 0;
                        while (IsZero == true && Count < 10)
                        {
                            SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, 32);
                            Count += 1;
                        }
                    }
                    Marshal.Copy(Key, 0, SecretKeyIntPtr, 32);
                    IsInitialized = true;
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                }
                else 
                {
                    throw new ArgumentException("Error: Access Denied");
                }
            }            
        }

        public static Byte[] XChaCha20HMACEncrypt(Byte[] Message) 
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherTextWithMAC = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else 
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    CipherTextWithMAC = EDSStreamCipher.XChaCha20HMACEncrypt(Message, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else 
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return CipherTextWithMAC;
        }

        public static Byte[] XChaCha20HMACDecrypt(Byte[] CipherTextWithMAC) 
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    Message = EDSStreamCipher.XChaCha20HMACDecrypt(CipherTextWithMAC, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return Message;
        }

        public static Byte[] XSalsa20HMACEncrypt(Byte[] Message) 
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherTextWithMAC = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    CipherTextWithMAC = EDSStreamCipher.XSalsa20HMACEncrypt(Message, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return CipherTextWithMAC;
        }

        public static Byte[] XSalsa20HMACDecrypt(Byte[] CipherTextWithMAC) 
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Nonce = SodiumGenericHash.ComputeHash(24, Initialization.GetPublicKey());
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    Message = EDSStreamCipher.XSalsa20HMACDecrypt(CipherTextWithMAC, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return Message;
        }

        public static Byte[] XChaCha20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherTextWithMAC = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    CipherTextWithMAC = EDSStreamCipher.XChaCha20HMACEncrypt(Message, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return CipherTextWithMAC;
        }

        public static Byte[] XChaCha20HMACDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    Message = EDSStreamCipher.XChaCha20HMACDecrypt(CipherTextWithMAC, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return Message;
        }

        public static Byte[] XSalsa20HMACEncrypt(Byte[] Message, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] CipherTextWithMAC = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    CipherTextWithMAC = EDSStreamCipher.XSalsa20HMACEncrypt(Message, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return CipherTextWithMAC;
        }

        public static Byte[] XSalsa20HMACDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce)
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Message = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    Byte[] Key = new Byte[32];
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretKeyIntPtr);
                    Marshal.Copy(SecretKeyIntPtr, Key, 0, 32);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                    Message = EDSStreamCipher.XSalsa20HMACDecrypt(CipherTextWithMAC, Nonce, Key);
                    SodiumSecureMemory.SecureClearBytes(Key);
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return Message;
        }
    }
}
