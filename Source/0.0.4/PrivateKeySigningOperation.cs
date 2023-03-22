using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ASodium;
using System.Runtime.InteropServices;
using BCASodium;

namespace SimpleSoftHSM
{
    public static class PrivateKeySigningOperation
    {
        private static IntPtr PrivateKeyIntPtr;
        private static int PrivateKeyLength;
        private static Boolean IsInitialized;
        private static Boolean HasSodiumInitialized;
        private static int Count;
        private static Boolean HasKeyCleared;
        private static Byte[] PublicKey = new Byte[] { };

        public static void LoadPrivateKey(Byte[] PrivateKey, Boolean ClearKey = false)
        {
            if (PrivateKey == null || PrivateKey.Length == 0)
            {
                throw new ArgumentException("Error: Private key can't be null or empty");
            }
            if (!(PrivateKey.Length == 57 || PrivateKey.Length==64) ==true)
            {
                throw new ArgumentException("Error: Private key length must be 57 or 64 bytes in length");
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
                    if (IsInitialized == true && HasKeyCleared == false)
                    {
                        SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(PrivateKeyIntPtr);
                    }
                    else
                    {
                        if (PrivateKey.Length == 57)
                        {
                            PrivateKeyLength = 57;
                        }
                        else 
                        {
                            PrivateKeyLength = 64;
                        }
                        PrivateKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, PrivateKeyLength);
                        Count = 0;
                        while (IsZero == true && Count < 10)
                        {
                            PrivateKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, PrivateKeyLength);
                            Count += 1;
                        }
                        if (Count == 10 && IsZero==true)
                        {
                            throw new SystemException("Error: Failed to create a libsodium storage pointer");
                        }
                    }
                    Marshal.Copy(PrivateKey, 0, PrivateKeyIntPtr, PrivateKeyLength);
                    IsInitialized = true;
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PrivateKeyIntPtr);
                    SodiumSecureMemory.SecureClearBytes(PrivateKey);
                }
                else
                {
                    throw new ArgumentException("Error: Access Denied");
                }
                HasKeyCleared = false;
            }
        }

        public static int GetPrivateKeyLength() 
        {
            return PrivateKeyLength;
        }

        public static Boolean GetIsInitialized() 
        {
            return IsInitialized;
        }

        public static Byte[] Sign(Byte[] Message) 
        {
            Boolean IsAuthorized = true;
            DateTime ChallengeGenerateDT = Initialization.GetChallengeGenerateDT();
            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] SignatureMessage = new Byte[] { };
            if (Duration.TotalMinutes > 8)
            {
                throw new ArgumentException("Error: Please request another challenge");
            }
            else
            {
                IsAuthorized = Initialization.GetIsAuthorized();
                if (IsAuthorized == true)
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(PrivateKeyIntPtr);
                    Byte[] PrivateKey = new Byte[PrivateKeyLength];
                    Marshal.Copy(PrivateKeyIntPtr, PrivateKey, 0, PrivateKey.Length);
                    SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PrivateKeyIntPtr);
                    if (PrivateKeyLength == 57)
                    {
                        PublicKey = SecureED448.GeneratePublicKey(PrivateKey);
                        SignatureMessage = SecureED448.GenerateSignatureMessage(PrivateKey, Message, new Byte[] { },true);
                    }
                    else 
                    {
                        PublicKey = SodiumPublicKeyAuth.GeneratePublicKey(PrivateKey);
                        SignatureMessage = SodiumPublicKeyAuth.Sign(Message, PrivateKey, true);
                    }
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
            return SignatureMessage;
        }

        public static Byte[] Verify(Byte[] SignatureMessage) 
        {
            Byte[] Message = new Byte[] { };
            if (PrivateKeyLength == 57)
            {
                Message = SecureED448.GetMessageFromSignatureMessage(PublicKey, SignatureMessage, new Byte[] { });
            }
            else 
            {
                Message = SodiumPublicKeyAuth.Verify(SignatureMessage, PublicKey);
            }
            return Message;
        }

        public static Byte[] GetPublicKey() 
        {
            return PublicKey;
        }

        public static void ClearPrivateKey()
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
                    SodiumGuardedHeapAllocation.Sodium_Free(PrivateKeyIntPtr);
                    HasKeyCleared = true;
                }
                else
                {
                    throw new ArgumentException("Error: Please request another challenge or use another public key");
                }
            }
        }

    }
}
