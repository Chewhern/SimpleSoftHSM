﻿using ASodium;
using System.Runtime.InteropServices ;
using BCASodium;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace SimpleSoftHSM
{
    public static class Initialization
    {
        private static Byte[] publicKey = new Byte[] { };
        private static Boolean IsED25519;
        private static Boolean IsInitialized;
        private static Byte[] RandomChallenge = new Byte[] { };
        private static DateTime ChallengeGenerateDT;
        private static DateTime PublicKeyInitializeDT;
        private static Boolean IsAuthorized;
        private static int PublicKeyReplacingDurationInMinutes;
        private static int DurationForAuthorizationInMinutes;

        public static void LoadPublicKey(Byte[] PublicKey,int publickeyreplacingdurationinminutes=30,int durationforauthorizationinminutes=8) 
        {
            if (PublicKey == null || PublicKey.Length==0) 
            {
                throw new ArgumentException("Error: Public key should not be null");
            }
            if (!(PublicKey.Length == SodiumPublicKeyAuth.GetPublicKeyBytesLength() || PublicKey.Length == Ed448.PublicKeySize) ==true)
            {
                throw new ArgumentException("Error: Public key must belong to either ED448 or ED25519");
            }
            if (IsInitialized == true)
            {
                DateTime PreventAlterationDT = DateTime.UtcNow.AddHours(8);
                TimeSpan Duration = PreventAlterationDT.Subtract(PublicKeyInitializeDT);
                if (Duration.TotalMinutes <= PublicKeyReplacingDurationInMinutes)
                {
                    throw new SystemException("Error: Once public key has been initialized, it can only be changed into other public key after "+ PublicKeyReplacingDurationInMinutes +" minutes");
                }
                else
                {
                    publicKey = PublicKey;
                    if (PublicKey.Length == SodiumPublicKeyAuth.GetPublicKeyBytesLength())
                    {
                        IsED25519 = true;
                    }
                    else
                    {
                        IsED25519 = false;
                    }
                    DurationForAuthorizationInMinutes = durationforauthorizationinminutes;
                    PublicKeyReplacingDurationInMinutes = publickeyreplacingdurationinminutes;
                    PublicKeyInitializeDT = DateTime.UtcNow.AddHours(8);
                    if (PrivateKeySigningOperation.GetIsInitialized() == true) 
                    {
                        PrivateKeySigningOperation.ClearPrivateKey();
                    }
                    if (SecretKeyOperation.GetIsEKeyInitialized() == true && SecretKeyOperation.GetIsMACKeyInitialized() == true) 
                    {
                        SecretKeyOperation.ClearKeys();
                    }
                }
            }
            else 
            {
                publicKey = PublicKey;
                if (PublicKey.Length == SodiumPublicKeyAuth.GetPublicKeyBytesLength())
                {
                    IsED25519 = true;
                }
                else
                {
                    IsED25519 = false;
                }
                IsInitialized = true;
                PublicKeyInitializeDT = DateTime.UtcNow.AddHours(8);
                DurationForAuthorizationInMinutes = durationforauthorizationinminutes;
                PublicKeyReplacingDurationInMinutes = publickeyreplacingdurationinminutes;
            }
            
        }

        public static Byte[] RequestChallenge() 
        {
            RandomChallenge = SodiumRNG.GetRandomBytes(128);
            ChallengeGenerateDT = DateTime.UtcNow.AddHours(8);
            return RandomChallenge;
        }

        public static Boolean GetIsAuthorized() 
        {
            return IsAuthorized; 
        }

        public static int GetAuthorizationDuration() 
        {
            return DurationForAuthorizationInMinutes;
        }

        public static Byte[] GetPublicKey() 
        {
            return publicKey;
        }

        public static DateTime GetChallengeGenerateDT() 
        {
            return ChallengeGenerateDT;
        }

        public static void Authorize(Byte[] SignedChallenge) 
        {
            if (SignedChallenge == null || SignedChallenge.Length == 0) 
            {
                throw new ArgumentException("Error: Signed Challenge can't be null or empty");
            }

            DateTime CurrentDateTime = DateTime.UtcNow.AddHours(8);
            TimeSpan Duration = CurrentDateTime.Subtract(ChallengeGenerateDT);
            Byte[] Challenge = new Byte[] { };

            if (Duration.TotalMinutes > DurationForAuthorizationInMinutes)
            {
                IsAuthorized = false;
            }
            else 
            {
                try
                {
                    if (IsInitialized == true)
                    {
                        if (IsED25519 == true)
                        {
                            Challenge = SodiumPublicKeyAuth.Verify(SignedChallenge, publicKey);
                        }
                        else 
                        {
                            Challenge = SecureED448.GetMessageFromSignatureMessage(publicKey, SignedChallenge, new byte[] { });
                        }
                        GCHandle ChallengeGCHandle = GCHandle.Alloc(Challenge, GCHandleType.Pinned);
                        GCHandle ChallengeGCHandle2 = GCHandle.Alloc(RandomChallenge, GCHandleType.Pinned);
                        try
                        {
                            SodiumHelper.Sodium_Memory_Compare(ChallengeGCHandle.AddrOfPinnedObject(), ChallengeGCHandle2.AddrOfPinnedObject(),128);                            
                            IsAuthorized = true;
                        }
                        catch 
                        {
                            IsAuthorized = false;
                        }
                        ChallengeGCHandle.Free();
                        ChallengeGCHandle2.Free();
                    }
                    else 
                    {
                        throw new ArgumentException("Error: Public key has not been initialized");
                    }
                }
                catch 
                {
                    IsAuthorized = false;   
                }
            }
        }
    }
}