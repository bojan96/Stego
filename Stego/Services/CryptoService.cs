using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Stego.Services
{
    static class CryptoService
    {
        const int SYMM_KEY_SIZE = 16; // in bytes
        const int IV_SIZE = 16;
        const int RSA_KEY_SIZE = 2048;
        static readonly HashAlgorithmName HASH_ALGORITHM = HashAlgorithmName.SHA256;
        static readonly RSASignaturePadding RSA_SIGNATURE_PADDING = RSASignaturePadding.Pkcs1;
        static readonly RSAEncryptionPadding RSA_ENCRYPTION_PADDING = RSAEncryptionPadding.OaepSHA1;
        private static readonly SecureRandom rng = new SecureRandom();


        public static byte[] EncryptMessage(string privateKeyPath, string publicKeyPath, string message)
        {
            using RSA privateKey = ReadPrivateKey(privateKeyPath);
            using RSA publicKey = ReadPublicKey(publicKeyPath);

            byte[] symmKey = GenerateSymmetricKey();
            byte[] iv = GenerateIV();
            byte[] envelope = EncryptSymmetricData(symmKey, iv, publicKey);

            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            byte[] signature = SignData(msgBytes, privateKey);
            byte[] dataAndSign = Utility.CombineByteArrays(msgBytes, signature);

            byte[] encData = EncryptData(dataAndSign, symmKey, iv);
            return Utility.CombineByteArrays(envelope, encData);
        }

        public static string DecryptMessage(string privateKeyPath, string publicKeyPath, byte[] payload)
        {
            using RSA privKey = ReadPrivateKey(privateKeyPath);
            using RSA pubKey = ReadPublicKey(publicKeyPath);

            (byte[] envelope, byte[] encData) = Utility.SplitArray(payload);
            (byte[] symmkey, byte[] iv) = DecryptSymmetricData(envelope, privKey);

            byte[] decData = DecryptData(encData, symmkey, iv);
            (byte[] msgBytes, byte[] signature) = Utility.SplitArray(decData);

            bool result = VerifyData(msgBytes, signature, pubKey);

            if (!result)
                throw new SignatureException("Signature verification failed");

            return Encoding.UTF8.GetString(msgBytes);
        }

        private static byte[] GenerateRandomBytes(int size)
        {

            byte[] key = new byte[size];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetBytes(key);

            return key;

        }


        private static byte[] GenerateSymmetricKey()
        {
            return GenerateRandomBytes(SYMM_KEY_SIZE);
        }

        private static byte[] GenerateIV()
        {
            return GenerateRandomBytes(IV_SIZE);
        }


        // Using symmetric algorithm
        private static byte[] EncryptData(byte[] data, byte[] key, byte[] iV)
        {

            using (Aes aes = Aes.Create())
            using (var memStream = new MemoryStream())
            {

                using (var encryptor = aes.CreateEncryptor(key, iV))
                using (var cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    cryptoStream.Write(data, 0, data.Length);


                // Stream is flushed upon closing CrytpoStream to MemoryStream
                return memStream.ToArray();

            }


        }

        private static byte[] DecryptData(byte[] data, byte[] key, byte[] iV)
        {

            using (Aes aes = Aes.Create())
            using (var dstStream = new MemoryStream())
            using (var memStream = new MemoryStream(data))
            using (var decryptor = aes.CreateDecryptor(key, iV))
            using (var cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
            {

                cryptoStream.CopyTo(dstStream);
                return dstStream.ToArray();

            }

        }

        // Creates a envelope
        private static byte[] EncryptSymmetricData(byte[] symmetricKey, byte[] iV, RSA rsa)
        {

            byte[] keyIVPair = new byte[symmetricKey.Length + iV.Length];
            symmetricKey.CopyTo(keyIVPair, 0);
            iV.CopyTo(keyIVPair, symmetricKey.Length);

            return rsa.Encrypt(keyIVPair, RSA_ENCRYPTION_PADDING);

        }

        private static (byte[], byte[]) DecryptSymmetricData(byte[] envelope, RSA rsa)
        {

            byte[] keyIVPair = rsa.Decrypt(envelope, RSA_ENCRYPTION_PADDING);
            byte[] symmetricKey = new byte[SYMM_KEY_SIZE];
            byte[] iV = new byte[IV_SIZE];

            Array.Copy(keyIVPair, 0, symmetricKey, 0, SYMM_KEY_SIZE);
            Array.Copy(keyIVPair, SYMM_KEY_SIZE, iV, 0, IV_SIZE);

            return (symmetricKey, iV);

        }

        private static byte[] SignData(byte[] data, RSA rsa)
        {

            return rsa.SignData(data, HASH_ALGORITHM, RSA_SIGNATURE_PADDING);

        }

        private static bool VerifyData(byte[] data, byte[] signature, RSA rsa)
        {

            return rsa.VerifyData(data, signature, HASH_ALGORITHM, RSA_SIGNATURE_PADDING);

        }

        // Also checks if there is RSA private key
        private static RSA ReadPrivateKey(string path)
        {

            if (!IsPrivateKeyValid(path))
                throw new FileFormatException("File is not valid pem file or does not contain rsa private key");

            using (StreamReader streamReader = new StreamReader(path))
            {

                PemReader pemReader = new PemReader(streamReader);
                var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                var privKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
                var rsaParam = new RSAParameters();

                rsaParam.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
                rsaParam.D = privKey.Exponent.ToByteArrayUnsigned();
                rsaParam.DP = privKey.DP.ToByteArrayUnsigned();
                rsaParam.DQ = privKey.DQ.ToByteArrayUnsigned();
                rsaParam.InverseQ = privKey.QInv.ToByteArrayUnsigned();
                rsaParam.P = privKey.P.ToByteArrayUnsigned();
                rsaParam.Q = privKey.Q.ToByteArrayUnsigned();
                rsaParam.Modulus = privKey.Modulus.ToByteArrayUnsigned();
               
                RSA rsa = RSA.Create();
                rsa.ImportParameters(rsaParam);

                return rsa;

            }

        }

        public static RSA ReadPublicKey(string path)
        {
            if (!IsPublicKeyValid(path))
                throw new FileFormatException("File is not valid pem file or does not contain rsa public key");

            using StreamReader reader = new StreamReader(path);
            PemReader pem = new PemReader(reader);
            RsaKeyParameters par = (RsaKeyParameters)pem.ReadObject();
            RSA rsa = RSA.Create();
            RSAParameters rsaParam = new RSAParameters();
            rsaParam.Modulus = par.Modulus.ToByteArrayUnsigned();
            rsaParam.Exponent = par.Exponent.ToByteArrayUnsigned();
            rsa.ImportParameters(rsaParam);
            return rsa;
        }

        public static bool IsPublicKeyValid(string path)
        {
            using StreamReader reader = new StreamReader(path);
            return reader.ReadLine() == "-----BEGIN PUBLIC KEY-----";
        }

        public static bool IsPrivateKeyValid(string path)
        {
            using StreamReader reader = new StreamReader(path);
            return reader.ReadLine() == "-----BEGIN RSA PRIVATE KEY-----";
        }

        public static void GenerateRsaKeyPair(string privKeyPath, string pubKeyPath)
        {
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(new KeyGenerationParameters(rng, RSA_KEY_SIZE));
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            using StreamWriter privKeyWriter = new StreamWriter(privKeyPath);
            using StreamWriter pubKeyWriter = new StreamWriter(pubKeyPath);
            PemWriter privKeyPem = new PemWriter(privKeyWriter);
            PemWriter pubKeyPem = new PemWriter(pubKeyWriter);
            privKeyPem.WriteObject(keyPair.Private);
            pubKeyPem.WriteObject(keyPair.Public);
        }
    }
}
