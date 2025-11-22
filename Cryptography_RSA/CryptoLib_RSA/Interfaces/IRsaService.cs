using System.Numerics;
using CryptoLib.RSA.RSA.Models;
public interface IRsaService
{
    RsaKeyPair GenerateKeyPair();
    BigInteger Encrypt(BigInteger message, RsaPublicKey key);
    BigInteger Decrypt(BigInteger ciphertext, RsaPrivateKey key);
}