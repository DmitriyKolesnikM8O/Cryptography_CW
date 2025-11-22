using System.Numerics;

namespace CryptoLib.RSA.RSA.Models
{
    public record RsaPrivateKey(BigInteger D, BigInteger N);
}