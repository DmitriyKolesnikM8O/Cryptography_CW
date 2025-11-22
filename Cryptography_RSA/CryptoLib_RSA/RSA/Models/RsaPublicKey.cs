using System.Numerics;

namespace CryptoLib.RSA.RSA.Models
{
    public record RsaPublicKey(BigInteger E, BigInteger N);
}