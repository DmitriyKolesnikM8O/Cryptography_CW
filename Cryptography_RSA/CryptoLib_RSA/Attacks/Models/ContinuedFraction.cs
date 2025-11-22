using System.Numerics;

namespace CryptoLib.RSA.Attacks.Models
{
    /// <summary>
    /// Представляет одну подходящую дробь k/d для непрерывной дроби.
    /// </summary>
    /// <param name="NumeratorK">Числитель k.</param>
    /// <param name="DenominatorD">Знаменатель d (кандидат в секретные ключи).</param>
    public record ContinuedFraction(BigInteger NumeratorK, BigInteger DenominatorD);
}