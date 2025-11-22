using System.Numerics;

namespace CryptoLib.RSA.Attacks.Models
{
    /// <summary>
    /// Представляет результат выполнения атаки Винера.
    /// </summary>
    /// <param name="IsSuccessful">Успешна ли была атака.</param>
    /// <param name="FoundD">Найденный секретный ключ d (null, если атака неуспешна).</param>
    /// <param name="FoundPhi">Найденная функция Эйлера phi(N) (null, если атака неуспешна).</param>
    /// <param name="Convergents">Коллекция всех вычисленных подходящих дробей.</param>
    public record WienersAttackResult(
        bool IsSuccessful, 
        BigInteger? FoundD, 
        BigInteger? FoundPhi, 
        IReadOnlyList<ContinuedFraction> Convergents
    );
}