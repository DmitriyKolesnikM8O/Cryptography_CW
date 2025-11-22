using CryptoLib.RSA.Attacks.Models;
using CryptoLib.RSA.RSA.Models;

namespace CryptoLib.RSA.Interfaces
{
    /// <summary>
    /// Определяет контракт для сервиса, выполняющего атаку Винера на RSA.
    /// </summary>
    public interface IWienersAttackService
    {
        /// <summary>
        /// Выполняет атаку Винера на заданный открытый ключ RSA.
        /// </summary>
        /// <param name="publicKey">Уязвимый открытый ключ.</param>
        /// <returns>Результат атаки, содержащий найденные параметры и статус успеха.</returns>
        WienersAttackResult Attack(RsaPublicKey publicKey);
    }
}