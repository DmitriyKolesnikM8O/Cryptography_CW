using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace CryptoLib.New.Protocols.DiffieHellman
{
    public class DiffieHellmanProtocol
    {
        // Безопасное простое число P (1536 бит) из RFC 3526 (Group 5).
        // Это стандартное число, используемое в интернете (IKE, SSH и т.д.).
        private static readonly BigInteger P_RFC3526 = BigInteger.Parse(
            "323170060713110073003389139264238282488179412411402391128420097514007417066343542226196894173635693471179017379097041917546058732091950288537589861856221532121754125149017745202702357960782362488842461894793563466972422131746205067972325752044460486774221310673036021227187158566833486653485626051914642966629"
        );
        
        // Генератор G для этой группы равен 2
        private static readonly BigInteger G_RFC3526 = 2;

        public BigInteger P { get; }
        public BigInteger G { get; }

        private BigInteger _privateKey;
        public BigInteger PublicKey { get; private set; }

        /// <summary>
        /// Конструктор инициатора.
        /// </summary>
        public DiffieHellmanProtocol()
        {
            P = P_RFC3526;
            G = G_RFC3526;
            GenerateKeyPair();
        }

        /// <summary>
        /// Конструктор получателя. Принимает P и G от инициатора.
        /// </summary>
        public DiffieHellmanProtocol(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            // Генерируем приватный ключ (случайное число длиной 256 бит)
            _privateKey = GenerateRandomSecret(32); 

            // Public Key = G^privateKey mod P
            PublicKey = BigInteger.ModPow(G, _privateKey, P);
        }

        /// <summary>
        /// Вычисляет общий секрет (Shared Secret).
        /// Secret = OtherPublicKey ^ MyPrivateKey mod P
        /// </summary>
        public BigInteger CalculateSharedSecret(BigInteger otherPublicKey)
        {
            return BigInteger.ModPow(otherPublicKey, _privateKey, P);
        }

        /// <summary>
        /// Превращает математический общий секрет в байтовый ключ для шифрования.
        /// (Берет хэш SHA256 от числа и обрезает до нужной длины).
        /// </summary>
        public static byte[] DeriveSymmetricKey(BigInteger sharedSecret, int keySizeInBytes)
        {
            byte[] secretBytes = sharedSecret.ToByteArray();

            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(secretBytes);
                
                if (hash.Length >= keySizeInBytes)
                {
                    byte[] key = new byte[keySizeInBytes];
                    Array.Copy(hash, key, keySizeInBytes);
                    return key;
                }
                else
                {
                    throw new ArgumentException("Requested key size is too large for SHA256 derivation");
                }
            }
        }

        private BigInteger GenerateRandomSecret(int length)
        {
            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            
            // Убираем знаковый бит (делаем положительным)
            bytes[bytes.Length - 1] &= 0x7F; 
            if (bytes.All(b => b == 0)) bytes[0] = 1; // Защита от нуля

            return new BigInteger(bytes);
        }
    }
}