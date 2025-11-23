using Xunit;
using System.Numerics;
using System.Text;
using CryptoLib.New.Protocols.DiffieHellman;
using CryptoLib.DES.Algorithms.TripleDES;

namespace CryptoTests_New
{
    public class DiffieHellmanTests
    {
        [Fact]
        public void DiffieHellman_ShouldExchangeKeys_And_EncryptWithTripleDES()
        {
            
            // Алиса создает параметры
            var aliceDH = new DiffieHellmanProtocol();
            
            // Алиса отправляет P и G Бобу. Боб инициализируется.
            var bobDH = new DiffieHellmanProtocol(aliceDH.P, aliceDH.G);
            
            // Обмен публичными ключами (по открытому каналу)
            BigInteger alicePublic = aliceDH.PublicKey;
            BigInteger bobPublic = bobDH.PublicKey;

            // Вычисление общего секрета
            BigInteger aliceSecret = aliceDH.CalculateSharedSecret(bobPublic);
            BigInteger bobSecret = bobDH.CalculateSharedSecret(alicePublic);

            // Проверка: математика сработала
            Assert.Equal(aliceSecret, bobSecret);

            // Нам нужен ключ 24 байта (192 бита) для TripleDES
            int keySize = 24; 
            
            // Алиса и Боб независимо превращают числовой секрет в байтовый ключ
            byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
            byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

            Assert.Equal(aliceKey, bobKey);

            
            
            var message = "Secret Message transmitted via DH key!";
            var data = Encoding.UTF8.GetBytes(message);

            // Алиса шифрует
            var aliceCipher = new TripleDESAlgorithm();
            aliceCipher.SetRoundKeys(aliceKey);
            
            // (Для теста шифруем блоками вручную, т.к. CipherContext тут избыточен для демо, 
            // просто зашифруем первый блок 8 байт для проверки)
            byte[] block = new byte[8];
            Array.Copy(data, block, 8); // Берем первые 8 байт "Secret M"
            
            byte[] encryptedBlock = aliceCipher.EncryptBlock(block);

            // Боб дешифрует
            var bobCipher = new TripleDESAlgorithm();
            bobCipher.SetRoundKeys(bobKey); // Боб использует СВОЙ вычисленный ключ

            byte[] decryptedBlock = bobCipher.DecryptBlock(encryptedBlock);

 
            Assert.Equal(block, decryptedBlock);
            string decryptedText = Encoding.UTF8.GetString(decryptedBlock);
            Assert.Equal("Secret M", decryptedText);
        }
    }
}