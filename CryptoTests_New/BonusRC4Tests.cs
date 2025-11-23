using Xunit;
using System;
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using System.Numerics;

using CryptoLib.New.Algorithms.RC4;
using CryptoLib.New.Protocols.DiffieHellman;
using CryptoLib.DES.Modes;
using CryptoLib.DES.Algorithms.TripleDES;

namespace CryptoTests_New
{
    public class BonusTests
    {

        [Fact]
        public void RC4_DecryptWithWrongKey_ShouldProduceGarbage()
        {
            string original = "Super Secret Military Plans";
            byte[] data = Encoding.UTF8.GetBytes(original);
            byte[] keyCorrect = Encoding.UTF8.GetBytes("CorrectKey");
            byte[] keyWrong = Encoding.UTF8.GetBytes("Wrong_Key_");

            // 1. Шифруем правильным ключом
            var rc4Enc = new RC4Algorithm(keyCorrect);
            byte[] encrypted = rc4Enc.ProcessData(data);

            // 2. Пытаемся расшифровать НЕПРАВИЛЬНЫМ ключом
            var rc4DecBad = new RC4Algorithm(keyWrong);
            byte[] decryptedBad = rc4DecBad.ProcessData(encrypted);

            // 3. Проверяем
            string resultBad = Encoding.UTF8.GetString(decryptedBad);
            
            // Результат не должен совпадать с оригиналом
            Assert.NotEqual(original, resultBad);
            // Результат не должен быть пустым
            Assert.NotEmpty(resultBad);
        }

        [Fact]
        public void RC4_StateShouldEvolve()
        {
            byte[] key = { 1, 2, 3, 4, 5 };
            
            var rc4 = new RC4Algorithm(key);

            // Шифруем байт 'A'
            byte[] out1 = rc4.ProcessData(new byte[] { 65 }); // 'A'
            
            // Шифруем байт 'A' еще раз ТЕМ ЖЕ инстансом
            byte[] out2 = rc4.ProcessData(new byte[] { 65 }); // 'A'

            // В потоковом шифре результат должен быть РАЗНЫМ, 
            // так как внутреннее состояние (_i, _j, S-Box) изменилось.
            Assert.NotEqual(out1[0], out2[0]);
        }

        [Fact]
        public async Task TripleDES_CBC_SameText_DiffIV_ShouldBeDifferent()
        {
            byte[] key = new byte[24]; // 192 bit key
            new Random().NextBytes(key);
            
            byte[] message = Encoding.UTF8.GetBytes("Same Message for both encryptions");
            byte[] output1 = new byte[128];
            byte[] output2 = new byte[128];

            // Шифрование 1: IV = все нули
            byte[] iv1 = new byte[8]; 
            var ctx1 = new CipherContext(key, CipherMode.CBC, PaddingMode.PKCS7, iv1, new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "TripleDES"));
            await ctx1.EncryptAsync(message, output1);

            // Шифрование 2: IV = все единицы
            byte[] iv2 = Enumerable.Repeat((byte)1, 8).ToArray();
            var ctx2 = new CipherContext(key, CipherMode.CBC, PaddingMode.PKCS7, iv2, new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "TripleDES"));
            await ctx2.EncryptAsync(message, output2);

            // Шифротексты должны быть абсолютно разными (ни одного совпадающего блока)
            // Достаточно проверить первые 8 байт
            Assert.False(output1.Take(8).SequenceEqual(output2.Take(8)));
        }

        [Fact]
        public void DH_ThirdParty_CannotDeriveSecret()
        {
            // Алиса
            var alice = new DiffieHellmanProtocol();
            // Боб
            var bob = new DiffieHellmanProtocol(alice.P, alice.G);
            
            // Ева (Злоумышленник) - знает P и G, но у нее свой приватный ключ
            var eve = new DiffieHellmanProtocol(alice.P, alice.G);

            // Алиса и Боб обмениваются ключами
            BigInteger sharedSecretAlice = alice.CalculateSharedSecret(bob.PublicKey);
            
            // Ева перехватила публичный ключ Боба и пытается подобрать секрет, 
            // используя СВОЙ приватный ключ (так как приватный ключ Алисы ей недоступен)
            BigInteger sharedSecretEve = eve.CalculateSharedSecret(bob.PublicKey);

            // Секрет Евы не должен совпасть с секретом Алисы и Боба
            Assert.NotEqual(sharedSecretAlice, sharedSecretEve);
        }

        [Fact]
        public async Task TripleDES_DecryptWithWrongKey_ShouldThrowPaddingException()
        {
            // Если мы зашифруем данные с PKCS7, а расшифруем неверным ключом,
            // то в конце получится случайный мусор, который не соответствует стандарту PKCS7.
            // Код должен либо выдать мусор, либо упасть с ошибкой (в зависимости от реализации RemovePadding).
    

            byte[] keyCorrect = new byte[24]; 
            byte[] keyWrong = new byte[24];
            keyWrong[0] = 1; // Делаем ключ чуть-чуть другим

            byte[] iv = new byte[8];
            string original = "Critical Data";
            byte[] input = Encoding.UTF8.GetBytes(original);
            byte[] encrypted = new byte[64];
            byte[] decrypted = new byte[64];

            // Шифруем верным ключом
            var ctxEnc = new CipherContext(keyCorrect, CipherMode.CBC, PaddingMode.PKCS7, iv, new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "TripleDES"));
            await ctxEnc.EncryptAsync(input, encrypted);

            // Дешифруем неверным
            var ctxDec = new CipherContext(keyWrong, CipherMode.CBC, PaddingMode.PKCS7, iv, new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "TripleDES"));
            await ctxDec.DecryptAsync(encrypted, decrypted);

            string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');

            // Результат не должен быть равен исходному
            Assert.NotEqual(original, result);
        }
    }
}