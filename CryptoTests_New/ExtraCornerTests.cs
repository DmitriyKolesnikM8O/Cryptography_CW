using Xunit;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

using CryptoLib.New.Algorithms.LOKI97;
using CryptoLib.New.Algorithms.RC4;
using CryptoLib.New.Modes; 
using CryptoLib.DES.Modes; 
using CryptoLib.New.Protocols.DiffieHellman;

namespace CryptoTests_New
{
    public class ExtraCornerTests
    {

        [Fact]
        public void LOKI97_KeySize_192Bits_ShouldWork()
        {
            byte[] key = new byte[24]; 
            for(int i=0; i<24; i++) key[i] = (byte)i;
            
            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key); 

            byte[] block = new byte[16];
            byte[] enc = loki.EncryptBlock(block);
            byte[] dec = loki.DecryptBlock(enc);

            Assert.Equal(block, dec);
        }

        [Fact]
        public async Task Context_EncryptECB_DecryptCBC_ShouldFailIntegrity()
        {
            // ИСПРАВЛЕНО: IV должен быть НЕ НУЛЕВЫМ.
            // Если IV=0, то CBC для первого блока превращается в ECB (A ^ 0 = A).
            // Из-за этого тест падал (расшифровка проходила успешно).
            
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            Array.Fill(iv, (byte)0x1); // Заполняем единицами

            byte[] input = Encoding.UTF8.GetBytes("Test message 123"); 

            byte[] encrypted = new byte[32];
            byte[] decrypted = new byte[32];

            // Encrypt ECB (без IV)
            var ctxEnc = new CipherContextLOKI97(key, CipherMode.ECB, PaddingMode.Zeros, null);
            await ctxEnc.EncryptAsync(input, encrypted);

            // Decrypt CBC (с IV)
            var ctxDec = new CipherContextLOKI97(key, CipherMode.CBC, PaddingMode.Zeros, iv);
            await ctxDec.DecryptAsync(encrypted, decrypted);

            // Теперь результат ГАРАНТИРОВАННО будет мусором из-за XOR с IV
            Assert.False(input.SequenceEqual(decrypted.Take(input.Length)));
        }

        [Fact]
        public async Task LOKI97_CBC_BitFlipping_Check()
        {
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            byte[] input = new byte[32]; 
            
            var ctx = new CipherContextLOKI97(key, CipherMode.CBC, PaddingMode.Zeros, iv);
            
            byte[] encrypted = new byte[32];
            await ctx.EncryptAsync(input, encrypted);

            encrypted[0] ^= 1; // Corrupt 1 bit

            byte[] decrypted = new byte[32];
            await ctx.DecryptAsync(encrypted, decrypted);

            bool firstBlockCorrupted = !decrypted.Take(16).All(b => b == 0);
            Assert.True(firstBlockCorrupted);
            Assert.Equal(1, decrypted[16]); // Error propagation to next block
        }

        [Fact]
        public void DH_DifferentParams_ShouldFailAgreement()
        {
            var alice = new DiffieHellmanProtocol();
            var fakeP = alice.P + 2; 
            var bob = new DiffieHellmanProtocol(fakeP, alice.G);

            BigInteger s1 = alice.CalculateSharedSecret(bob.PublicKey);
            BigInteger s2 = bob.CalculateSharedSecret(alice.PublicKey);

            Assert.NotEqual(s1, s2);
        }

        [Fact]
        public void LOKI97_ZeroKey_ZeroInput_ShouldNotCrash()
        {
            byte[] key = new byte[16]; 
            byte[] block = new byte[16]; 

            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key);
            
            byte[] enc = loki.EncryptBlock(block);
            Assert.False(enc.All(b => b == 0));
            
            byte[] dec = loki.DecryptBlock(enc);
            Assert.Equal(block, dec);
        }

        [Fact]
        public void RC4_Reinitialization_ShouldProduceSameStream()
        {
            byte[] key = { 0xAA, 0xBB };
            byte[] data = { 1, 2, 3, 4, 5 };

            var rc4_1 = new RC4Algorithm(key);
            byte[] res1 = rc4_1.ProcessData(data);

            var rc4_2 = new RC4Algorithm(key);
            byte[] res2 = rc4_2.ProcessData(data);

            Assert.Equal(res1, res2);
        }
    }
}