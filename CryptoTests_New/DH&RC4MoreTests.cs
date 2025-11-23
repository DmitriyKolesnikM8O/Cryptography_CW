using Xunit;
using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using CryptoLib.New.Algorithms.RC4;
using CryptoLib.New.Protocols.DiffieHellman;
using System.Numerics;

namespace CryptoTests_New
{
    public class MoreTests
    {

        [Fact]
        public void RC4_KeyLength_Min_1Byte_ShouldWork()
        {
            byte[] key = { 0x01 }; // Минимальный ключ
            byte[] data = { 0xAA, 0xBB, 0xCC };

            var rc4 = new RC4Algorithm(key);
            byte[] result = rc4.ProcessData(data);

            Assert.Equal(data.Length, result.Length);
            Assert.False(data.SequenceEqual(result)); // Должно зашифроваться
        }

        [Fact]
        public void RC4_KeyLength_Max_256Bytes_ShouldWork()
        {
            byte[] key = new byte[256]; // Максимальный ключ
            for (int i = 0; i < 256; i++) key[i] = (byte)i;

            byte[] data = Encoding.UTF8.GetBytes("Testing large key");

            var rc4 = new RC4Algorithm(key);
            byte[] result = rc4.ProcessData(data);

            Assert.Equal(data.Length, result.Length);
        }

        [Fact]
        public void RC4_EmptyInput_ShouldReturnEmpty()
        {
            byte[] key = { 1, 2, 3 };
            var rc4 = new RC4Algorithm(key);
            
            byte[] result = rc4.ProcessData(new byte[0]);
            
            Assert.Empty(result);
        }

        [Fact]
        public void RC4_StreamConsistency_Chunked_vs_Full()
        {
            // Проверяем, что encrypt("Hello") == encrypt("He") + encrypt("llo")
            
            byte[] key = { 0x55, 0x66, 0x77 };
            byte[] fullData = Encoding.UTF8.GetBytes("HelloWorld");
            
            // Вариант 1: Шифруем всё сразу
            var rc4_1 = new RC4Algorithm(key);
            byte[] resultFull = rc4_1.ProcessData(fullData);

            // Вариант 2: Шифруем по кускам одним инстансом
            var rc4_2 = new RC4Algorithm(key);
            byte[] part1 = fullData.Take(5).ToArray(); // "Hello"
            byte[] part2 = fullData.Skip(5).ToArray(); // "World"

            byte[] res1 = rc4_2.ProcessData(part1);
            byte[] res2 = rc4_2.ProcessData(part2);

            // Склеиваем результат
            byte[] resultChunked = res1.Concat(res2).ToArray();

            Assert.Equal(resultFull, resultChunked);
        }

        [Fact]
        public void RC4_Deterministic_SameKeySameData()
        {
            byte[] key = { 10, 20, 30 };
            byte[] data = { 1, 2, 3, 4, 5 };

            var rc4_1 = new RC4Algorithm(key);
            byte[] res1 = rc4_1.ProcessData(data);

            var rc4_2 = new RC4Algorithm(key);
            byte[] res2 = rc4_2.ProcessData(data);

            Assert.Equal(res1, res2);
        }

        [Fact]
        public void RC4_AvalancheEffect_ChangeKeyBit()
        {
            
            byte[] key1 = { 0, 0, 0, 0 };
            byte[] key2 = { 0, 0, 0, 1 }; 
            byte[] data = new byte[10];   

            var rc4_1 = new RC4Algorithm(key1);
            byte[] res1 = rc4_1.ProcessData(data);

            var rc4_2 = new RC4Algorithm(key2);
            byte[] res2 = rc4_2.ProcessData(data);

            Assert.NotEqual(res1, res2);
        }

        [Fact]
        public void DH_StressTest_50_Iterations()
        {
            
            for (int i = 0; i < 50; i++)
            {
                var alice = new DiffieHellmanProtocol();
                var bob = new DiffieHellmanProtocol(alice.P, alice.G);

                var s1 = alice.CalculateSharedSecret(bob.PublicKey);
                var s2 = bob.CalculateSharedSecret(alice.PublicKey);

                Assert.Equal(s1, s2);
                Assert.True(s1 > 0);
            }
        }

        [Fact]
        public void DH_DeriveKey_TooLarge_ShouldThrow()
        {
            var dh = new DiffieHellmanProtocol();
            // Мы используем SHA256, он выдает 32 байта.
            // Если попросить 33 байта, должно упасть (согласно нашей реализации).
            
            BigInteger dummySecret = 12345;
            
            Assert.Throws<ArgumentException>(() => 
                DiffieHellmanProtocol.DeriveSymmetricKey(dummySecret, 33));
        }

        [Fact]
        public void DH_DeriveKey_DifferentLengths()
        {
            BigInteger secret = BigInteger.Parse("12345678901234567890");

            // Проверяем 16 байт (AES-128, RC4)
            byte[] key16 = DiffieHellmanProtocol.DeriveSymmetricKey(secret, 16);
            Assert.Equal(16, key16.Length);

            // Проверяем 24 байта (TripleDES)
            byte[] key24 = DiffieHellmanProtocol.DeriveSymmetricKey(secret, 24);
            Assert.Equal(24, key24.Length);

            // Проверяем 32 байта (AES-256)
            byte[] key32 = DiffieHellmanProtocol.DeriveSymmetricKey(secret, 32);
            Assert.Equal(32, key32.Length);

            // Проверка, что ключи согласованы (key16 это префикс key32)
            // Т.к. мы просто обрезаем хеш, начало должно совпадать
            Assert.Equal(key16, key32.Take(16).ToArray());
        }

        [Fact]
        public void DH_Keys_ShouldBeWithinRange()
        {
            var dh = new DiffieHellmanProtocol();
            
            // Публичный ключ должен быть: 1 < PublicKey < P-1
            Assert.True(dh.PublicKey > 1);
            Assert.True(dh.PublicKey < dh.P - 1);
            
            // P должно быть положительным и большим (1536 бит)
            Assert.True(dh.P.Sign > 0);
            Assert.True(dh.P.ToByteArray().Length > 100); 
        }
        
        [Fact]
        public void DH_SameParams_ShouldHaveSameModulus()
        {
            var alice = new DiffieHellmanProtocol();
            var bob = new DiffieHellmanProtocol(alice.P, alice.G);
            
            Assert.Equal(alice.P, bob.P);
            Assert.Equal(alice.G, bob.G);
        }
    }
}