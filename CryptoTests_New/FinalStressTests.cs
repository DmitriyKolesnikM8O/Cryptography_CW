using Xunit;
using Xunit.Abstractions;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Numerics;

using CryptoLib.New.Algorithms.LOKI97;
using CryptoLib.New.Algorithms.RC4;
using CryptoLib.DES.Algorithms.TripleDES;
using CryptoLib.DES.Algorithms.DES;
using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;

namespace CryptoTests_New
{
    public class FinalStressTests
    {
        private readonly ITestOutputHelper _output;

        public FinalStressTests(ITestOutputHelper output)
        {
            _output = output;
        }

        // ==========================================
        // 1. LOKI97: ЛАВИННЫЙ ЭФФЕКТ (AVALANCHE EFFECT)
        // ==========================================
        [Fact]
        public void LOKI97_AvalancheEffect_Plaintext()
        {
            // Суть: меняем 1 бит в открытом тексте -> должно измениться около 50% бит шифротекста (64 из 128)
            byte[] key = new byte[16];
            new Random().NextBytes(key);
            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key);

            byte[] block1 = new byte[16]; // Все нули
            byte[] block2 = new byte[16];
            block2[0] = 1; // Меняем 1 бит (00000000 -> 00000001)

            byte[] enc1 = loki.EncryptBlock(block1);
            byte[] enc2 = loki.EncryptBlock(block2);

            int changedBits = CountDifferentBits(enc1, enc2);
            
            _output.WriteLine($"LOKI97 Plaintext Avalanche: {changedBits} bits changed out of 128");

            // Критерий: должно измениться хотя бы 40 бит (в идеале 64)
            Assert.True(changedBits > 40, $"Avalanche effect too weak: only {changedBits} bits changed");
        }

        [Fact]
        public void LOKI97_AvalancheEffect_Key()
        {
            // Суть: меняем 1 бит в КЛЮЧЕ -> шифротекст должен измениться кардинально
            byte[] block = new byte[16];
            
            byte[] key1 = new byte[16];
            byte[] key2 = new byte[16];
            key2[0] = 1; // Отличается на 1 бит

            var loki1 = new LOKI97Algorithm(); loki1.SetRoundKeys(key1);
            var loki2 = new LOKI97Algorithm(); loki2.SetRoundKeys(key2);

            byte[] enc1 = loki1.EncryptBlock(block);
            byte[] enc2 = loki2.EncryptBlock(block);

            int changedBits = CountDifferentBits(enc1, enc2);
            
            _output.WriteLine($"LOKI97 Key Avalanche: {changedBits} bits changed out of 128");
            Assert.True(changedBits > 40);
        }

        // ==========================================
        // 2. RC4: STRESS TEST (LARGE DATA)
        // ==========================================
        [Fact]
        public void RC4_LargeData_StabilityTest()
        {
            // Шифруем 10 МБ данных. Проверяем скорость и отсутствие ошибок.
            int size = 10 * 1024 * 1024; // 10 MB
            byte[] data = new byte[size];
            // Заполнять рандомом долго, заполним паттерном
            for (int i = 0; i < size; i += 1000) data[i] = (byte)(i % 255);

            byte[] key = { 1, 2, 3, 4, 5 };
            var rc4 = new RC4Algorithm(key);

            var sw = Stopwatch.StartNew();
            byte[] encrypted = rc4.ProcessData(data);
            sw.Stop();

            _output.WriteLine($"RC4 Processed 10MB in {sw.ElapsedMilliseconds} ms");
            
            // Простая проверка, что данные изменились
            Assert.NotEqual(data[0], encrypted[0]);
            Assert.Equal(data.Length, encrypted.Length);
            Assert.True(sw.ElapsedMilliseconds < 5000, "RC4 is too slow!"); // Должно быть очень быстро
        }

        // ==========================================
        // 3. МНОГОПОТОЧНОСТЬ (THREAD SAFETY)
        // ==========================================
        [Fact]
        public void LOKI97_Concurrency_StressTest()
        {
            // Запускаем 1000 параллельных шифрований разными ключами.
            // Это проверяет, нет ли статических полей, которые ломаются при доступе из разных потоков.
            
            int iterations = 1000;
            var tasks = new Task[iterations];
            
            // Базовые данные
            byte[] baseBlock = new byte[16];

            Parallel.For(0, iterations, i =>
            {
                byte[] key = new byte[16];
                // Уникальный ключ для потока (псевдо)
                BitConverter.GetBytes(i).CopyTo(key, 0); 
                
                var loki = new LOKI97Algorithm();
                loki.SetRoundKeys(key);
                
                byte[] enc = loki.EncryptBlock(baseBlock);
                byte[] dec = loki.DecryptBlock(enc);

                // Если алгоритм не потокобезопасен, здесь будет каша
                Assert.Equal(baseBlock, dec);
            });
        }

        // ==========================================
        // 4. БЕНЧМАРК АЛГОРИТМОВ (КТО БЫСТРЕЕ?)
        // ==========================================
        [Fact]
        public void Grand_Prix_Algorithm_Benchmark()
        {
            // Сравниваем производительность на 1 МБ данных
            int dataSize = 1024 * 1024; // 1 MB
            byte[] data = new byte[dataSize];
            new Random().NextBytes(data); // Random data is fair

            _output.WriteLine($"--- BENCHMARK (1 MB Processing) ---");

            // 1. RC4
            long tRC4 = Measure(() => 
            {
                var rc4 = new RC4Algorithm(new byte[]{1,2,3});
                rc4.ProcessData(data);
            });
            _output.WriteLine($"RC4:        {tRC4} ms");

            // 2. DES (ECB Simulation loop)
            long tDES = Measure(() =>
            {
                var des = new DESAlgorithm();
                des.SetRoundKeys(new byte[8]);
                // Эмуляция ECB цикла вручную для чистоты замера алгоритма (без накладных расходов Context)
                byte[] block = new byte[8];
                for(int i=0; i<dataSize; i+=8) des.EncryptBlock(block);
            });
            _output.WriteLine($"DES:        {tDES} ms");

            // 3. TripleDES
            long t3DES = Measure(() =>
            {
                var tdes = new TripleDESAlgorithm();
                tdes.SetRoundKeys(new byte[24]);
                byte[] block = new byte[8];
                for(int i=0; i<dataSize; i+=8) tdes.EncryptBlock(block);
            });
            _output.WriteLine($"TripleDES:  {t3DES} ms");

            // 4. LOKI97
            long tLOKI = Measure(() =>
            {
                var loki = new LOKI97Algorithm();
                loki.SetRoundKeys(new byte[16]);
                byte[] block = new byte[16];
                for(int i=0; i<dataSize; i+=16) loki.EncryptBlock(block);
            });
            _output.WriteLine($"LOKI97:     {tLOKI} ms");

            // 5. Rijndael
            long tAES = Measure(() =>
            {
                var aes = new RijndaelCipher(KeySize.K128, BlockSize.B128);
                aes.SetRoundKeys(new byte[16]);
                byte[] block = new byte[16];
                for(int i=0; i<dataSize; i+=16) aes.EncryptBlock(block);
            });
            _output.WriteLine($"Rijndael:   {tAES} ms");

            // Assertions (RC4 обычно самый быстрый, 3DES самый медленный)
            Assert.True(tRC4 < t3DES, "RC4 should be faster than 3DES");
        }

        // ==========================================
        // HELPERS
        // ==========================================

        private long Measure(Action action)
        {
            // Прогрев
            action(); 
            
            var sw = Stopwatch.StartNew();
            action();
            sw.Stop();
            return sw.ElapsedMilliseconds;
        }

        private int CountDifferentBits(byte[] a, byte[] b)
        {
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                byte xor = (byte)(a[i] ^ b[i]);
                while (xor != 0)
                {
                    if ((xor & 1) != 0) diff++;
                    xor >>= 1;
                }
            }
            return diff;
        }
    }
}