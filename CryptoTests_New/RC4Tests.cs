using Xunit;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using CryptoLib.New.Algorithms.RC4;

namespace CryptoTests_New
{
    public class RC4Tests
    {
        [Fact]
        public void RC4_WikipediaVector_ShouldMatch()
        {
            // Тестовые вектора из Википедии
            // Key: "Key"
            // Plaintext: "Plaintext"
            // Ciphertext: BB F3 16 E8 D9 40 AF 0A D3

            byte[] key = Encoding.ASCII.GetBytes("Key");
            byte[] plaintext = Encoding.ASCII.GetBytes("Plaintext");
            byte[] expectedCipher = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];

            var rc4 = new RC4Algorithm(key);
            byte[] actualCipher = rc4.ProcessData(plaintext);

            Assert.Equal(expectedCipher, actualCipher);
        }

        [Fact]
        public void RC4_EncryptDecrypt_ShouldReturnOriginal()
        {
            byte[] key = Encoding.UTF8.GetBytes("SecretKey123");
            string originalText = "Hello RC4 World!";
            byte[] data = Encoding.UTF8.GetBytes(originalText);

            var rc4Encrypt = new RC4Algorithm(key);
            byte[] encrypted = rc4Encrypt.ProcessData(data);

            var rc4Decrypt = new RC4Algorithm(key);
            byte[] decrypted = rc4Decrypt.ProcessData(encrypted);

            string resultText = Encoding.UTF8.GetString(decrypted);
            Assert.Equal(originalText, resultText);
        }

        public static IEnumerable<object[]> TestDataGenerator()
        {
            string[] filePaths = 
            {
                "TestData/text.txt",
                "TestData/image.jpg"
            };

            foreach (var filePath in filePaths)
            {
                yield return new object[] { filePath };
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task RC4_FileAsync_ShouldEncryptDecrypt(string inputFilePath)
        {
            if (!File.Exists(inputFilePath)) return;

            byte[] key = Encoding.UTF8.GetBytes("FileEncryptionKey_2025");
            
            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                var rc4Encrypt = new RC4Algorithm(key);
                await rc4Encrypt.ProcessFileAsync(inputFilePath, encryptedFile);


                var rc4Decrypt = new RC4Algorithm(key);
                await rc4Decrypt.ProcessFileAsync(encryptedFile, decryptedFile);

                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);

                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
            }
        }
    }
}