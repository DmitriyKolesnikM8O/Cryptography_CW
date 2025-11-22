using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;
using CryptoLib.Rijndael.Interfaces;
using CryptoLib.Rijndael.Modes;
using System.Security.Cryptography;
using System.Text;

namespace CryptoDemo.Demos
{
    public static class Task3_FileEncryptionDemo
    {
        public static async Task Run()
        {

            string outputDirectory = "DemoOutput";
            Directory.CreateDirectory(outputDirectory);
            string reportPath = "DemonstrationReport.txt";
            var report = new StringBuilder();

            
            Action<string> log = (message) =>
            {
                Console.WriteLine(message);
                report.AppendLine(message);
            };

            log("--- Комплексная демонстрация шифрования (Задание 3) ---");
            log("Будут протестированы все комбинации режимов и паддингов.");
            
            string originalText = "Это тестовый текст для демонстрации работы алгоритма Rijndael. " +
                                  "Длина этого текста специально подобрана так, чтобы проверить работу паддинга.";
            
            var cipherModes = (CryptoLib.Rijndael.Modes.CipherMode[])Enum.GetValues(typeof(CryptoLib.Rijndael.Modes.CipherMode));
            var paddingModes = (CryptoLib.Rijndael.Modes.PaddingMode[])Enum.GetValues(typeof(CryptoLib.Rijndael.Modes.PaddingMode));

            var rijndael = new RijndaelCipher(KeySize.K256, BlockSize.B128);
            var key = new byte[32]; // 256 бит
            RandomNumberGenerator.Fill(key);

            log($"\n[INFO] Исходный ключ (256-бит): {BitConverter.ToString(key).Replace("-", "")}");
            log($"[INFO] Исходный текст: \"{originalText}\"");
            
            int totalCombinations = 0;
            int passedTests = 0;

            foreach (var mode in cipherModes)
            {
                foreach (var padding in paddingModes)
                {
                    totalCombinations++;
                    log($"\n{new string('=', 70)}");
                    bool testPassed = await RunSingleTest(rijndael, key, mode, padding, originalText, log, outputDirectory);
                    if (testPassed)
                    {
                        passedTests++;
                    }
                }
            }

            
            log($"\n{new string('=', 70)}");
            log("\n--- Демонстрация с кастомным неприводимым полиномом ---");
            
            // 0x8D - это x^8 + x^7 + x^3 + x^2 + 1
            byte customPolynomial = 0x8D; 
            log($"[INFO] Выбран альтернативный неприводимый полином: 0x{customPolynomial:X2}");

            // Создаем два экземпляра Rijndael с ОДИНАКОВЫМ кастомным полиномом
            var rijndaelCustomEncrypt = new RijndaelCipher(KeySize.K128, BlockSize.B128, customPolynomial);
            var rijndaelCustomDecrypt = new RijndaelCipher(KeySize.K128, BlockSize.B128, customPolynomial);

            // Создаем ключ и IV для этого теста
            var customKey = new byte[16];
            RandomNumberGenerator.Fill(customKey);

            
            var originalBlock = Encoding.UTF8.GetBytes("This is 16 bytes");
            
            rijndaelCustomEncrypt.SetRoundKeys(customKey);
            byte[] encryptedBlock = rijndaelCustomEncrypt.EncryptBlock(originalBlock);

            rijndaelCustomDecrypt.SetRoundKeys(customKey);
            byte[] decryptedBlock = rijndaelCustomDecrypt.DecryptBlock(encryptedBlock);
            
            log($"[INFO] Исходный блок (HEX): {BitConverter.ToString(originalBlock).Replace("-", " ")}");
            log($"[INFO] Зашифрованный (HEX):  {BitConverter.ToString(encryptedBlock).Replace("-", " ")}");
            log($"[INFO] Расшифрованный (HEX): {BitConverter.ToString(decryptedBlock).Replace("-", " ")}");
            
            if (originalBlock.SequenceEqual(decryptedBlock))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                log("[PASS] Демонстрация успешна! Блоки совпадают.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                log("[FAIL] Демонстрация провалена! Блоки не совпадают.");
            }
            Console.ResetColor();
            
            log($"\n{new string('=', 70)}");
            log("\n--- ИТОГИ ТЕСТИРОВАНИЯ ---");
            
            
            int streamModes = cipherModes.Count(m => m == CryptoLib.Rijndael.Modes.CipherMode.CTR || m == CryptoLib.Rijndael.Modes.CipherMode.OFB || m == CryptoLib.Rijndael.Modes.CipherMode.CFB);
            int paddingsToSkip = paddingModes.Length - 1;
            int skippedTests = streamModes * paddingsToSkip;

            
            if (passedTests == totalCombinations)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                log($"Все {passedTests - skippedTests} значащих тестов успешно пройдены! ({skippedTests} комбинаций пропущено как нерелевантные)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                log($"Пройдено {passedTests} из {totalCombinations} тестов. Есть ошибки!");
            }
            Console.ResetColor();
            
            await File.WriteAllTextAsync(reportPath, report.ToString(), Encoding.UTF8);
            Console.WriteLine($"\n[INFO] Полный отчет сохранен в файл: {Path.GetFullPath(reportPath)}");
        }
        
        /// <summary>
        /// Выполняет один цикл шифрования/дешифрования для заданной комбинации параметров.
        /// </summary>
        private static async Task<bool> RunSingleTest(
            ISymmetricCipher algorithm,
            byte[] key,
            CryptoLib.Rijndael.Modes.CipherMode mode,
            CryptoLib.Rijndael.Modes.PaddingMode padding,
            string originalText,
            Action<string> log,
            string outputDirectory)
        {
            log($"[*] ТЕСТ: Режим = {mode}, Паддинг = {padding}");
            
            bool isStreamMode = mode == CryptoLib.Rijndael.Modes.CipherMode.CTR || 
                                mode == CryptoLib.Rijndael.Modes.CipherMode.OFB || 
                                mode == CryptoLib.Rijndael.Modes.CipherMode.CFB;


            if (isStreamMode && padding != CryptoLib.Rijndael.Modes.PaddingMode.Zeros)
            {
                log("[INFO] Потоковые режимы не используют паддинг. Комбинация пропускается.");
                return true;
            }
            
            string tempFilePrefix = $"{mode}_{padding}";
            string plaintextFile = Path.Combine(outputDirectory, $"{tempFilePrefix}_plaintext.txt");
            string ciphertextFile = Path.Combine(outputDirectory, $"{tempFilePrefix}_ciphertext.bin");
            string decryptedFile = Path.Combine(outputDirectory, $"{tempFilePrefix}_decrypted.txt");
            
            try
            {
                await File.WriteAllTextAsync(plaintextFile, originalText, Encoding.UTF8);

                var iv = new byte[algorithm.BlockSize];
                RandomNumberGenerator.Fill(iv);
                log($"[INFO] IV: {BitConverter.ToString(iv).Replace("-", "")}");

                
                var context = new CipherContext(algorithm, key, mode, padding, iv);
                await context.EncryptAsync(plaintextFile, ciphertextFile);
                log($"[ACTION] Шифрование завершено.");

                byte[] ciphertextBytes = await File.ReadAllBytesAsync(ciphertextFile);
                log($"[INFO] Шифротекст (HEX): {BitConverter.ToString(ciphertextBytes).Replace("-", " ")}");

                
                var decryptContext = new CipherContext(algorithm, key, mode, padding, iv);
                await decryptContext.DecryptAsync(ciphertextFile, decryptedFile);
                log($"[ACTION] Дешифрование завершено.");

                
                byte[] originalBytes = await File.ReadAllBytesAsync(plaintextFile);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);

                bool success;
                if (padding == CryptoLib.Rijndael.Modes.PaddingMode.Zeros && !isStreamMode)
                {
                    log("[INFO] Для Zeros паддинга выполняется проверка по исходной длине, т.к. паддинg необратим.");
                    if (decryptedBytes.Length < originalBytes.Length)
                    {
                        success = false;
                    }
                    else
                    {
                        
                        success = decryptedBytes.Take(originalBytes.Length).SequenceEqual(originalBytes);
                    }
                }
                else
                {
                    
                    success = originalBytes.SequenceEqual(decryptedBytes);
                }

                if (success)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    log("[PASS] Проверка успешна! Данные совпадают.");
                    Console.ResetColor();
                    return true;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    log("[FAIL] ПРОВЕРКА ПРОВАЛЕНА! Данные не совпадают.");
                    Console.ResetColor();
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                log($"[FAIL] Во время теста произошло исключение: {ex.Message}");
                Console.ResetColor();
                return false;
            }
            
        }
    }
}