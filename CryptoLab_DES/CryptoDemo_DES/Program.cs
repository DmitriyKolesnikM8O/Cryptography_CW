using CryptoLib.DES.Modes;

namespace CryptoDemo
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=== CryptoLab DEMO - DES/DEAL Algorithms ===");
            
            while (true)
            {
                Console.WriteLine("\nВыберите действие:");
                Console.WriteLine("1. Демонстрация DES");
                Console.WriteLine("2. Демонстрация DEAL");
                Console.WriteLine("3. Шифрование файла");
                Console.WriteLine("4. Дешифрование файла");
                Console.WriteLine("0. Выход");
                
                var choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await DemonstrateDES();
                        break;
                    case "2":
                        await DemonstrateDEAL();
                        break;
                    case "3":
                        await EncryptFile();
                        break;
                    case "4":
                        await DecryptFile();
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Неверный выбор");
                        break;
                }
            }
        }
        
        
        static async Task DemonstrateDES()
        {
            Console.WriteLine("\n=== Демонстрация DES ===");
            byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            byte[] iv = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] testData = { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 
            };
            Console.WriteLine("Ключ: " + BitConverter.ToString(key));
            Console.WriteLine("Данные: " + BitConverter.ToString(testData));
            var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta };
            foreach (var mode in modes)
            {
                Console.WriteLine($"\n--- Режим {mode} ---");
                try
                {
                    byte[]? ivForMode = mode == CipherMode.ECB ? null : iv;
                    var context = new CipherContext(key, mode, PaddingMode.PKCS7, ivForMode, new KeyValuePair<string, object>("Algorithm", "DES"));
                    byte[] encrypted = new byte[32];
                    await context.EncryptAsync(testData, encrypted);
                    byte[] decrypted = new byte[32];
                    await context.DecryptAsync(encrypted, decrypted);
                    bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                    Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}");
                    Console.WriteLine($"Зашифровано: {BitConverter.ToString(encrypted.Take(16).ToArray())}");
                }
                catch (Exception ex) { Console.WriteLine($"Ошибка: {ex.Message}"); }
            }
        }
        
        static async Task DemonstrateDEAL()
        {
            Console.WriteLine("\n=== Демонстрация DEAL ===");
            byte[] key128 = { 
                0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
            };
            byte[] iv = { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };
            byte[] testData = { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
            };
            Console.WriteLine("Ключ (128-bit): " + BitConverter.ToString(key128));
            Console.WriteLine("Данные: " + BitConverter.ToString(testData));
            var modes = new[] { CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta };
            foreach (var mode in modes)
            {
                Console.WriteLine($"\n--- DEAL-128 Режим {mode} ---");
                try
                {
                    byte[]? ivForMode = mode == CipherMode.ECB ? null : iv;
                    
                    
                    var encryptContext = new CipherContext(key128, mode, PaddingMode.PKCS7, ivForMode, new KeyValuePair<string, object>("Algorithm", "DEAL"));
                    byte[] encrypted = new byte[48];
                    await encryptContext.EncryptAsync(testData, encrypted);
                    
                    
                    var decryptContext = new CipherContext(key128, mode, PaddingMode.PKCS7, ivForMode, new KeyValuePair<string, object>("Algorithm", "DEAL"));
                    byte[] decrypted = new byte[48];
                    await decryptContext.DecryptAsync(encrypted, decrypted);
                    
                    bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                    Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}");
                    Console.WriteLine($"Зашифровано: {BitConverter.ToString(encrypted.Take(32).ToArray())}");
                }
                catch (Exception ex) { Console.WriteLine($"Ошибка: {ex.Message}"); }
            }
        }
        
        
        static async Task EncryptFile()
        {
            Console.WriteLine("\n=== Шифрование файла ===");
            try
            {
                Console.Write("Введите путь к исходному файлу: ");
                string? inputFile = Console.ReadLine();
                if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
                {
                    Console.WriteLine("Ошибка: Исходный файл не существует!");
                    return;
                }

                Console.Write("Введите путь для зашифрованного файла: ");
                string? outputFile = Console.ReadLine();
                if (string.IsNullOrEmpty(outputFile))
                {
                    Console.WriteLine("Ошибка: Не указан путь для зашифрованного файла.");
                    return;
                }

                (string algoName, byte[] key) = SelectAlgorithmAndGenerateKey();
                (CipherMode mode, byte[]? iv) = SelectModeAndGenerateIV(algoName);

                var padding = (mode == CipherMode.CFB || mode == CipherMode.OFB || mode == CipherMode.CTR) 
                    ? PaddingMode.Zeros : PaddingMode.PKCS7;

                var context = new CipherContext(key, mode, padding, iv, new KeyValuePair<string, object>("Algorithm", algoName));
                
                Console.WriteLine("Начинаю шифрование...");

                
                await using (var inputFileStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                await using (var outputFileStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    
                    if (iv != null)
                    {
                        await outputFileStream.WriteAsync(iv, 0, iv.Length);
                    }
                    
                    await context.EncryptAsync(inputFileStream, outputFileStream);
                }
                
                Console.WriteLine($"\nФайл успешно зашифрован: {outputFile}");
                Console.WriteLine("--- СОХРАНИТЕ ЭТИ ДАННЫЕ ДЛЯ ДЕШИФРОВАНИЯ ---");
                Console.WriteLine($"Алгоритм: {algoName}");
                Console.WriteLine($"Режим: {mode}");
                Console.WriteLine($"Ключ (Hex): {BitConverter.ToString(key)}");
                
                Console.WriteLine("--------------------------------------------");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при шифровании: {ex.Message}");
            }
        }

        static async Task DecryptFile()
        {
            Console.WriteLine("\n=== Дешифрование файла ===");
            try
            {
                Console.Write("Введите путь к зашифрованному файлу: ");
                string? inputFile = Console.ReadLine();
                if (string.IsNullOrEmpty(inputFile) || !File.Exists(inputFile))
                {
                    Console.WriteLine("Ошибка: Зашифрованный файл не существует!");
                    return;
                }

                Console.Write("Введите путь для расшифрованного файла: ");
                string? outputFile = Console.ReadLine();
                if (string.IsNullOrEmpty(outputFile))
                {
                    Console.WriteLine("Ошибка: Не указан путь для расшифрованного файла.");
                    return;
                }
                
                Console.Write("Введите алгоритм (DES/DEAL): ");
                string? algorithm = Console.ReadLine()?.ToUpper();

                Console.Write("Введите режим шифрования: ");
                if (!Enum.TryParse<CipherMode>(Console.ReadLine(), true, out var mode))
                {
                    Console.WriteLine("Ошибка: Неверный режим шифрования.");
                    return;
                }

                Console.Write("Введите ключ (Hex строка): ");
                byte[] key = HexStringToByteArray(Console.ReadLine() ?? "");

                
                byte[]? iv = null;
                var padding = (mode == CipherMode.CFB || mode == CipherMode.OFB || mode == CipherMode.CTR) 
                    ? PaddingMode.Zeros : PaddingMode.PKCS7;

                await using (var inputFileStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                await using (var outputFileStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    
                    if (mode != CipherMode.ECB)
                    {
                        
                        int ivSize = (algorithm == "DES") ? 8 : 16;
                        iv = new byte[ivSize];
                        int bytesRead = await inputFileStream.ReadAsync(iv, 0, iv.Length);
                        if (bytesRead < iv.Length)
                        {
                            throw new IOException("Не удалось прочитать полный IV из зашифрованного файла.");
                        }
                    }
                    
                    
                    var context = new CipherContext(key, mode, padding, iv, new KeyValuePair<string, object>("Algorithm", algorithm ?? "DES"));
                    
                    
                    Console.WriteLine("Начинаю дешифрование...");
                    await context.DecryptAsync(inputFileStream, outputFileStream);
                }
                
                Console.WriteLine($"Файл успешно расшифрован: {outputFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при дешифровании: {ex.Message}");
            }
        }

        static (string, byte[]) SelectAlgorithmAndGenerateKey()
        {
            Console.WriteLine("Выберите алгоритм:");
            Console.WriteLine("1. DES (64-bit ключ)");
            Console.WriteLine("2. DEAL-128 (128-bit ключ)");
            Console.WriteLine("3. DEAL-192 (192-bit ключ)");
            Console.WriteLine("4. DEAL-256 (256-bit ключ)");
            string? algoChoice = Console.ReadLine();

            Random rnd = new Random();
            return algoChoice switch
            {
                "1" => ("DES", Enumerable.Range(0, 8).Select(_ => (byte)rnd.Next(256)).ToArray()),
                "2" => ("DEAL", Enumerable.Range(0, 16).Select(_ => (byte)rnd.Next(256)).ToArray()),
                "3" => ("DEAL", Enumerable.Range(0, 24).Select(_ => (byte)rnd.Next(256)).ToArray()),
                "4" => ("DEAL", Enumerable.Range(0, 32).Select(_ => (byte)rnd.Next(256)).ToArray()),
                _ => throw new ArgumentException("Неверный выбор алгоритма")
            };
        }

        static (CipherMode, byte[]?) SelectModeAndGenerateIV(string algoName)
        {
            Console.WriteLine("Выберите режим шифрования:");
            var modes = Enum.GetValues<CipherMode>();
            for (int i = 0; i < modes.Length; i++)
            {
                Console.WriteLine($"{i + 1}. {modes[i]}");
            }
            string? modeChoice = Console.ReadLine();
            CipherMode mode = modes[int.Parse(modeChoice ?? "1") - 1];

            byte[]? iv = null;
            if (mode != CipherMode.ECB)
            {
                Random rnd = new Random();
                int ivSize = algoName == "DES" ? 8 : 16;
                iv = Enumerable.Range(0, ivSize).Select(_ => (byte)rnd.Next(256)).ToArray();
            }
            return (mode, iv);
        }
        
        static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "").Replace(":", "").Trim();
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have an even number of digits");
            
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return result;
        }
    }
}