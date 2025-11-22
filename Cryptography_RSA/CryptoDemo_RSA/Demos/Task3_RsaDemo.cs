using System.Numerics;
using CryptoLib.RSA.Enums;
using CryptoLib.RSA.RSA;

namespace CryptoDemo.Demos
{
    public static class Task3_RsaDemo
    {
        public static void Run()
        {
            Console.WriteLine("--- Демонстрация Задания 3: RSA Шифрование ---");

            
            
            var testType = PrimalityTestType.MillerRabin;
            var probability = 0.9999;
            var bitLength = 256;

            Console.WriteLine($"Настройки: Тест={testType}, Вероятность={probability}, Битность p/q={bitLength}");
            Console.WriteLine("\n[1] Создание сервиса RSA...");
            IRsaService rsaService = new RsaService(testType, probability, bitLength);

            // Генерация ключевой пары
            Console.WriteLine("[2] Генерация ключевой пары (может занять несколько секунд)...");
            var keyPair = rsaService.GenerateKeyPair();
            Console.WriteLine("Ключи успешно сгенерированы!");
            Console.WriteLine($"   Открытый ключ (E): {keyPair.PublicKey.E}");
            Console.WriteLine($"   Закрытый ключ (D): {keyPair.PrivateKey.D}");
            Console.WriteLine($"   Модуль (N): {keyPair.PublicKey.N}");

            // Шифрование
            BigInteger message = new BigInteger(123456789012345);
            Console.WriteLine($"\n[3] Шифрование сообщения: {message}");
            var encryptedMessage = rsaService.Encrypt(message, keyPair.PublicKey);
            Console.WriteLine($"   Зашифрованное сообщение (C): {encryptedMessage}");

            // Дешифрование
            Console.WriteLine("\n[4] Дешифрование сообщения...");
            var decryptedMessage = rsaService.Decrypt(encryptedMessage, keyPair.PrivateKey);
            Console.WriteLine($"   Расшифрованное сообщение: {decryptedMessage}");

            // Проверка
            Console.WriteLine("\n[5] Проверка...");
            if (message == decryptedMessage)
            {
                Console.WriteLine("УСПЕХ: Исходное и расшифрованное сообщения совпадают!");
            }
            else
            {
                Console.WriteLine("ОШИБКА: Сообщения не совпадают!");
            }
            Console.WriteLine("--- Конец демонстрации Задания 3 ---\n");
        }
    }
}