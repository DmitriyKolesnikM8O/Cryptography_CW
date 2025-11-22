using System.Numerics;
using CryptoLib.RSA.Attacks;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.RSA.Models;

namespace CryptoDemo.Demos
{
    public static class Task4_WienersAttackDemo
    {
        public static void Run()
        {
            Console.WriteLine("--- Демонстрация Задания 4: Атака Винера на RSA ---");

            // p = 379, q = 239
            // N = p * q = 90581
            // phi = (p-1)*(q-1) = 89964
            // d = 5 (секретный ключ, который мы ищем)
            // e = 17993 (e*d ≡ 1 mod phi)
            var weakPublicKey = new RsaPublicKey(
                E: 17993,
                N: 90581
            );
            var actual_d = new BigInteger(5);

            Console.WriteLine("Используется уязвимый открытый ключ (из учебника):");
            Console.WriteLine($"   E = {weakPublicKey.E}");
            Console.WriteLine($"   N = {weakPublicKey.N}");
            Console.WriteLine($"   (Настоящий секретный ключ для проверки d = {actual_d})");


            Console.WriteLine("\n[1] Запуск атаки Винера...");
            IWienersAttackService attackService = new WienersAttackService();
            var result = attackService.Attack(weakPublicKey);

            Console.WriteLine("\n[2] Вычисленные подходящие дроби (k/d):");
            foreach (var fraction in result.Convergents)
            {
                Console.WriteLine($"   {fraction.NumeratorK} / {fraction.DenominatorD}");
                
                if (fraction.DenominatorD == result.FoundD)
                {
                    break;
                }
            }

            
            Console.WriteLine("\n[3] Результат атаки:");
            if (result.IsSuccessful)
            {
                Console.WriteLine("   Статус: УСПЕХ!");
                Console.WriteLine($"   Найденный секретный ключ (d): {result.FoundD}");
                Console.WriteLine($"   Восстановленная функция Эйлера (phi): {result.FoundPhi}");

                if (result.FoundD == actual_d)
                {
                    Console.WriteLine("   Проверка: Найденный ключ совпадает с исходным секретным ключом!");
                }
            }
            else
            {
                Console.WriteLine("   Статус: Атака не удалась. Это указывает на ошибку в алгоритме.");
            }
            
        }
    }
}