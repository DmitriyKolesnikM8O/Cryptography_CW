using System.Numerics;
using CryptoLib.RSA.Attacks.Models;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.RSA.Models;

namespace CryptoLib.RSA.Attacks
{
    /// <summary>
    /// Реализация сервиса для выполнения атаки Винера на уязвимые ключи RSA.
    /// Атака эффективна, если секретная экспонента d мала (d < (1/3) * N^(1/4)).
    /// </summary>
    public class WienersAttackService : IWienersAttackService
    {
        /// <summary>
        /// Выполняет атаку Винера, пытаясь найти секретный ключ d
        /// через разложение дроби e/N в непрерывную дробь.
        /// </summary>
        public WienersAttackResult Attack(RsaPublicKey publicKey)
        {
            var e = publicKey.E;
            var n = publicKey.N;
            var convergents = new List<ContinuedFraction>();

            // Итеративное вычисление подходящих дробей для e/n
            BigInteger a = e;
            BigInteger b = n;
            // Начальные значения для итеративного вычисления числителей (k) и знаменателей (d)
            BigInteger prev_k = 0, k = 1;
            BigInteger prev_d = 1, d = 0;

            while (b != 0)
            {
                var quotient = a / b;
                (a, b) = (b, a % b);

                // Вычисляем следующую подходящую дробь k_i/d_i = q_i * k_{i-1} + k_{i-2} / q_i * d_{i-1} + d_{i-2}
                BigInteger next_k = quotient * k + prev_k;
                BigInteger next_d = quotient * d + prev_d;
                (prev_k, k) = (k, next_k);
                (prev_d, d) = (d, next_d);
                
                var currentFraction = new ContinuedFraction(k, d);
                convergents.Add(currentFraction);

                // Проверка каждого кандидата k/d
                // Пропускаем первую дробь (0/1) и дроби с четным знаменателем (d)
                if (k == 0 || d == 0 || d % 2 == 0)
                {
                    continue;
                }

                // Вычисляем предполагаемую phi(N) из соотношения e*d - k*phi = 1
                // Отсюда phi = (e*d - 1) / k
                var ed_minus_1 = e * d - 1;
                if (ed_minus_1 % k != 0) continue;
                var phi = ed_minus_1 / k;

                // Решаем квадратное уравнение x^2 - (N - phi + 1)x + N = 0
                // Его корни p и q должны быть целыми числами.
                // Коэффициент при x равен p+q = N - phi + 1
                var s = n - phi + 1;
                var discriminant = s * s - 4 * n;

                if (discriminant >= 0 && IsPerfectSquare(discriminant, out var sqrtDiscriminant))
                {
                    if ((s + sqrtDiscriminant) % 2 == 0)
                    {
                        return new WienersAttackResult(true, d, phi, convergents);
                    }
                }
            }
            
            return new WienersAttackResult(false, null, null, convergents);
        }

        /// <summary>
        /// Проверяет, является ли число идеальным квадратом.
        /// </summary>
        /// <param name="n">Проверяемое число.</param>
        /// <param name="root">Выходной параметр для корня, если он целочисленный.</param>
        /// <returns>true, если n - идеальный квадрат.</returns>
        private static bool IsPerfectSquare(BigInteger n, out BigInteger root)
        {
            if (n < 0) { root = 0; return false; }
            if (n == 0) { root = 0; return true; }
            root = Sqrt(n);
            return root * root == n;
        }

        /// <summary>
        /// Вычисляет целочисленный квадратный корень из BigInteger.
        /// </summary>
        private static BigInteger Sqrt(BigInteger n)
        {
            if (n == 0) return 0;
            // Метод мужика, на которого яблоко упало
            BigInteger x = n / 2 + 1;
            BigInteger y = (x + n / x) / 2;
            while (y < x)
            {
                x = y;
                y = (x + n / x) / 2;
            }
            return x;
        }
    }
}