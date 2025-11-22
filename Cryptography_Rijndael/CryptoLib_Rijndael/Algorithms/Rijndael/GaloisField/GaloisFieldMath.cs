using System.Numerics;
using System.Security.Cryptography; // RandomNumberGeneration

namespace CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField
{
    /// <summary>
    /// Stateless-сервис для выполнения арифметических операций в конечном поле Галуа GF(2^8).
    /// Элементы поля представляются байтами.
    /// </summary>
    public static class GaloisFieldMath
    {
        /// <summary>
        /// Сложение двух элементов в поле GF(2^8). Эквивалентно операции XOR.
        /// </summary>
        public static byte Add(byte a, byte b) => (byte)(a ^ b);

        /// <summary>
        /// Умножение двух элементов в поле GF(2^8) по заданному неприводимому полиному.
        /// Это каноническая, исправленная реализация.
        /// </summary>
        public static byte Multiply(byte a, byte b, byte module)
        {
            byte result = 0;
            byte hi_bit_set;
            while (b > 0)
            {
                if ((b & 1) == 1)
                    result ^= a;

                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                    a ^= module;

                b >>= 1;
            }
            return result;
        }



        /// <summary>
        /// Находит обратный элемент для заданного элемента в поле GF(2^8)
        /// по Малой теореме Ферма: a⁻¹ = a^(254).
        /// </summary>
        public static byte Inverse(byte element, byte module)
        {
            if (element == 0) return 0;
            return Power(element, 254, module);
        }

        /// <summary>
        /// Возводит элемент поля в степень по заданному модулю
        /// методом двоичного разложения (Exponentiation by Squaring).
        /// </summary>
        private static byte Power(byte baseValue, int exponent, byte module)
        {
            byte result = 1;
            while (exponent > 0)
            {
                if ((exponent & 1) == 1)
                    result = Multiply(result, baseValue, module);

                baseValue = Multiply(baseValue, baseValue, module);
                exponent >>= 1;
            }
            return result;
        }

        /// <summary>
        /// Проверяет, является ли полином 8-й степени неприводимым над полем GF(2).
        /// </summary>
        public static bool IsIrreducible(byte polynomialByte)
        {
            
            if (polynomialByte == 0) return false;
                        
            int p = 0x100 | polynomialByte; 

            if ((p & 1) == 0) return false;
            
            int[] irreducibleFactors = {
                0b11,       // x+1 (степень 1)
                0b111,      // x²+x+1 (степень 2)
                0b1011,     // x³+x+1 (степень 3)
                0b1101,     // x³+x²+1 (степень 3)
                0b10011,    // x⁴+x+1 (степень 4)
                0b11001,    // x⁴+x³+1 (степень 4)
                0b11111     // x⁴+x³+x²+x+1 (степень 4)
            };

            foreach (var factor in irreducibleFactors)
            {
                
                int remainder = GetRemainder(p, factor);
                // Console.WriteLine($"PolynomialByte: {polynomialByte} Remainder: {remainder} , Factor: {factor}");
                
                if (remainder == 0)
                {
                    return false;
                }
            }

            return true;
        }


        /// <summary>
        /// Находит все неприводимые двоичные полиномы 8-й степени.
        /// </summary>
        public static List<byte> FindAllIrreduciblePolynomials()
        {
            var polynomials = new List<byte>();
            for (int i = 0; i <= 255; i++)
            {
                if (IsIrreducible((byte)i)) polynomials.Add((byte)i);
            }
            return polynomials;
        }


        /// <summary>
        /// Выполняет деление полиномов в GF(2) и возвращает остаток.
        /// </summary>
        private static int GetRemainder(int dividend, int divisor)
        {
            if (divisor == 0) throw new DivideByZeroException();

            
            int divisorDegree = GetPolynomialDegree(divisor);
            while (GetPolynomialDegree(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegree(dividend) - divisorDegree;
                dividend ^= divisor << degreeDifference;
            }
            return dividend;
        }


        /// <summary>
        /// Определяет степень полинома (позицию старшего установленного бита).
        /// </summary>
        private static int GetPolynomialDegree(int polynomial)
        {
            for (int i = 31; i >= 0; i--)
            {
                if (((polynomial >> i) & 1) == 1) return i;
            }
            return -1;
        }
        
        #region Polynomial Factorization

        /// <summary>
        /// Выполняет разложение двоичного полинома произвольной степени на неприводимые множители.
        /// Реализует алгоритм Кантора-Цассенхауза.
        /// </summary>
        public static Dictionary<BigInteger, int> FactorizePolynomial(BigInteger polynomial)
        {
            var factors = new Dictionary<BigInteger, int>();
            if (polynomial <= 1) return factors;
            
            while ((polynomial & 1) == 0)
            {
                AddFactor(factors, 2); // 2 - это полином 'x' (0b10)
                polynomial >>= 1;
            }

            FactorizeRecursive(polynomial, factors);
            return factors;
        }

        /// <summary>
        /// Рекурсивно (с помощью стека) раскладывает полином на множители.
        /// </summary>
        /// <param name="polynomial">Полином для разложения.</param>
        /// <param name="factors">Словарь для накопления найденных множителей и их степеней.</param>
        private static void FactorizeRecursive(BigInteger polynomial, Dictionary<BigInteger, int> factors)
        {
            // стэк для имитации рекурсии
            var polynomialsToFactor = new Stack<BigInteger>();
            polynomialsToFactor.Push(polynomial);

            while (polynomialsToFactor.Count > 0)
            {
                BigInteger currentPoly = polynomialsToFactor.Pop();
                if (currentPoly == 1) continue;

                // Если полином неприводим, он является простым множителем.
                // Добавляем его в результат и завершаем эту ветвь рекурсии.
                if (IsIrreducibleBig(currentPoly))
                {
                    AddFactor(factors, currentPoly);
                }
                else
                {
                    BigInteger divisor = FindDivisor(currentPoly);
                    if (divisor == 1 || divisor == currentPoly)
                    {
                        AddFactor(factors, currentPoly);
                    }
                    else
                    {
                        polynomialsToFactor.Push(divisor);
                        polynomialsToFactor.Push(PolynomialDivision(currentPoly, divisor).Quotient);
                    }
                }
            }
        }

        /// <summary>
        /// Находит один нетривиальный делитель полинома p(x).
        /// Исключает неэффективный FindDivisorFallback.
        /// </summary>
        private static BigInteger FindDivisor(BigInteger polynomial)
        {
            // Приводимые полиномы должны иметь степень > 1.
            int n = GetPolynomialDegreeBig(polynomial);
            if (n <= 1) return polynomial;

            var rng = RandomNumberGenerator.Create();
            
            const int MaxAttempts = 200; 

            for (int attempt = 0; attempt < MaxAttempts; attempt++)
            {
                // Генерируем случайный полином a(x) степени < n
                byte[] bytes = new byte[n / 8 + 1];
                rng.GetBytes(bytes);
                BigInteger a = new BigInteger(bytes, isUnsigned: true);
                // Ограничиваем степень
                a %= BigInteger.One << n;
                
                if (a <= 1) continue;

                // Вычисляем x^(2^k) mod p(x) для разных k.
                // Здесь идея Кантора-Цассенхауза:
                // НОД(p(x), a(x)^(2^k) - a(x)) должен быть нетривиальным для некоторых k.
                
                // Нам нужно найти нетривиальный делитель p(x). 
                // Если p(x) - произведение k равностепенных полиномов степени d, 
                // то d*k = n. Мы пробуем k = 1..n/2.
                for (int k = 1; k <= n / 2; k++)
                {
                    // Вычисляем a(x)^(2^k) mod p(x)
                    BigInteger a_power = PolynomialModPower(a, BigInteger.Pow(2, k), polynomial);
                    
                    // НОД(p(x), a(x)^(2^k) + a(x)) = НОД(p(x), a_power ^ a)
                    BigInteger g = PolynomialGcd(polynomial, a_power ^ a); 
                    
                    if (g != 1 && g != polynomial)
                    {
                        return g; // Найден нетривиальный делитель
                    }
                }
            }
    
            return polynomial; 
        }

        /// <summary>
        /// Умножает два полинома по модулю третьего.
        /// </summary>
        private static long PolynomialMultiplyMod(long a, long b, long modulus)
        {
            long result = 0;
            int modDeg = GetPolynomialDegreeBig(modulus);
            if (modDeg < 0) throw new DivideByZeroException();

            while (b != 0)
            {
                if ((b & 1) == 1)
                {
                    result ^= a;
                }

                b >>= 1;

                a <<= 1;

                int aDeg = GetPolynomialDegreeBig(a);
                if (aDeg >= modDeg)
                {
                    int shift = aDeg - modDeg;
                    a ^= modulus << shift;
                }
            }

            int rDeg;
            while ((rDeg = GetPolynomialDegreeBig(result)) >= modDeg)
            {
                int shift = rDeg - modDeg;
                result ^= modulus << shift;
            }

            return result;
        }

        /// <summary>
        /// Добавляет множитель в словарь или инкрементирует его степень, если он уже существует.
        /// </summary>
        /// <param name="factors">Словарь с множителями.</param>
        /// <param name="factor">Найденный множитель для добавления.</param>
        private static void AddFactor(Dictionary<BigInteger, int> factors, BigInteger factor)
        {
            factors.TryGetValue(factor, out int count);
            factors[factor] = count + 1;
        }


        /// <summary>
        /// Выполняет деление полиномов в поле GF(2), представленных как BigInteger.
        /// Реализует стандартный алгоритм деления "в столбик".
        /// </summary>
        /// <param name="dividend">Делимое.</param>
        /// <param name="divisor">Делитель.</param>
        /// <returns>Кортеж, содержащий (Частное, Остаток).</returns>
        private static (BigInteger Quotient, BigInteger Remainder) PolynomialDivision(BigInteger dividend, BigInteger divisor)
        {
            if (divisor.IsZero) throw new DivideByZeroException();
            BigInteger quotient = 0;
            int divisorDegree = GetPolynomialDegreeBig(divisor);

            while (GetPolynomialDegreeBig(dividend) >= divisorDegree)
            {
                int degreeDifference = GetPolynomialDegreeBig(dividend) - divisorDegree;
                quotient ^= BigInteger.One << degreeDifference;
                dividend ^= divisor << degreeDifference;
            }
            return (quotient, dividend);
        }

        /// <summary>
        /// Вычисляет Наибольший Общий Делитель (НОД) для двух полиномов с помощью алгоритма Евклида.
        /// </summary>
        /// <param name="a">Первый полином.</param>
        /// <param name="b">Второй полином.</param>
        /// <returns>НОД для a и b.</returns>
        private static BigInteger PolynomialGcd(BigInteger a, BigInteger b)
        {
            while (!b.IsZero)
            {
                (a, b) = (b, PolynomialDivision(a, b).Remainder);
            }
            return a;
        }

        /// <summary>
        /// Возводит полином в степень по модулю другого полинома.
        /// Использует алгоритм возведения в степень путем двоичного разложения.
        /// </summary>
        /// <param name="baseValue">Основание.</param>
        /// <param name="exponent">Показатель степени.</param>
        /// <param name="modulus">Модуль.</param>
        /// <returns>Результат (baseValue^exponent) mod modulus.</returns>
        private static BigInteger PolynomialModPower(BigInteger baseValue, BigInteger exponent, BigInteger modulus)
        {
            BigInteger result = 1;
            baseValue = PolynomialDivision(baseValue, modulus).Remainder;
            while (exponent > 0)
            {
                if (!exponent.IsEven) // Если текущий бит степени равен 1
                    result = PolynomialMultiplyMod(result, baseValue, modulus);

                baseValue = PolynomialMultiplyMod(baseValue, baseValue, modulus);
                exponent >>= 1;
            }
            return result;
        }

        /// <summary>
        /// Умножает два полинома по модулю третьего.
        /// </summary>
        /// <param name="a">Первый множитель.</param>
        /// <param name="b">Второй множитель.</param>
        /// <param name="modulus">Модуль.</param>
        /// <returns>Результат (a*b) mod modulus.</returns>
        private static BigInteger PolynomialMultiplyMod(BigInteger a, BigInteger b, BigInteger modulus)
        {
            BigInteger result = 0;
            int modDeg = GetPolynomialDegreeBig(modulus);
            if (modDeg < 0) throw new DivideByZeroException();

            while (b > 0)
            {
                if (!b.IsEven) // b & 1 != 0
                {
                    result ^= a;
                }
                b >>= 1;
                a <<= 1;
                if (GetPolynomialDegreeBig(a) >= modDeg)
                {
                    a ^= modulus;
                }
            }
            return result;
        }

        /// <summary>
        /// Проверяет полином на неприводимость с помощью теста Бен-Ора.
        /// Полином p(x) степени d неприводим <=> НОД(p(x), x^(2^i) - x) = 1 для всех i = 1..d/2.
        /// </summary>
        /// <param name="polynomial">Полином для проверки.</param>
        /// <returns>True, если полином неприводим, иначе false.</returns>
        private static bool IsIrreducibleBig(BigInteger polynomial)
        {
            if (polynomial <= 1) return false;
            int degree = GetPolynomialDegreeBig(polynomial);
            BigInteger h = 2; // h(x) = x

            for (int i = 1; i <= degree / 2; i++)
            {
                h = PolynomialModPower(h, 2, polynomial); // h = h^2 mod p(x) => h = x^(2^i) mod p(x)
                BigInteger gcd = PolynomialGcd(polynomial, h ^ 0b10);
                if (gcd != 1)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Определяет степень полинома (позицию старшего установленного бита).
        /// </summary>
        /// <param name="polynomial">Полином.</param>
        /// <returns>Степень полинома. Возвращает -1 для нулевого полинома.</returns>
        private static int GetPolynomialDegreeBig(BigInteger polynomial)
        {
            if (polynomial.IsZero) return -1;
            // GetBitLength() возвращает позицию старшего бита + 1
            return (int)polynomial.GetBitLength() - 1;
        }

        #endregion
    }
}