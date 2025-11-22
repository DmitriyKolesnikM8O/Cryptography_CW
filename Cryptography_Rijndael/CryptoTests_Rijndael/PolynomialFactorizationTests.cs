using CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField;
using System.Reflection;
using System.Numerics;

/*
1. GetPolynomialDegreeBig_ShouldReturnCorrectDegree - Тестирует private-метод GetPolynomialDegreeBig, проверяя, что он правильно определяет степень полинома для базовых случаев.
2. PolynomialDivision_ShouldReturnCorrectQuotientAndRemainder - Тестирует private-метод PolynomialDivision, проверяя на известных примерах, что он правильно вычисляет и частное, и остаток.
3. PolynomialGcd_ShouldReturnCorrectGcd - Тестирует private-метод PolynomialGcd, проверяя, что он корректно находит Наибольший Общий Делитель для двух полиномов.
4. IsIrreducibleBig_ShouldWorkCorrectly - Тестирует private-метод IsIrreducibleBig, проверяя его на известных приводимых и неприводимых полиномах.
5. FactorizePolynomial_ShouldFactorizeCorrectly - Проверяет основной публичный метод FactorizePolynomial на классическом примере разложения x^7+1.
6. FactorizePolynomial_WithRepeatedFactors - Проверяет, что алгоритм правильно определяет степень повторяющихся множителей (на примере (x+1)^4).
7. FactorizePolynomial_WithXAsFactor - Проверяет, что алгоритм корректно выделяет множитель x, если полином на него делится.
8. PolynomialDivision_WhenDivisorDegreeIsGreater_ShouldReturnZeroQuotient - Тестирует граничный случай деления: деление полинома на полином большей степени.
9. PolynomialDivision_ByOne_ShouldReturnPolynomialAsQuotient - Тестирует граничный случай деления: деление на единицу.
10. PolynomialDivision_ByItself_ShouldReturnOneAsQuotient - Тестирует граничный случай деления: деление полинома самого на себя.
11. PolynomialDivision_ZeroByPolynomial_ShouldReturnZero - Тестирует граничный случай деления: деление нуля.
12. FactorizePolynomial_OfIrreduciblePolynomial_ShouldReturnItself - Проверяет, что алгоритм правильно останавливается и возвращает сам полином, если он неприводимый.
13. FactorizePolynomial_WithRepeatedIrreducibleFactor - Проверяет разложение полинома, являющегося квадратом неприводимого множителя (случай, отличный от x+1).
14. FactorizePolynomial_WithMixedFactorsAndPowers - Проверяет сложный сценарий разложения полинома, имеющего несколько разных множителей с разными степенями.
15. FactorizePolynomial_ForZeroAndOne_ShouldReturnEmpty - Проверяет граничные случаи: разложение 0 и 1 должно давать пустой результат.
16. FactorizePolynomial_ProductOfTwoIrreduciblesOfSameDegree - Тестирует сложный случай разложения полинома, состоящего из двух разных неприводимых множителей одинаковой степени.
17. FactorizePolynomial_ForLargeIrreduciblePolynomial - Стресс-тест, проверяющий, что алгоритм корректно работает с неприводимым полиномом, степень которого умещается в long.
18. FactorizePolynomial_ForVeryLargeIrreduciblePolynomial_BeyondLong - Стресс-тест, доказывающий, что реализация на BigInteger работает для полиномов со степенью выше 63.
*/


namespace CryptoTests
{
    public class PolynomialFactorizationTests
    {
        private static MethodInfo GetPrivateStaticMethod(string methodName, Type[] types)
        {
            var method = typeof(GaloisFieldMath).GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static, types);
            if (method == null)
                throw new InvalidOperationException($"Не удалось найти приватный метод {methodName}");
            return method;
        }

        // Вспомогательная функция для парсинга двоичных строк в BigInteger
        private BigInteger FromBinaryString(string s)
        {
            BigInteger result = 0;
            foreach (char c in s)
            {
                result <<= 1;
                if (c == '1')
                    result |= 1;
            }
            return result;
        }

        [Theory]
        [InlineData("1011", 3)]
        [InlineData("1", 0)]
        [InlineData("0", -1)]
        [InlineData("100000000", 8)]
        public void GetPolynomialDegreeBig_ShouldReturnCorrectDegree(string polyStr, int expectedDegree)
        {
            BigInteger poly = FromBinaryString(polyStr);

            var method = GetPrivateStaticMethod("GetPolynomialDegreeBig", new[] { typeof(BigInteger) });
            var result = (int)method.Invoke(null, [poly]);
            Assert.Equal(expectedDegree, result);
        }

        [Theory]
        [InlineData("1101101", "101", "11100", "1")]
        [InlineData("1001", "11", "111", "0")]
        public void PolynomialDivision_ShouldReturnCorrectQuotientAndRemainder(string dividendStr, string divisorStr, string expectedQuotientStr, string expectedRemainderStr)
        {
            BigInteger dividend = FromBinaryString(dividendStr);
            BigInteger divisor = FromBinaryString(divisorStr);
            BigInteger expectedQuotient = FromBinaryString(expectedQuotientStr);
            BigInteger expectedRemainder = FromBinaryString(expectedRemainderStr);

            var method = GetPrivateStaticMethod("PolynomialDivision", [typeof(BigInteger), typeof(BigInteger)]);
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });
            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Theory]
        [InlineData("1111", "1001", "11")]
        [InlineData("10011", "101", "1")]
        public void PolynomialGcd_ShouldReturnCorrectGcd(string aStr, string bStr, string expectedGcdStr)
        {
            BigInteger a = FromBinaryString(aStr);
            BigInteger b = FromBinaryString(bStr);
            BigInteger expectedGcd = FromBinaryString(expectedGcdStr);

            var method = GetPrivateStaticMethod("PolynomialGcd", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = (BigInteger)method.Invoke(null, [a, b]);
            Assert.Equal(expectedGcd, result);
        }

        [Theory]
        [InlineData("10011", true)]
        [InlineData("111", true)]
        [InlineData("10001", false)]
        [InlineData("110011", false)]
        public void IsIrreducibleBig_ShouldWorkCorrectly(string polyStr, bool expected)
        {
            BigInteger poly = FromBinaryString(polyStr);

            var method = GetPrivateStaticMethod("IsIrreducibleBig", new[] { typeof(BigInteger) });
            var result = (bool)method.Invoke(null, [poly]);
            Assert.Equal(expected, result);
        }

        [Fact]
        public void FactorizePolynomial_ShouldFactorizeCorrectly()
        {
            BigInteger polynomial = FromBinaryString("10000001");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("11"), 1 },
                { FromBinaryString("1011"), 1 },
                { FromBinaryString("1101"), 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void FactorizePolynomial_WithRepeatedFactors()
        {
            BigInteger polynomial = FromBinaryString("10001");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("11"), 4 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(FromBinaryString("11")));
            Assert.Equal(4, actualFactors[FromBinaryString("11")]);
        }

        [Fact]
        public void FactorizePolynomial_WithXAsFactor()
        {
            BigInteger polynomial = FromBinaryString("10010");
            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { 2, 1 },
                { FromBinaryString("11"), 1 },
                { FromBinaryString("111"), 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);
            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void PolynomialDivision_WhenDivisorDegreeIsGreater_ShouldReturnZeroQuotient()
        {
            // Делим p1(x) = x^3 на p2(x) = x^5
            BigInteger dividend = FromBinaryString("1000"); // x^3
            BigInteger divisor = FromBinaryString("100000"); // x^5

            BigInteger expectedQuotient = 0;
            BigInteger expectedRemainder = dividend; // Остаток должен быть равен самому делимому

            var method = GetPrivateStaticMethod("PolynomialDivision", [typeof(BigInteger), typeof(BigInteger)]);
            var result = ((BigInteger, BigInteger))method.Invoke(null, [dividend, divisor]);

            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ByOne_ShouldReturnPolynomialAsQuotient()
        {
            BigInteger dividend = FromBinaryString("1101101"); // p(x)
            BigInteger divisor = 1;

            BigInteger expectedQuotient = dividend;
            BigInteger expectedRemainder = 0;

            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });

            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ByItself_ShouldReturnOneAsQuotient()
        {
            BigInteger polynomial = FromBinaryString("1101101"); // p(x)

            BigInteger expectedQuotient = 1;
            BigInteger expectedRemainder = 0;

            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { polynomial, polynomial });

            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void PolynomialDivision_ZeroByPolynomial_ShouldReturnZero()
        {
            BigInteger dividend = 0;
            BigInteger divisor = FromBinaryString("1101101");

            BigInteger expectedQuotient = 0;
            BigInteger expectedRemainder = 0;

            var method = GetPrivateStaticMethod("PolynomialDivision", new[] { typeof(BigInteger), typeof(BigInteger) });
            var result = ((BigInteger, BigInteger))method.Invoke(null, new object[] { dividend, divisor });

            Assert.Equal(expectedQuotient, result.Item1);
            Assert.Equal(expectedRemainder, result.Item2);
        }

        [Fact]
        public void FactorizePolynomial_OfIrreduciblePolynomial_ShouldReturnItself()
        {
            // x^4 + x + 1 - известный неприводимый полином
            BigInteger irreduciblePolynomial = FromBinaryString("10011");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { irreduciblePolynomial, 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(irreduciblePolynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(irreduciblePolynomial));
            Assert.Equal(1, actualFactors[irreduciblePolynomial]);
        }

        [Fact]
        public void FactorizePolynomial_WithRepeatedIrreducibleFactor()
        {
            // p(x) = (x^2 + x + 1)^2 = x^4 + x^2 + 1
            BigInteger polynomial = FromBinaryString("10101");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("111"), 2 } // (x^2+x+1) в степени 2
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(FromBinaryString("111")));
            Assert.Equal(2, actualFactors[FromBinaryString("111")]);
        }

        [Fact]
        public void FactorizePolynomial_WithMixedFactorsAndPowers()
        {
            // p(x) = x * (x+1)^2 * (x^2+x+1)
            // (x+1)^2 = x^2+1
            // x * (x^2+1) * (x^2+x+1) = (x^3+x) * (x^2+x+1) = x^5+x^4+x^2+x
            BigInteger polynomial = FromBinaryString("110110");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { 2, 1 },                       // x
                { FromBinaryString("11"), 2 },  // (x+1) в степени 2
                { FromBinaryString("111"), 1 }  // x^2+x+1
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Theory]
        [InlineData("0")]
        [InlineData("1")]
        public void FactorizePolynomial_ForZeroAndOne_ShouldReturnEmpty(string value)
        {
            BigInteger polynomial = FromBinaryString(value);

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            Assert.Empty(actualFactors);
        }

        [Fact]
        public void FactorizePolynomial_ProductOfTwoIrreduciblesOfSameDegree()
        {
            // p(x) = (x^3+x+1) * (x^3+x^2+1) = x^6+x^5+x^4+x^3+x^2+x+1
            BigInteger polynomial = FromBinaryString("1111111");

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { FromBinaryString("1011"), 1 },
                { FromBinaryString("1101"), 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(polynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            foreach (var factor in expectedFactors)
            {
                Assert.True(actualFactors.ContainsKey(factor.Key));
                Assert.Equal(factor.Value, actualFactors[factor.Key]);
            }
        }

        [Fact]
        public void FactorizePolynomial_ForLargeIrreduciblePolynomial()
        {
            // p(x) = x^16 + x^5 + x^3 + x + 1
            // Это известный неприводимый полином.
            BigInteger largeIrreduciblePolynomial =
                (BigInteger.One << 16) |
                (BigInteger.One << 5) |
                (BigInteger.One << 3) |
                (BigInteger.One << 1) |
                BigInteger.One;

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { largeIrreduciblePolynomial, 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(largeIrreduciblePolynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(largeIrreduciblePolynomial));
            Assert.Equal(1, actualFactors[largeIrreduciblePolynomial]);
        }

        [Fact]
        public void FactorizePolynomial_ForVeryLargeIrreduciblePolynomial_BeyondLong()
        {
            // p(x) = x^128 + x^7 + x^2 + x + 1
            // Это стандартный неприводимый полином для поля GF(2^128)
            BigInteger largeIrreduciblePolynomial =
                (BigInteger.One << 128) |
                (BigInteger.One << 7) |
                (BigInteger.One << 2) |
                (BigInteger.One << 1) |
                BigInteger.One;

            var expectedFactors = new Dictionary<BigInteger, int>
            {
                { largeIrreduciblePolynomial, 1 }
            };

            var actualFactors = GaloisFieldMath.FactorizePolynomial(largeIrreduciblePolynomial);

            Assert.Equal(expectedFactors.Count, actualFactors.Count);
            Assert.True(actualFactors.ContainsKey(largeIrreduciblePolynomial));
            Assert.Equal(1, actualFactors[largeIrreduciblePolynomial]);
        }
    }
}