using CryptoLib.RSA.Core;
using System.Numerics;

namespace CryptoTests.Core
{
    /// <summary>
    /// Набор тестов для класса CryptoMathService.
    /// </summary>
    public class CryptoMathServiceTests
    {
        private readonly CryptoMathService _service = new CryptoMathService();

        /// <summary>
        /// Тестирует метод Gcd на различных наборах входных данных,
        /// включая стандартные случаи, взаимно простые числа, наличие нуля,
        /// отрицательные числа и большие числа.
        /// </summary>
        [Theory]
        // Стандартный случай
        [InlineData("48", "18", "6")]
        // Одно число является делителем другого
        [InlineData("20", "5", "5")]
        // Взаимно простые числа
        [InlineData("17", "23", "1")]
        // Одно из чисел равно нулю
        [InlineData("50", "0", "50")]
        // Первое число равно нулю
        [InlineData("0", "30", "30")]
        // Оба числа равны нулю (по соглашению, НОД(0,0) = 0)
        [InlineData("0", "0", "0")]
        // Одно из чисел отрицательное
        [InlineData("-48", "18", "6")]
        // Второе число отрицательное
        [InlineData("48", "-18", "6")]
        // Оба числа отрицательные
        [InlineData("-48", "-18", "6")]
        // Случай с большим числом, которое кратно меньшему
        [InlineData("3000000021", "5000000035", "1000000007")]
        // Случай с большими взаимно простыми числами
        [InlineData("65432109876543210", "12345678901234567", "1")]
        public void Gcd_ShouldReturnCorrectGcd_ForVariousInputs(string aStr, string bStr, string expectedStr)
        {
            var a = BigInteger.Parse(aStr);
            var b = BigInteger.Parse(bStr);
            var expected = BigInteger.Parse(expectedStr);

            var result1 = _service.Gcd(a, b);
            var result2 = _service.Gcd(b, a);

            Assert.Equal(expected, result1);
            Assert.Equal(expected, result2);
        }

        /// <summary>
        /// Тестирует метод ExtendedGcd. Проверяет как корректность НОД,
        /// так и выполнение соотношения Безу a*x + b*y = НОД(a, b).
        /// </summary>
        [Theory]
        // Стандартный случай
        [InlineData("48", "18")]
        // Взаимно простые числа
        [InlineData("17", "23")]
        // Одно число является делителем другого
        [InlineData("99", "3")]
        // Первое число равно нулю
        [InlineData("0", "30")]
        // Второе число равно нулю
        [InlineData("50", "0")]
        // Отрицательные числа
        [InlineData("-48", "18")]
        [InlineData("48", "-18")]
        // Большие числа
        [InlineData("3000000021", "5000000035")]
        public void ExtendedGcd_ShouldSatisfyBezoutsIdentity(string aStr, string bStr)
        {
            var a = BigInteger.Parse(aStr);
            var b = BigInteger.Parse(bStr);

            var (gcd, x, y) = _service.ExtendedGcd(a, b);

            Assert.Equal(gcd, a * x + b * y);
            Assert.Equal(_service.Gcd(a, b), gcd);
        }

        /// <summary>
        /// Тестирует метод ModPow на корректность вычислений.
        /// </summary>
        [Theory]
        // Классический пример: 4^13 mod 497 = 445
        [InlineData("4", "13", "497", "445")]
        // Показатель степени равен нулю: a^0 = 1
        [InlineData("12345", "0", "987", "1")]
        // Показатель степени равен единице: a^1 mod m = a mod m
        [InlineData("100", "1", "30", "10")]
        // Основание равно нулю: 0^a = 0 (при a > 0)
        [InlineData("0", "123", "456", "0")]
        // Основание равно единице: 1^a = 1
        [InlineData("1", "12345", "987", "1")]
        // Модуль равен единице: a mod 1 = 0
        [InlineData("123", "456", "1", "0")]
        // Большие числа, которые вызвали бы переполнение при прямом вычислении
        [InlineData("123456789", "987654321", "12345", "10869")]
        public void ModPow_ShouldReturnCorrectResult(string valueStr, string expStr, string modStr, string expectedStr)
        {
            // Arrange
            var value = BigInteger.Parse(valueStr);
            var exponent = BigInteger.Parse(expStr);
            var modulus = BigInteger.Parse(modStr);
            var expected = BigInteger.Parse(expectedStr);

            // Act
            var result = _service.ModPow(value, exponent, modulus);

            // Assert
            Assert.Equal(expected, result);
        }

        /// <summary>
        /// Тестирует, что метод ModPow выбрасывает исключение при некорректном модуле или показателе.
        /// </summary>
        [Theory]
        // Модуль равен нулю
        [InlineData("10", "10", "0")]
        // Модуль отрицательный
        [InlineData("10", "10", "-5")]
        // Показатель отрицательный
        [InlineData("10", "-2", "5")]
        public void ModPow_ShouldThrowException_ForInvalidArguments(string valueStr, string expStr, string modStr)
        {
            // Arrange
            var value = BigInteger.Parse(valueStr);
            var exponent = BigInteger.Parse(expStr);
            var modulus = BigInteger.Parse(modStr);

            // Act & Assert
            // Проверяем, что вызов метода с данными параметрами приводит к исключению ArgumentException.
            Assert.Throws<ArgumentException>(() => _service.ModPow(value, exponent, modulus));
        }

        /// <summary>
        /// Тестирует метод LegendreSymbol на корректность вычислений.
        /// </summary>
        [Theory]
        // Случай 1: a - квадратичный вычет (например, 2^2=4, 4 - вычет по mod 5)
        [InlineData("4", "5", 1)]
        [InlineData("10", "13", 1)] // 6^2 = 36 ≡ 10 (mod 13)
        // Случай 2: a - квадратичный невычет
        [InlineData("2", "5", -1)]
        [InlineData("5", "7", -1)]
        // Случай 3: a делится на p
        [InlineData("10", "5", 0)]
        [InlineData("0", "13", 0)]
        // a > p
        [InlineData("15", "7", 1)] // 15 mod 7 = 1, а 1 - всегда вычет
        // a - отрицательное
        [InlineData("-1", "5", 1)] // -1 ≡ 4 (mod 5), 4 - вычет
        [InlineData("-1", "7", -1)] // -1 ≡ 6 (mod 7), 6 - невычет
        // Большие числа (p=10007 - простое)
        [InlineData("123456", "10007", 1)] // 123456 mod 10007 = 3372. 3372 - вычет.
        public void LegendreSymbol_ShouldReturnCorrectValue(string aStr, string pStr, int expected)
        {
            // Arrange
            var a = BigInteger.Parse(aStr);
            var p = BigInteger.Parse(pStr);

            // Act
            var result = _service.LegendreSymbol(a, p);

            // Assert
            Assert.Equal(expected, result);
        }

        /// <summary>
        /// Тестирует, что LegendreSymbol выбрасывает исключение для некорректного p.
        /// </summary>
        [Theory]
        [InlineData("10", "2")]  // p = 2
        [InlineData("10", "-5")] // p - отрицательное
        [InlineData("10", "1")]  // p < 3
        public void LegendreSymbol_ShouldThrowException_ForInvalidModulus(string aStr, string pStr)
        {
            // Arrange
            var a = BigInteger.Parse(aStr);
            var p = BigInteger.Parse(pStr);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _service.LegendreSymbol(a, p));
        }
        
        /// <summary>
        /// Тестирует метод JacobiSymbol на корректность вычислений.
        /// </summary>
        [Theory]
        // Примеры, где n - простое (должно совпадать с Лежандром)
        [InlineData("2", "7", 1)]
        [InlineData("10", "13", 1)]
        [InlineData("21", "71", -1)] // 71 - простое
        // Примеры, где n - составное
        [InlineData("2", "15", 1)]   // (2/3)*(2/5) = (-1)*(-1) = 1
        [InlineData("19", "45", 1)]  // (19/5)*(19/9) -> (4/5)*(1/9) = 1*1 = 1. Перепроверить! (19/45)=(45/19)=(7/19)=-(19/7)=-(5/7)=-(-1)=1
        [InlineData("7", "15", -1)]  // (7/3)*(7/5) = (1)*(-1) = -1
        [InlineData("1001", "9907", -1)] // 9907 - простое, 1001 - составное
        // Случай, когда НОД(a,n) > 1
        [InlineData("6", "15", 0)]
        [InlineData("35", "77", 0)]
        [InlineData("369", "615", 0)] // НОД = 123
        // a > n
        [InlineData("100", "33", 1)] // (100/33) = (1/33) = 1
        // a - отрицательное
        [InlineData("-1", "21", 1)] // (-1/3)*(-1/7) = (-1)*(-1) = 1
        // Большие числа
        [InlineData("1234567", "9876543", -1)] // НОД > 1
        [InlineData("1000000007", "1000000011", -1)] // Два простых числа
        public void JacobiSymbol_ShouldReturnCorrectValue(string aStr, string nStr, int expected)
        {
            // Arrange
            var a = BigInteger.Parse(aStr);
            var n = BigInteger.Parse(nStr);

            // Act
            var result = _service.JacobiSymbol(a, n);

            // Assert
            Assert.Equal(expected, result);
        }

        /// <summary>
        /// Тестирует, что JacobiSymbol выбрасывает исключение для некорректного n.
        /// </summary>
        [Theory]
        [InlineData("10", "2")]  // n - четное
        [InlineData("10", "-5")] // n - отрицательное
        [InlineData("10", "0")]  // n = 0
        public void JacobiSymbol_ShouldThrowException_ForInvalidModulus(string aStr, string nStr)
        {
            // Arrange
            var a = BigInteger.Parse(aStr);
            var n = BigInteger.Parse(nStr);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _service.JacobiSymbol(a, n));
        }
    }
}