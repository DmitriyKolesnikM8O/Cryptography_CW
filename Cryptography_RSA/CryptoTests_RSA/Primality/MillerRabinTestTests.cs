
using System.Numerics;
using CryptoLib.RSA.Core;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.Primality.Implementations;
using Xunit;

namespace CryptoTests.Primality
{
    public class MillerRabinTestTests
    {
        private readonly IPrimalityTest _millerRabinTest;

        public MillerRabinTestTests()
        {
            ICryptoMathService mathService = new CryptoMathService();
            _millerRabinTest = new MillerRabinTest(mathService);
        }

        /// <summary>
        /// Тестирует на известных простых числах.
        /// </summary>
        [Theory]
        [InlineData("7")]
        [InlineData("101")]
        [InlineData("15485863")] // Большое простое
        public void IsPrime_ShouldReturnTrue_ForPrimeNumbers(string numberStr)
        {
            var number = BigInteger.Parse(numberStr);
            Assert.True(_millerRabinTest.IsPrime(number, 0.999));
        }

        /// <summary>
        /// Тестирует на известных составных числах.
        /// </summary>
        [Theory]
        [InlineData("9")]
        [InlineData("119")] // 7 * 17
        [InlineData("2047")] // Сильный псевдопростой по основанию 2 (2^1023 mod 2047 = 1)
        public void IsPrime_ShouldReturnFalse_ForCompositeNumbers(string numberStr)
        {
            var number = BigInteger.Parse(numberStr);
            Assert.False(_millerRabinTest.IsPrime(number, 0.999));
        }

        /// <summary>
        /// Тестирует, что тест Миллера-Рабина корректно определяет
        /// число Кармайкла 561 как составное.
        /// </summary>
        [Fact]
        public void IsPrime_ShouldReturnFalse_ForCarmichaelNumber561()
        {
            
            var carmichaelNumber = new BigInteger(561);
            
            var result = _millerRabinTest.IsPrime(carmichaelNumber, 0.999);

            Assert.False(result);
        }
    }
}