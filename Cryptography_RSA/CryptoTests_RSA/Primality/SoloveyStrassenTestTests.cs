using System.Numerics;
using CryptoLib.RSA.Core;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.Primality.Implementations;


namespace CryptoTests.Primality
{
    public class SoloveyStrassenTestTests
    {
        private readonly IPrimalityTest _soloveyStrassenTest;

        public SoloveyStrassenTestTests()
        {
            ICryptoMathService mathService = new CryptoMathService();
            _soloveyStrassenTest = new SoloveyStrassenTest(mathService);
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
            Assert.True(_soloveyStrassenTest.IsPrime(number, 0.999));
        }

        /// <summary>
        /// Тестирует на известных составных числах.
        /// </summary>
        [Theory]
        [InlineData("9")]
        [InlineData("119")] // 7 * 17
        [InlineData("123456")]
        public void IsPrime_ShouldReturnFalse_ForCompositeNumbers(string numberStr)
        {
            var number = BigInteger.Parse(numberStr);
            Assert.False(_soloveyStrassenTest.IsPrime(number, 0.999));
        }

        /// <summary>
        /// Тестирует, что тест Соловея-Штрассена, в отличие от теста Ферма,
        /// корректно определяет число Кармайкла 561 как составное.
        /// </summary>
        [Fact]
        public void IsPrime_ShouldReturnFalse_ForCarmichaelNumber561()
        {
            
            var carmichaelNumber = new BigInteger(561);
            
            var result = _soloveyStrassenTest.IsPrime(carmichaelNumber, 0.999);

            Assert.False(result);
        }
    }
}