using System.Numerics;
using CryptoLib.RSA.Core;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.Primality.Implementations;
using Xunit;

namespace CryptoTests.Primality
{
    public class FermatTestTests
    {
        private readonly IPrimalityTest _fermatTest;
        private readonly ICryptoMathService _mathService = new CryptoMathService();

        public FermatTestTests()
        {
            _fermatTest = new FermatTest(_mathService);
        }

        [Theory]
        [InlineData("7")]
        [InlineData("101")]
        [InlineData("15485863")] 
        public void IsPrime_ShouldReturnTrue_ForPrimeNumbers(string numberStr)
        {
            var number = BigInteger.Parse(numberStr);
            Assert.True(_fermatTest.IsPrime(number, 0.999));
        }

        [Theory]
        [InlineData("9")]
        [InlineData("119")] 
        public void IsPrime_ShouldReturnFalse_ForCompositeNumbers(string numberStr)
        {
            var number = BigInteger.Parse(numberStr);
            Assert.False(_fermatTest.IsPrime(number, 0.999));
        }
        
        /// <summary>
        /// Этот тест детерминированно демонстрирует уязвимость теста Ферма.
        /// Он не вызывает IsPrime, а напрямую проверяет основное условие теста.
        /// </summary>
        [Fact]
        public void FermatTest_DemonstratesWeakness_OnCarmichaelNumber561()
        {

            var carmichaelNumber = new BigInteger(561);
            // Выбираем свидетеля 'a', который взаимно прост с 561 (НОД(2, 561) = 1)
            var coprimeWitness = new BigInteger(2);
            // Выбираем свидетеля 'a', который НЕ взаимно прост с 561 (НОД(3, 561) = 3)
            var nonCoprimeWitness = new BigInteger(3);

            
            // Проверяем поведение для взаимно простого свидетеля.
            // Это тот случай, где тест Ферма должен ошибиться.
            var resultForCoprime = _mathService.ModPow(coprimeWitness, carmichaelNumber - 1, carmichaelNumber);

            // Проверяем поведение для НЕ взаимно простого свидетеля.
            // Здесь тест Ферма должен сработать правильно.
            var resultForNonCoprime = _mathService.ModPow(nonCoprimeWitness, carmichaelNumber - 1, carmichaelNumber);

            //  Для взаимно простого свидетеля тест ошибочно возвращает 1,
            // как будто число простое. Это и есть демонстрация уязвимости.
            Assert.Equal(BigInteger.One, resultForCoprime);

            // Для свидетеля, являющегося делителем, тест правильно
            // возвращает НЕ 1, доказывая, что число составное.
            Assert.NotEqual(BigInteger.One, resultForNonCoprime);
        }
    }
}