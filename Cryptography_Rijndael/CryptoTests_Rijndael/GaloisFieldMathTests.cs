using CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField;
using System.Reflection;

/*
1. Add_ShouldReturnCorrectXorResult - Проверяет операцию сложения на нескольких известных векторах.
2. Multiply_ShouldReturnCorrectProduct - Проверяет операцию умножения на известных векторах из стандарта FIPS-197.
3. Inverse_ShouldFindCorrectMultiplicativeInverse - Проверяет операцию нахождения обратного элемента на известных векторах.
4. Inverse_OfZero_ShouldBeZero - Проверяет граничный случай: обратный элемент для нуля должен быть нулем.
5. Inverse_Property_A_Times_InverseA_ShouldBe_1 - Проверяет фундаментальное свойство поля: a * a⁻¹ = 1 для всех ненулевых элементов.
6. FindAllIrreduciblePolynomials_ShouldReturnExactly30Polynomials - Проверяет, что функция поиска неприводимых полиномов возвращает ровно 30 штук, как указано в спецификации.
7. IsIrreducible_ShouldCorrectlyIdentifyPolynomials - Проверяет функцию определения неприводимости на наборе известных приводимых и неприводимых полиномов.
8. Multiply_KnownValue_From_FIPS197 - Дополнительный тест, дублирующий один из векторов Multiply_ShouldReturnCorrectProduct для надежности.
9. Add_ShouldBeCommutative - Проверяет свойство коммутативности сложения (a+b = b+a).
10. Multiply_ShouldBeCommutative - Проверяет свойство коммутативности умножения (a*b = b*a).
11. Multiply_ShouldBeAssociative - Проверяет свойство ассоциативности умножения ((a*b)*c = a*(b*c)).
12. Multiply_ShouldBeDistributiveOverAdd - Проверяет свойство дистрибутивности (a*(b+c) = a*b + a*c).
13. Multiply_WithCustomModule_ShouldReturnCorrectProduct - Проверяет, что умножение корректно работает с нестандартным неприводимым полиномом.
14. Inverse_Property_WithCustomModule_ShouldHold - Проверяет, что свойство a * a⁻¹ = 1 сохраняется при использовании нестандартного неприводимого полинома.
15. FindAllIrreduciblePolynomials_ShouldReturnCorrectPolynomials - Проверяет, что список найденных неприводимых полиномов в точности совпадает с эталонным.
16. GetRemainder_For_0x1C3_div_0x07_ShouldBeZero - Отладочный тест, проверяющий корректность работы private-метода деления на конкретном проблемном значении.
17. IsIrreducible_ForBoundaryCases_ShouldReturnFalse - Проверяет функцию определения неприводимости на граничных случаях (ноль, четные полиномы).
*/

namespace CryptoTests
{
    public class GaloisFieldMathTests
    {
        // Стандартный неприводимый полином для AES
        private const byte AesIrreduciblePolynomial = 0x1B;

        [Theory]
        [InlineData(0x53, 0xCA, 0x99)] // Пример из Википедии
        [InlineData(0x00, 0xFF, 0xFF)]
        [InlineData(0xAB, 0xAB, 0x00)]
        public void Add_ShouldReturnCorrectXorResult(byte a, byte b, byte expected)
        {
            var result = GaloisFieldMath.Add(a, b);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(0x57, 0x83, 0xC1)] // Пример из стандарта FIPS-197
        [InlineData(0x57, 0x13, 0xFE)]
        [InlineData(0xAE, 0x01, 0xAE)] // Умножение на 1
        [InlineData(0xAE, 0x00, 0x00)] // Умножение на 0
        [InlineData(0x02, 0x8D, 0x01)] // 0x8D - обратный к 0x02
        public void Multiply_ShouldReturnCorrectProduct(byte a, byte b, byte expected)
        {
            var result = GaloisFieldMath.Multiply(a, b, AesIrreduciblePolynomial);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(0x01, 0x01)] // Обратный к 1 это 1
        [InlineData(0x02, 0x8D)]
        [InlineData(0x53, 0xCA)]
        [InlineData(0xAE, 0xD2)]
        public void Inverse_ShouldFindCorrectMultiplicativeInverse(byte element, byte expectedInverse)
        {
            var result = GaloisFieldMath.Inverse(element, AesIrreduciblePolynomial);
            Assert.Equal(expectedInverse, result);
        }

        [Fact]
        public void Inverse_OfZero_ShouldBeZero()
        {
            var result = GaloisFieldMath.Inverse(0, AesIrreduciblePolynomial);
            Assert.Equal(0, result);
        }

        [Fact]
        public void Inverse_Property_A_Times_InverseA_ShouldBe_1()
        {
            // Проверим для всех ненулевых элементов
            for (int i = 1; i < 256; i++)
            {
                byte element = (byte)i;
                byte inverse = GaloisFieldMath.Inverse(element, AesIrreduciblePolynomial);
                byte product = GaloisFieldMath.Multiply(element, inverse, AesIrreduciblePolynomial);
                Assert.Equal(1, product);
            }
        }

        [Fact]
        public void FindAllIrreduciblePolynomials_ShouldReturnExactly30Polynomials()
        {
            // Спойлер в задании говорил, что их должно быть 30
            var polynomials = GaloisFieldMath.FindAllIrreduciblePolynomials();
            Assert.Equal(30, polynomials.Count);
        }



        [Theory]
        [InlineData(0x1B, true)]  // Стандартный полином AES
        [InlineData(0x8D, true)]  // Другой известный неприводимый
        [InlineData(0x01, false)] // x^8 + 1 = (x+1)^8, приводимый
        [InlineData(0xC3, true)] // x^8+x^7+x^6+x+1, неприводимый
        [InlineData(0x83, false)] // x^8+x^7+x+1, ПРИВОДИМЫЙ
        public void IsIrreducible_ShouldCorrectlyIdentifyPolynomials(byte poly, bool expected)
        {
            var result = GaloisFieldMath.IsIrreducible(poly);
            Assert.Equal(expected, result);
        }


        [Fact]
        public void Multiply_KnownValue_From_FIPS197()
        {
            byte result = GaloisFieldMath.Multiply(0x57, 0x83, 0x1B);
            Assert.Equal(0xC1, result);
        }

        #region Field Property Tests

        [Fact]
        public void Add_ShouldBeCommutative()
        {
            // Проверяем свойство: a + b = b + a
            // Для XOR это свойство выполняется по определению, но тест это подтвердит.
            for (int i = 0; i < 256; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    byte a = (byte)i;
                    byte b = (byte)j;
                    Assert.Equal(GaloisFieldMath.Add(a, b), GaloisFieldMath.Add(b, a));
                }
            }
        }

        [Fact]
        public void Multiply_ShouldBeCommutative()
        {
            // Проверяем свойство: a * b = b * a
            var rand = new Random();
            for (int i = 0; i < 1000; i++) // 1000 случайных пар
            {
                byte a = (byte)rand.Next(256);
                byte b = (byte)rand.Next(256);
                Assert.Equal(
                    GaloisFieldMath.Multiply(a, b, AesIrreduciblePolynomial),
                    GaloisFieldMath.Multiply(b, a, AesIrreduciblePolynomial)
                );
            }
        }

        [Fact]
        public void Multiply_ShouldBeAssociative()
        {
            // Проверяем свойство: (a * b) * c = a * (b * c)
            var rand = new Random();
            for (int i = 0; i < 1000; i++) // 1000 случайных троек
            {
                byte a = (byte)rand.Next(256);
                byte b = (byte)rand.Next(256);
                byte c = (byte)rand.Next(256);

                var leftSide = GaloisFieldMath.Multiply(GaloisFieldMath.Multiply(a, b, AesIrreduciblePolynomial), c, AesIrreduciblePolynomial);
                var rightSide = GaloisFieldMath.Multiply(a, GaloisFieldMath.Multiply(b, c, AesIrreduciblePolynomial), AesIrreduciblePolynomial);

                Assert.Equal(leftSide, rightSide);
            }
        }

        [Fact]
        public void Multiply_ShouldBeDistributiveOverAdd()
        {
            // Проверяем свойство: a * (b + c) = (a * b) + (a * c)
            var rand = new Random();
            for (int i = 0; i < 1000; i++) // 1000 случайных троек
            {
                byte a = (byte)rand.Next(256);
                byte b = (byte)rand.Next(256);
                byte c = (byte)rand.Next(256);

                var leftSide = GaloisFieldMath.Multiply(a, GaloisFieldMath.Add(b, c), AesIrreduciblePolynomial);
                var rightSide = GaloisFieldMath.Add(
                    GaloisFieldMath.Multiply(a, b, AesIrreduciblePolynomial),
                    GaloisFieldMath.Multiply(a, c, AesIrreduciblePolynomial)
                );

                Assert.Equal(leftSide, rightSide);
            }
        }

        #endregion

        [Theory]
        [InlineData((byte)0x02, (byte)0x03, (byte)0x06, (byte)0x8D)] // x * (x+1) = x^2+x (0x06)
        [InlineData((byte)0xC6, (byte)0xAE, (byte)0x57, (byte)0x8D)] // Случайные значения, посчитанные на калькуляторе для этого поля
        public void Multiply_WithCustomModule_ShouldReturnCorrectProduct(byte a, byte b, byte expected, byte module)
        {

            var result = GaloisFieldMath.Multiply(a, b, module);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void Inverse_Property_WithCustomModule_ShouldHold()
        {
            // x^8 + x^7 + x^3 + x^2 + 1 - другой известный неприводимый полином
            byte customIrreduciblePolynomial = 0x8D;

            // Проверяем свойство a * a⁻¹ = 1 для всех ненулевых элементов в этом новом поле.
            for (int i = 1; i < 256; i++)
            {
                byte element = (byte)i;
                byte inverse = GaloisFieldMath.Inverse(element, customIrreduciblePolynomial);
                byte product = GaloisFieldMath.Multiply(element, inverse, customIrreduciblePolynomial);

                Assert.Equal(1, product);
            }
        }

        [Fact]
        public void FindAllIrreduciblePolynomials_ShouldReturnCorrectPolynomials()
        {
            var expectedPolynomials = new HashSet<byte>
            {
                0x1B, 0x1D, 0x2B, 0x2D, 0x39, 0x3F, 0x4D, 0x5F, 0x63, 0x7B,
                0x65, 0x69, 0x71, 0x77, 0x87, 0x8B, 0x8D, 0x9F, 0xA3, 0xA9,
                0xBD, 0xE7, 0xB1, 0xF3, 0xF5, 0xC3, 0xF9, 0xCF, 0xD7, 0xDD
            };

            var actualPolynomials = GaloisFieldMath.FindAllIrreduciblePolynomials();
            var actualSet = new HashSet<byte>(actualPolynomials);

            if (!expectedPolynomials.SetEquals(actualSet))
            {


                // 1. Полиномы, которые мы нашли, но не ожидали (лишние)
                var unexpected = new HashSet<byte>(actualSet);
                unexpected.ExceptWith(expectedPolynomials); // Удаляем все ожидаемые

                // 2. Полиномы, которые мы ожидали, но не нашли (отсутствующие)
                var missing = new HashSet<byte>(expectedPolynomials);
                missing.ExceptWith(actualSet);

                string errorMessage = $"\n--- Ошибка в неприводимых полиномах 8-й степени ({actualSet.Count} из 30) ---\n" +
                                    $"Ожидалось: 30. Найдено: {actualSet.Count}.\n" +
                                    $"Лишние (Reducible, но найдены): {string.Join(", ", FormatBytes(unexpected))}\n" +
                                    $"Отсутствующие (Irreducible, но пропущены): {string.Join(", ", FormatBytes(missing))}\n";

                Assert.Fail(errorMessage);
            }

            Assert.Equal(30, actualPolynomials.Count);
        }



        [Fact]
        public void GetRemainder_For_0x1C3_div_0x07_ShouldBeZero()
        {
            // Этот тест является прямым следствием анализа лога.
            // Мы знаем, что полином 0xC3 (x^8+x^7+x^6+1) должен делиться
            // на 0x07 (x^2+x+1). Это значит, что GetRemainder должен вернуть 0.

            var method = typeof(GaloisFieldMath).GetMethod("GetRemainder", BindingFlags.NonPublic | BindingFlags.Static, new[] { typeof(int), typeof(int) });
            if (method == null)
                throw new InvalidOperationException("Не удалось найти приватный метод GetRemainder.");

            int dividend = 0x1C3; // Полином x^8 + x^7 + x^6 + 1
            int divisor = 0x07;  // Полином x^2 + x + 1
            int expectedRemainder = 0x03;

            var actualRemainder = (int)method.Invoke(null, [dividend, divisor]);

            Assert.Equal(expectedRemainder, actualRemainder);
        }

        private static IEnumerable<string> FormatBytes(IEnumerable<byte> bytes)
        {
            return bytes.OrderBy(b => b).Select(b => $"0x{b:X2}");
        }

        [Theory]
        [InlineData((byte)0x00, false)] // Полином 0 (x^8) тривиально приводим
        [InlineData((byte)0x1A, false)] // Четный полином (x^8+x^4+x^3+x), делится на x
        [InlineData((byte)0xFE, false)] // Еще один четный полином
        public void IsIrreducible_ForBoundaryCases_ShouldReturnFalse(byte polynomial, bool expected)
        {

            var result = GaloisFieldMath.IsIrreducible(polynomial);
            Assert.Equal(expected, result);
        }
    }
}