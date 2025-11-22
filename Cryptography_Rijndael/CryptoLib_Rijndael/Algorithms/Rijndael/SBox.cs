using CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField;

namespace CryptoLib.Rijndael.Algorithms.Rijndael
{
    /// <summary>
    /// Отвечает за генерацию и хранение S-Box и Inverse S-Box таблиц.
    /// Реализует "ленивую" (отложенную) инициализацию: таблицы генерируются
    /// только при первом обращении к ним.
    /// </summary>
    public class SBox
    {
        private readonly byte _irreduciblePolynomial;

        // Приватные поля для кэширования сгенерированных таблиц
        private byte[]? _sBoxTable;
        private byte[]? _inverseSBoxTable;

        /// <summary>
        /// Прямая таблица замен (S-Box).
        /// </summary>
        public byte[] SBoxTable => _sBoxTable ??= GenerateSBox();
        
        /// <summary>
        /// Обратная таблица замен (Inverse S-Box).
        /// </summary>
        public byte[] InverseSBoxTable => _inverseSBoxTable ??= GenerateInverseSBox();

        /// <summary>
        /// Инициализирует новый экземпляр SBox.
        /// </summary>
        /// <param name="irreduciblePolynomial">Неприводимый полином для операций в поле GF(2^8).</param>
        public SBox(byte irreduciblePolynomial)
        {
            // ПРОВЕРКА НА НЕПРИВОДИМОСТЬ
            if (!GaloisFieldMath.IsIrreducible(irreduciblePolynomial))
            {
                throw new ArgumentException("Полином должен быть неприводимым.", nameof(irreduciblePolynomial));
            }
            _irreduciblePolynomial = irreduciblePolynomial;
        }

        /// <summary>
        /// Генерирует прямую S-Box таблицу.
        /// </summary>
        /// <remarks>
        /// Для каждого байта 'b' выполняются два шага:
        /// 1. Находится мультипликативный обратный элемент в поле GF(2^8). Обратный для 0 - это 0.
        /// 2. К результату применяется афинное преобразование.
        /// </remarks>
        private byte[] GenerateSBox()
        {
            var sbox = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                byte b = (byte)i;
                
                byte inverse = GaloisFieldMath.Inverse(b, _irreduciblePolynomial);
                
                // 2. Применяем афинное преобразование
                byte x = inverse;
                byte result = (byte)(x ^ 
                                     ((x << 1) | (x >> 7)) ^ 
                                     ((x << 2) | (x >> 6)) ^ 
                                     ((x << 3) | (x >> 5)) ^ 
                                     ((x << 4) | (x >> 4)) ^ 
                                     0x63); // 0x63 - константа из стандарта AES
                sbox[i] = result;
            }
            return sbox;
        }

        /// <summary>
        /// Генерирует обратную S-Box таблицу.
        /// </summary>
        private byte[] GenerateInverseSBox()
        {
            var invSbox = new byte[256];
            // Прямая таблица SBoxTable вызовет генерацию, если она еще не была создана.
            var sbox = this.SBoxTable;

            // Если sbox[x] = y, то обратная таблица invSbox[y] = x.
            // Это самый надежный способ получить обратную S-Box.
            for (int i = 0; i < 256; i++)
            {
                invSbox[sbox[i]] = (byte)i;
            }

            return invSbox;
        }
    }
}