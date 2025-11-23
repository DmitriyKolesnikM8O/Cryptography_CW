using System;
using System.IO;
using System.Threading.Tasks;

namespace CryptoLib.New.Algorithms.RC4
{
    public class RC4Algorithm
    {
        private byte[] _s; // State vector (S-Box)
        private int _i;
        private int _j;

        /// <summary>
        /// Инициализирует новый экземпляр алгоритма RC4 с заданным ключом.
        /// </summary>
        /// <param name="key">Ключ шифрования (от 1 до 256 байт).</param>
        public RC4Algorithm(byte[] key)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key must not be null or empty.");

            InitializeState(key);
        }

        /// <summary>
        /// KSA (Key-scheduling algorithm). Инициализация состояния S на основе ключа.
        /// </summary>
        private void InitializeState(byte[] key)
        {
            _s = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                _s[i] = (byte)i;
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + _s[i] + key[i % key.Length]) % 256;
                Swap(_s, i, j);
            }

            _i = 0;
            _j = 0;
        }

        /// <summary>
        /// Шифрует или дешифрует массив байт (операция симметрична).
        /// </summary>
        public byte[] ProcessData(byte[] data)
        {
            byte[] result = new byte[data.Length];
            
            for (int k = 0; k < data.Length; k++)
            {
                // PRGA (Pseudo-random generation algorithm)
                _i = (_i + 1) % 256;
                _j = (_j + _s[_i]) % 256;
                
                Swap(_s, _i, _j);
                
                byte kByte = _s[(_s[_i] + _s[_j]) % 256];
                
                // XOR с открытым текстом
                result[k] = (byte)(data[k] ^ kByte);
            }

            return result;
        }

        /// <summary>
        /// Асинхронно шифрует/дешифрует файл.
        /// Читает файл кусками, обрабатывает и пишет в выходной файл.
        /// </summary>
        public async Task ProcessFileAsync(string inputFilePath, string outputFilePath)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"File not found: {inputFilePath}");

            const int bufferSize = 1024 * 64; // 64 KB
            byte[] buffer = new byte[bufferSize];

            using (var sourceStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize, true))
            using (var destinationStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize, true))
            {
                int bytesRead;
                while ((bytesRead = await sourceStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    
                    byte[] processedChunk = new byte[bytesRead];
                    for (int k = 0; k < bytesRead; k++)
                    {
                        _i = (_i + 1) % 256;
                        _j = (_j + _s[_i]) % 256;

                        Swap(_s, _i, _j);

                        byte kByte = _s[(_s[_i] + _s[_j]) % 256];
                        processedChunk[k] = (byte)(buffer[k] ^ kByte);
                    }

                    await destinationStream.WriteAsync(processedChunk, 0, bytesRead);
                }
            }
        }

        private void Swap(byte[] array, int index1, int index2)
        {
            byte temp = array[index1];
            array[index1] = array[index2];
            array[index2] = temp;
        }
    }
}