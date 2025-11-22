using CryptoLib.DES.Interfaces;
using CryptoLib.DES.Algorithms.DES;
using CryptoLib.DES.Algorithms.DEAL;

namespace CryptoLib.DES.Modes
{
    /// <summary>
    /// Представляет собой "оркестратор" для выполнения операций симметричного шифрования и дешифрования.
    /// Этот класс инкапсулирует логику выбора алгоритма, режима шифрования, управления состоянием (IV, фидбэки) и применения паддинга.
    /// </summary>
    public class CipherContext
    {
        //readonly - после выбора в конструкторе нельзя поменять
        private readonly ISymmetricCipher _algorithm; // DES or DEAL
        private readonly CipherMode _mode; // выбранный режим
        private readonly object _algorithmLock = new object(); // Для потокобезопасности
        private readonly PaddingMode _padding;
        private readonly byte[] _initializationVector;
        private readonly int _blockSize;

        // Регистры состояния для режимов с обратной связью
        // тут храним инфу о предыдущем обработанном блоке
        // Plaintext - открытый текст предыдущего блока
        // Ciphertext - шифротекст предыдущего блока
        private (byte[] Plaintext, byte[] Ciphertext) _pcbcFeedbackRegisters;

        // более простая штука для хранения инфы о предыдущем шаге для CBC, OFB, CFB
        private byte[] _feedbackRegister = default!;

        /// <summary>
        /// Инициализирует новый экземпляр класса CipherContext с заданными параметрами шифрования.
        /// </summary>
        /// <param name="key">Секретный ключ для шифрования и дешифрования.</param>
        /// <param name="mode">Режим работы блочного шифра (ECB, CBC, CTR и т.д.).</param>
        /// <param name="padding">Схема дополнения (паддинга) для выравнивания данных по размеру блока.</param>
        /// <param name="initializationVector">Вектор инициализации (IV). Блок рандомных данных, который перемешивается с первым блоком
        /// перед шифрованием. Не является секретом, обычно просто записывается в самое начало файла.</param>
        /// <param name="additionalParameters">Дополнительные параметры, например, для явного указания алгоритма ("Algorithm", "DES"/"DEAL").</param>
        public CipherContext(
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[]? initializationVector = null,
            params KeyValuePair<string, object>[] additionalParameters)
        {
            _mode = mode;
            _padding = padding;
            _initializationVector = initializationVector;

            _algorithm = CreateAlgorithm(key, additionalParameters);
            _algorithm.SetRoundKeys(key);
            _blockSize = _algorithm.BlockSize;

            ValidateParameters();
        }

        /// <summary>
        /// Инициализирует или сбрасывает внутреннее состояние (регистры обратной связи) перед началом новой операции шифрования или дешифрования.
        /// Использует вектор инициализации для установки начальных значений.
        /// Именно тут копируем _initializationVector в обе части кортежа _pcbcFeedbackRegisters
        /// _pcbcFeedbackRegisters - тут храним инфу о предыдущем обработанном блоке
        /// </summary>
        private void InitializeState()
        {
            if (_mode != CipherMode.ECB && _initializationVector != null)
            {
                _feedbackRegister = (byte[])_initializationVector.Clone();
                _pcbcFeedbackRegisters =
                (
                    (byte[])_initializationVector.Clone(),
                    (byte[])_initializationVector.Clone()
                );
            }
        }

        /// <summary>
        /// Метод, который создает и возвращает экземпляр нужного алгоритма шифрования (DES или DEAL)
        /// на основе размера ключа или явно переданного параметра.
        /// </summary>
        private ISymmetricCipher CreateAlgorithm(byte[] key, KeyValuePair<string, object>[] additionalParameters)
        {

            if (additionalParameters != null)
            {
                var algorithmParam = additionalParameters.FirstOrDefault(p => p.Key == "Algorithm");
                if (!algorithmParam.Equals(default(KeyValuePair<string, object>)))
                {
                    var algorithmValue = algorithmParam.Value.ToString();

                    if (algorithmValue.Contains("DEAL"))
                    {

                        return key.Length switch
                        {
                            16 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_128),
                            24 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_192),
                            32 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_256),
                            _ => throw new ArgumentException($"Unsupported DEAL key size: {key.Length} bytes")
                        };
                    }
                    else if (algorithmValue.Contains("DES"))
                    {
                        return new DESAlgorithm();
                    }

                    return algorithmValue switch
                    {
                        "DEAL" => new DEALAlgorithm(), // по умолчанию 128-bit
                        "DES" => new DESAlgorithm(),
                        _ => throw new ArgumentException($"Unsupported algorithm: {algorithmValue}")
                    };
                }
            }


            return key.Length switch
            {
                8 => new DESAlgorithm(),
                16 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_128),
                24 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_192),
                32 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_256),
                _ => throw new ArgumentException($"Unsupported key size: {key.Length} bytes")
            };
        }

        /// <summary>
        /// Проверяет корректность предоставленных параметров, например, наличие IV для режимов, которые его требуют.
        /// </summary>
        private void ValidateParameters()
        {
            if (_mode != CipherMode.ECB && _initializationVector == null)
            {
                throw new ArgumentException($"Режим {_mode} требует вектор инициализации");
            }

            if (_initializationVector != null && _initializationVector.Length != _blockSize)
            {
                throw new ArgumentException(
                    $"Размер вектора инициализации ({_initializationVector.Length}) " +
                    $"должен совпадать с размером блока ({_blockSize})");
            }
        }

        /// <summary>
        /// Асинхронно шифрует данные из входного массива байтов и записывает результат в выходной массив.
        /// </summary>
        /// <param name="inputData">Массив байтов с открытым текстом.</param>
        /// <param name="output">Массив байтов для записи шифротекста. Должен иметь достаточный размер.</param>
        public async Task EncryptAsync(byte[] inputData, byte[] output)
        {
            InitializeState();
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (output == null) throw new ArgumentNullException(nameof(output));

            //асинхронное выполнение кода в фоновом потоке  (await - оператор асинхронности)
            await Task.Run(() =>
            {
                byte[] paddedData = ApplyPadding(inputData, _blockSize);
                byte[] encryptedData = EncryptData(paddedData);

                int copyLength = Math.Min(encryptedData.Length, output.Length);
                Array.Copy(encryptedData, output, copyLength);
            });
        }

        /// <summary>
        /// Асинхронно дешифрует данные из входного массива байтов и записывает результат в выходной массив.
        /// </summary>
        /// <param name="inputData">Массив байтов с шифротекстом.</param>
        /// <param name="output">Массив байтов для записи открытого текста. Должен иметь достаточный размер.</param>
        public async Task DecryptAsync(byte[] inputData, byte[] output)
        {
            InitializeState();
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (output == null) throw new ArgumentNullException(nameof(output));

            await Task.Run(() =>
            {
                byte[] decryptedData = DecryptData(inputData);
                byte[] unpaddedData = RemovePadding(decryptedData);

                int copyLength = Math.Min(unpaddedData.Length, output.Length);
                Array.Copy(unpaddedData, output, copyLength);
            });
        }

        // Ебанем весь файл в оперативку? ГО
        // public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        // {
        //     if (!File.Exists(inputFilePath))
        //         throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

        //     byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
        //     byte[] encryptedData = await EncryptDataAsync(inputData);
        //     await File.WriteAllBytesAsync(outputFilePath, encryptedData);
        // }

        // public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        // {
        //     if (!File.Exists(inputFilePath))
        //         throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

        //     byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
        //     byte[] decryptedData = await DecryptDataAsync(inputData);
        //     await File.WriteAllBytesAsync(outputFilePath, decryptedData);
        // }

        /// <summary>
        /// Асинхронно шифрует содержимое файла, указанного в <paramref name="inputFilePath"/>, и сохраняет результат в <paramref name="outputFilePath"/>.
        /// </summary>
        /// <param name="inputFilePath">Путь к исходному файлу.</param>
        /// <param name="outputFilePath">Путь к файлу для сохранения шифротекста.</param>
        public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState();
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await EncryptAsync(inputFileStream, outputFileStream);
        }

        /// <summary>
        /// Асинхронно дешифрует содержимое файла, указанного в <paramref name="inputFilePath"/>, и сохраняет результат в <paramref name="outputFilePath"/>.
        /// </summary>
        /// <param name="inputFilePath">Путь к зашифрованному файлу.</param>
        /// <param name="outputFilePath">Путь к файлу для сохранения расшифрованного текста.</param>
        public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState();
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await DecryptAsync(inputFileStream, outputFileStream); // Делегируем потоковой версии
        }

        /// <summary>
        /// Асинхронно шифрует данные из входного потока и записывает результат в выходной поток.
        /// Реализует потоковую обработку для эффективной работы с большими файлами.
        /// </summary>
        /// <param name="inputStream">Поток с исходными данными.</param>
        /// <param name="outputStream">Поток для записи зашифрованных данных.</param>
        public async Task EncryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();
            const int bufferSize = 65536;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                bool isLastChunk = bytesRead < bufferSize; //является ли прочитанный из потока фрагмент данных последний (да - паддинги)

                byte[] chunkToEncrypt;
                if (isLastChunk)
                {
                    byte[] finalData = new byte[bytesRead];
                    Array.Copy(buffer, finalData, bytesRead);

                    if (_mode == CipherMode.CTR || _mode == CipherMode.OFB || _mode == CipherMode.CFB)
                    {

                        chunkToEncrypt = finalData;
                    }
                    else
                    {
                        chunkToEncrypt = ApplyPadding(finalData, _blockSize);
                    }
                }
                else
                {
                    chunkToEncrypt = buffer;
                }

                byte[] encryptedChunk = EncryptData(chunkToEncrypt);
                await outputStream.WriteAsync(encryptedChunk, 0, encryptedChunk.Length);
            }
        }

        /// <summary>
        /// Асинхронно дешифрует данные из входного потока и записывает результат в выходной поток.
        /// Реализует потоковую обработку для эффективной работы с большими файлами.
        /// </summary>
        /// <param name="inputStream">Поток с зашифрованными данными.</param>
        /// <param name="outputStream">Поток для записи расшифрованных данных.</param>
        public async Task DecryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();
            const int bufferSize = 65536;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            byte[] previousChunk = new byte[bufferSize];
            int previousBytesRead = await inputStream.ReadAsync(previousChunk, 0, previousChunk.Length);
            while (previousBytesRead > 0)
            {
                bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length);

                if (bytesRead == 0) // ласт блок
                {
                    byte[] finalChunk = new byte[previousBytesRead];
                    Array.Copy(previousChunk, finalChunk, previousBytesRead);

                    byte[] decryptedFinal = DecryptData(finalChunk);
                    byte[] resultToWrite;
                    if (_mode == CipherMode.CTR || _mode == CipherMode.OFB || _mode == CipherMode.CFB)
                    {
                        resultToWrite = decryptedFinal;
                    }
                    else
                    {
                        resultToWrite = RemovePadding(decryptedFinal);
                    }
                    await outputStream.WriteAsync(resultToWrite, 0, resultToWrite.Length);
                }
                else 
                {
                    byte[] chunkToDecrypt = new byte[previousBytesRead];
                    Array.Copy(previousChunk, chunkToDecrypt, previousBytesRead);

                    byte[] decryptedPrevious = DecryptData(chunkToDecrypt);
                    await outputStream.WriteAsync(decryptedPrevious, 0, decryptedPrevious.Length);
                }

                Array.Copy(buffer, previousChunk, bytesRead);
                previousBytesRead = bytesRead;
            }
        }

        /// <summary>
        /// Метод, выбирающий конкретную реализацию шифрования в зависимости от установленного режима.
        /// </summary>
        private byte[] EncryptData(byte[] data)
        {
            return _mode switch
            {
                CipherMode.ECB => EncryptECB(data),
                CipherMode.CBC => EncryptCBC(data),
                CipherMode.PCBC => EncryptPCBC(data),
                CipherMode.CFB => EncryptCFB(data),
                CipherMode.OFB => EncryptOFB(data),
                CipherMode.CTR => EncryptCTR(data),
                CipherMode.RandomDelta => EncryptRandomDelta(data),
                _ => throw new NotSupportedException($"Режим {_mode} не реализован")
            };
        }

        /// <summary>
        /// Метод, выбирающий конкретную реализацию дешифрования в зависимости от установленного режима.
        /// </summary>
        private byte[] DecryptData(byte[] data)
        {
            return _mode switch
            {
                CipherMode.ECB => DecryptECB(data),
                CipherMode.CBC => DecryptCBC(data),
                CipherMode.PCBC => DecryptPCBC(data),
                CipherMode.CFB => DecryptCFB(data),
                CipherMode.OFB => DecryptOFB(data),
                CipherMode.CTR => DecryptCTR(data),
                CipherMode.RandomDelta => DecryptRandomDelta(data),
                _ => throw new NotSupportedException($"Режим {_mode} не реализован")
            };
        }

        /// <summary>
        /// Шифрует данные в режиме Electronic Codebook (ECB).
        /// Каждый блок шифруется независимо от других
        /// </summary>
        private byte[] EncryptECB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, data.Length / blockSize, i =>
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);


                byte[] encryptedBlock = _algorithm.EncryptBlock(block);

                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
            });

            return result;
        }

        /// <summary>
        /// Дешифрует данные в режиме Electronic Codebook (ECB).
        /// Каждый блок дешифруется независимо.
        /// </summary>
        private byte[] DecryptECB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, data.Length / blockSize, i =>
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);


                byte[] decryptedBlock = _algorithm.DecryptBlock(block);

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
            });

            return result;
        }

        /// <summary>
        /// Шифрует данные в режиме Cipher Block Chaining (CBC).
        /// Каждый блок открытого текста перед шифрованием XOR-ится с предыдущим блоком шифротекста.
        /// </summary>
        private byte[] EncryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = _feedbackRegister;


            byte[] block = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;

                Array.Copy(data, offset, block, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= previousBlock[j];
                }

                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);

                previousBlock = encryptedBlock;
            }

            _feedbackRegister = previousBlock;
            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                byte[] currentCipherBlock = new byte[blockSize];
                Array.Copy(data, i * blockSize, currentCipherBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(currentCipherBlock);

                int resultOffset = i * blockSize;
                int prevCipherOffset = (i - 1) * blockSize;

                for (int j = 0; j < blockSize; j++)
                {
                    byte previousCipherByte;
                    if (i == 0)
                    {
                        previousCipherByte = _feedbackRegister[j];
                    }
                    else
                    {
                        previousCipherByte = data[prevCipherOffset + j];
                    }
                    
                    result[resultOffset + j] = (byte)(decryptedBlock[j] ^ previousCipherByte);
                }
            });

            if (blockCount > 0)
            {
                byte[] lastCipherBlock = new byte[blockSize];
                Array.Copy(data, (blockCount - 1) * blockSize, lastCipherBlock, 0, blockSize);
                _feedbackRegister = lastCipherBlock;
            }
            
            return result;
        }

        /// <summary>
        /// Шифрует данные в режиме Propagating Cipher Block Chaining (PCBC).
        /// Модификация CBC, где каждый блок открытого текста XOR-ится как с предыдущим блоком открытого текста, так и с предыдущим блоком шифротекста.
        /// </summary>
        private byte[] EncryptPCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            var (previousInput, previousOutput) = _pcbcFeedbackRegisters;

            byte[] originalBlock = new byte[blockSize];
            byte[] blockToEncrypt = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                Array.Copy(data, offset, originalBlock, 0, blockSize);
                Array.Copy(originalBlock, 0, blockToEncrypt, 0, blockSize);


                byte[] feedback = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {

                    feedback[j] = (byte)(previousInput[j] ^ previousOutput[j]);
                }

                for (int j = 0; j < blockSize; j++)
                {
                    blockToEncrypt[j] ^= feedback[j];
                }

                byte[] encryptedBlock;
                lock (_algorithmLock)
                {
                    encryptedBlock = _algorithm.EncryptBlock(blockToEncrypt);
                }
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);

                previousInput = (byte[])originalBlock.Clone();
                previousOutput = (byte[])encryptedBlock.Clone();
            }

            _pcbcFeedbackRegisters = (previousInput, previousOutput);
            return result;
        }

        /// <summary>
        /// Дешифрует данные в режиме Propagating Cipher Block Chaining (PCBC).
        /// </summary>
        private byte[] DecryptPCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];

            var (previousPlaintext, previousCiphertext) = _pcbcFeedbackRegisters;


            byte[] currentCiphertext = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;

                Array.Copy(data, offset, currentCiphertext, 0, blockSize);

                byte[] decryptedBlock;
                lock (_algorithmLock)
                {
                    decryptedBlock = _algorithm.DecryptBlock(currentCiphertext);
                }

                byte[] feedback = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    feedback[j] = (byte)(previousPlaintext[j] ^ previousCiphertext[j]);
                }

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= feedback[j];
                }

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);

                previousPlaintext = (byte[])decryptedBlock.Clone();
                previousCiphertext = (byte[])currentCiphertext.Clone();
            }
            _pcbcFeedbackRegisters = (previousPlaintext, previousCiphertext);
            return result;
        }

        /// <summary>
        /// Шифрует данные в режиме Cipher Feedback (CFB).
        /// Шифрует регистр обратной связи, XOR-ит результат с открытым текстом, а полученный шифротекст становится новым значением для регистра.
        /// </summary>
        private byte[] EncryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = _feedbackRegister;

            int offset = 0;
            while (offset < data.Length)
            {

                byte[] keystream;
                lock (_algorithmLock)
                {
                    keystream = _algorithm.EncryptBlock(feedback);
                }

                int bytesToProcess = Math.Min(blockSize, data.Length - offset);

                for (int j = 0; j < bytesToProcess; j++)
                {
                    result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                }

                byte[] nextFeedback = new byte[blockSize];
                Array.Copy(result, offset, nextFeedback, 0, bytesToProcess);
                feedback = nextFeedback;
                offset += blockSize;
            }

            _feedbackRegister = feedback;
            return result;
        }

        /// <summary>
        /// Дешифрует данные в режиме Cipher Feedback (CFB).
        /// Операция дешифрования аналогична шифрованию, но регистр обратной связи заполняется шифротекстом.
        /// </summary>
        private byte[] DecryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = _feedbackRegister;

            int offset = 0;
            while (offset < data.Length)
            {

                byte[] keystream;
                lock (_algorithmLock)
                {
                    keystream = _algorithm.EncryptBlock(feedback);
                }

                int bytesToProcess = Math.Min(blockSize, data.Length - offset);

                byte[] nextFeedback = new byte[blockSize];
                Array.Copy(data, offset, nextFeedback, 0, bytesToProcess);

                for (int j = 0; j < bytesToProcess; j++)
                {
                    result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                }

                feedback = nextFeedback;

                offset += blockSize;
            }

            _feedbackRegister = feedback;
            return result;
        }
        
        /// <summary>
        /// Шифрует данные в режиме Output Feedback (OFB), превращая блочный шифр в генератор потока ключей.
        /// Последовательно шифрует регистр обратной связи и XOR-ит результат с открытым текстом.
        /// </summary>
        private byte[] EncryptOFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];

            byte[] feedback = _feedbackRegister;

            int offset = 0;

            while (offset < data.Length)
            {

                byte[] keystream;
                lock (_algorithmLock)
                {
                    keystream = _algorithm.EncryptBlock(feedback);
                }

                feedback = keystream;

                int bytesToProcess = Math.Min(blockSize, data.Length - offset);

                for (int j = 0; j < bytesToProcess; j++)
                {
                    result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                }

                offset += blockSize;
            }

            _feedbackRegister = feedback;
            return result;
        }

        /// <summary>
        /// Дешифрует данные в режиме Output Feedback (OFB).
        /// Операция полностью идентична шифрованию, так как представляет собой XOR с тем же потоком ключей.
        /// </summary>
        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

        /// <summary>
        /// Шифрует данные в режиме Counter (CTR).
        /// Генерирует поток ключей путем шифрования последовательных значений счетчика.
        /// </summary>
        private byte[] EncryptCTR(byte[] data)
        {
            int blockSize = _blockSize;

            int blockCount = (data.Length + blockSize - 1) / blockSize;

            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount,
                () => (new byte[blockSize], new byte[8]),
                (i, loopState, localBuffers) =>
                {
                    var (blockCounter, incrementedBytes) = localBuffers;

                    Array.Copy(_initializationVector, blockCounter, blockSize);

                    long counterValue = BitConverter.ToInt64(blockCounter, blockCounter.Length - 8);
                    counterValue += (long)i;

                    BitConverter.TryWriteBytes(incrementedBytes, counterValue);
                    Array.Copy(incrementedBytes, 0, blockCounter, blockCounter.Length - 8, 8);

                    byte[] keystream = _algorithm.EncryptBlock(blockCounter);

                    int offset = i * blockSize;
                    for (int j = 0; j < blockSize; j++)
                    {
                        if (offset + j < data.Length)
                        {
                            result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                        }
                    }

                    return localBuffers;
                },
                _ => { });

            return result;
        }

        /// <summary>
        /// Дешифрует данные в режиме Counter (CTR).
        /// </summary>
        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

        /// <summary>
        /// Шифрует данные в режиме Random Delta.
        /// Кастомный режим, где каждый блок XOR-ится с псевдослучайной "дельтой", сгенерированной на основе IV и номера блока.
        /// </summary>
        private byte[] EncryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);

                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= delta[j];
                }

                byte[] encryptedBlock = _algorithm.EncryptBlock(block);

                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
            });

            return result;
        }

        /// <summary>
        /// Генерирует псевдослучайную "дельту" для указанного номера блока.
        /// </summary>
        private byte[] ComputeDeltaForBlock(byte[] initialDelta, int blockIndex)
        {
            byte[] delta = (byte[])initialDelta.Clone();
            int seed = BitConverter.ToInt32(initialDelta, 0) ^ blockIndex;
            Random random = new Random(seed);
            random.NextBytes(delta);
            return delta;
        }

        /// <summary>
        /// Дешифрует данные в режиме Random Delta.
        /// </summary>
        private byte[] DecryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                int offset = i * blockSize;
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);

                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(decryptedBlock[j] ^ delta[j]);
                }
            });

            return result;
        }

        /// <summary>
        /// Применяет к данным выбранную схему дополнения (паддинга), чтобы их длина стала кратной размеру блока.
        /// </summary>
        private byte[] ApplyPadding(byte[] data, int blockSize)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            return _padding switch
            {
                PaddingMode.Zeros => ApplyZerosPadding(data, paddingLength),
                PaddingMode.PKCS7 => ApplyPKCS7Padding(data, paddingLength),
                PaddingMode.ANSIX923 => ApplyAnsiX923Padding(data, paddingLength),
                PaddingMode.ISO10126 => ApplyIso10126Padding(data, paddingLength),
                _ => throw new NotSupportedException($"Режим паддинга {_padding} не поддерживается")
            };
        }

        /// <summary>
        /// Удаляет из данных дополнение (паддинг) в соответствии с выбранной схемой.
        /// </summary>
        private byte[] RemovePadding(byte[] data)
        {
            if (data.Length == 0 || data.Length % _blockSize != 0)
                return data;

            return _padding switch
            {
                PaddingMode.Zeros => RemoveZerosPadding(data),
                PaddingMode.PKCS7 => RemovePKCS7Padding(data),
                PaddingMode.ANSIX923 => RemoveAnsiX923Padding(data),
                PaddingMode.ISO10126 => RemoveIso10126Padding(data),
                _ => throw new NotSupportedException($"Режим паддинга {_padding} не поддерживается")
            };
        }

        /// <summary>
        /// Дополняет данные нулями.
        /// </summary>
        private byte[] ApplyZerosPadding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            return result;
        }

        /// <summary>
        /// Удаляет дополнение нулями.
        /// </summary>
        private byte[] RemoveZerosPadding(byte[] data)
        {
            return data;
        }

        /// <summary>
        /// Применяет паддинг по стандарту PKCS#7. Каждый байт дополнения равен общему числу добавленных байт.
        /// </summary>
        private byte[] ApplyPKCS7Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            for (int i = data.Length; i < result.Length; i++)
            {
                result[i] = (byte)paddingLength;
            }
            return result;
        }

        /// <summary>
        /// Удаляет паддинг по стандарту PKCS#7.
        /// </summary>
        private byte[] RemovePKCS7Padding(byte[] data)
        {
            if (data.Length == 0) return data;

            byte paddingValue = data[^1];

            if (paddingValue > data.Length) return data;

            for (int i = data.Length - paddingValue; i < data.Length; i++)
            {
                if (data[i] != paddingValue)
                    return data;
            }

            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

        /// <summary>
        /// Применяет паддинг по стандарту ANSI X9.23. Добавляются нули, а последний байт равен числу добавленных байт.
        /// </summary>
        private byte[] ApplyAnsiX923Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            result[^1] = (byte)paddingLength;
            return result;
        }

        /// <summary>
        /// Удаляет паддинг по стандарту ANSI X9.23.
        /// </summary>
        private byte[] RemoveAnsiX923Padding(byte[] data)
        {
            if (data.Length == 0) return data;

            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;

            for (int i = data.Length - paddingValue; i < data.Length - 1; i++)
            {
                if (data[i] != 0)
                    return data;
            }

            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

        /// <summary>
        /// Применяет паддинг по стандарту ISO 10126. Добавляются случайные байты, а последний байт равен числу добавленных байт.
        /// </summary>
        private byte[] ApplyIso10126Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);

            Random random = new Random();
            for (int i = data.Length; i < result.Length - 1; i++)
            {
                result[i] = (byte)random.Next(256);
            }

            result[^1] = (byte)paddingLength;
            return result;
        }


        /// <summary>
        /// Удаляет паддинг по стандарту ISO 10126.
        /// </summary>
        private byte[] RemoveIso10126Padding(byte[] data)
        {
            if (data.Length == 0) return data;

            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;

            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }
    }
}