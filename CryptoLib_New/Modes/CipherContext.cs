using System;
using System.IO;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;


using CryptoLib.DES.Interfaces;
using CryptoLib.DES.Modes; 


using CryptoLib.New.Algorithms.LOKI97;

namespace CryptoLib.New.Modes
{
    /// <summary>
    /// Полная реализация CipherContext для библиотеки LOKI97.
    /// Поддерживает все режимы шифрования и паддинга, аналогично библиотеке DES.
    /// </summary>
    public class CipherContextLOKI97
    {
        private readonly ISymmetricCipher _algorithm;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _initializationVector;
        private readonly int _blockSize;
        private readonly object _algorithmLock = new object();

        // Регистры состояния для режимов с обратной связью
        private (byte[] Plaintext, byte[] Ciphertext) _pcbcFeedbackRegisters;
        private byte[] _feedbackRegister = default!;

        /// <summary>
        /// Инициализирует контекст для алгоритма LOKI97.
        /// </summary>
        public CipherContextLOKI97(
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[]? initializationVector = null,
            byte polynomial = 0x1B)
        {
            _mode = mode;
            _padding = padding;
            _initializationVector = initializationVector;

            // В этой библиотеке всегда используем LOKI97
            _algorithm = new LOKI97Algorithm(key.Length, polynomial); 
            _algorithm.SetRoundKeys(key);
            
            _blockSize = _algorithm.BlockSize; // 16 байт (128 бит)

            ValidateParameters();
        }

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

        // ==========================================
        // PUBLIC API
        // ==========================================

        public async Task EncryptAsync(byte[] inputData, byte[] output)
        {
            InitializeState();
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (output == null) throw new ArgumentNullException(nameof(output));

            await Task.Run(() =>
            {
                byte[] paddedData = ApplyPadding(inputData, _blockSize);
                byte[] encryptedData = EncryptData(paddedData);

                int copyLength = Math.Min(encryptedData.Length, output.Length);
                Array.Copy(encryptedData, output, copyLength);
            });
        }

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

        public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState();
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await EncryptAsync(inputFileStream, outputFileStream);
        }

        public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState();
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await DecryptAsync(inputFileStream, outputFileStream);
        }

        public async Task EncryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();
            const int bufferSize = 65536;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                bool isLastChunk = bytesRead < bufferSize; 

                byte[] chunkToEncrypt;
                if (isLastChunk)
                {
                    byte[] finalData = new byte[bytesRead];
                    Array.Copy(buffer, finalData, bytesRead);

                    // Для потоковых режимов паддинг не нужен, если это не блочный режим
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

                if (bytesRead == 0) // last block
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

        // ==========================================
        // CORE LOGIC
        // ==========================================

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

        // ==========================================
        // MODES IMPLEMENTATION
        // ==========================================

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

        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

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

                    // Учитываем, что блок может быть 16 байт (LOKI97).
                    // Инкрементируем последние 8 байт, как счетчик.
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

        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

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

        private byte[] ComputeDeltaForBlock(byte[] initialDelta, int blockIndex)
        {
            byte[] delta = (byte[])initialDelta.Clone();
            int seed = BitConverter.ToInt32(initialDelta, 0) ^ blockIndex;
            Random random = new Random(seed);
            random.NextBytes(delta);
            return delta;
        }

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

        // ==========================================
        // PADDING
        // ==========================================

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

        private byte[] ApplyZerosPadding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            return result;
        }

        private byte[] RemoveZerosPadding(byte[] data)
        {
            int i = data.Length - 1;
            while (i >= 0 && data[i] == 0)
            {
                i--;
            }
            // i - индекс последнего НЕ нулевого байта.
            // Берем i + 1 байт.
            return data.Take(i + 1).ToArray();
        }

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

        private byte[] RemovePKCS7Padding(byte[] data)
        {
            if (data.Length == 0) return data;
            byte paddingValue = data[^1];
            if (paddingValue > data.Length) return data;

            for (int i = data.Length - paddingValue; i < data.Length; i++)
            {
                if (data[i] != paddingValue) return data;
            }

            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

        private byte[] ApplyAnsiX923Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            result[^1] = (byte)paddingLength;
            return result;
        }

        private byte[] RemoveAnsiX923Padding(byte[] data)
        {
            if (data.Length == 0) return data;
            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;

            for (int i = data.Length - paddingValue; i < data.Length - 1; i++)
            {
                if (data[i] != 0) return data;
            }

            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

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