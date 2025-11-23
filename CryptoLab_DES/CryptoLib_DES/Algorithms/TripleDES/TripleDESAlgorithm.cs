using System;
using CryptoLib.DES.Interfaces;
using CryptoLib.DES.Algorithms.DES;

namespace CryptoLib.DES.Algorithms.TripleDES
{
    /// <summary>
    /// Реализация алгоритма TripleDES (3DES) по схеме EDE (Encrypt-Decrypt-Encrypt).
    /// Использует три экземпляра стандартного DESAlgorithm.
    /// </summary>
    public class TripleDESAlgorithm : ISymmetricCipher
    {
        // Три независимых экземпляра DES для каждого этапа
        private readonly DESAlgorithm _des1;
        private readonly DESAlgorithm _des2;
        private readonly DESAlgorithm _des3;
        
        private bool _keysSet = false;

        public TripleDESAlgorithm()
        {
            // Инициализируем три "движка" DES
            _des1 = new DESAlgorithm();
            _des2 = new DESAlgorithm();
            _des3 = new DESAlgorithm();
        }

        /// <summary>
        /// Размер блока у 3DES такой же, как у DES — 64 бита (8 байт).
        /// </summary>
        public int BlockSize => 8;

        /// <summary>
        /// Размер ключа для 3-Key TripleDES — 192 бита (24 байта).
        /// </summary>
        public int KeySize => 24;

        /// <summary>
        /// Разбивает 24-байтный ключ на три части по 8 байт и настраивает экземпляры DES.
        /// </summary>
        /// <param name="key">Ключ длиной 24 байта.</param>
        public void SetRoundKeys(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
                
            if (key.Length != KeySize)
                throw new ArgumentException($"TripleDES key must be {KeySize} bytes (192 bits).");

            // Выделяем память под три су-ключа
            byte[] key1 = new byte[8];
            byte[] key2 = new byte[8];
            byte[] key3 = new byte[8];

            // Копируем байты: 
            // 0..7 -> key1
            // 8..15 -> key2
            // 16..23 -> key3
            Array.Copy(key, 0, key1, 0, 8);
            Array.Copy(key, 8, key2, 0, 8);
            Array.Copy(key, 16, key3, 0, 8);

            // Настраиваем каждый DES экземпляр
            _des1.SetRoundKeys(key1);
            _des2.SetRoundKeys(key2);
            _des3.SetRoundKeys(key3);

            _keysSet = true;
        }

        /// <summary>
        /// Шифрование блока: C = E3( D2( E1(P) ) )
        /// </summary>
        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            // 1. Encrypt with Key 1
            byte[] stage1 = _des1.EncryptBlock(block);
            
            // 2. Decrypt with Key 2
            byte[] stage2 = _des2.DecryptBlock(stage1);
            
            // 3. Encrypt with Key 3
            byte[] result = _des3.EncryptBlock(stage2);

            return result;
        }

        /// <summary>
        /// Дешифрование блока: P = D1( E2( D3(C) ) )
        /// Операция обратная шифрованию.
        /// </summary>
        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");

            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            // Обратный порядок действий:
            
            // 1. Decrypt with Key 3
            byte[] stage1 = _des3.DecryptBlock(block);
            
            // 2. Encrypt with Key 2
            byte[] stage2 = _des2.EncryptBlock(stage1);
            
            // 3. Decrypt with Key 1
            byte[] result = _des1.DecryptBlock(stage2);

            return result;
        }
    }
}