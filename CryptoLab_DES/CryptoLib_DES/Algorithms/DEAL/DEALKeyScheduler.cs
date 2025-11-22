using CryptoLib.DES.Interfaces;
using CryptoLib.DES.Algorithms.DES;

namespace CryptoLib.DES.Algorithms.DEAL
{
    /// <summary>
    /// Реализует планировщик ключей для алгоритма DEAL в соответствии с его официальной спецификацией.
    /// Раундовые ключи генерируются криптографически, путем шифрования констант с помощью алгоритма DES,
    /// где в качестве ключа используется основной ключ DEAL.
    /// </summary>
    public class DEALKeyScheduler : IKeyScheduler
    {
        public enum KeyType
        {
            KEY_SIZE_128,
            KEY_SIZE_192,
            KEY_SIZE_256
        }

        private readonly KeyType _keyType;
        private readonly int _rounds;
        
        
        private static readonly byte[] C1 = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
        private static readonly byte[] C2 = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
        private static readonly byte[] C3 = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };

        public DEALKeyScheduler(KeyType keyType)
        {
            _keyType = keyType;
            _rounds = keyType switch
            {
                KeyType.KEY_SIZE_128 => 6,
                KeyType.KEY_SIZE_192 => 8,
                KeyType.KEY_SIZE_256 => 8,
                _ => throw new ArgumentException("Invalid key type")
            };
        }

        /// <summary>
        /// Генерирует набор раундовых ключей из предоставленного основного ключа.
        /// </summary>
        public byte[][] ExpandKey(byte[] inputKey)
        {
            ValidateKeySize(inputKey);

            byte[][] roundKeys = new byte[_rounds][];
            var des = new DESAlgorithm();

            byte[] roundCounterBlock = new byte[8];

            switch (_keyType)
            {
                case KeyType.KEY_SIZE_128:
                {

                    byte[] k1 = GetSubKey(inputKey, 0, 8);
                    byte[] k2 = GetSubKey(inputKey, 8, 8);
                    XorWithConstant(k1, C1);
                    XorWithConstant(k2, C2);

                    for (int i = 0; i < _rounds; i++)
                    {
                        
                        roundCounterBlock[7] = (byte)(i + 1); 
                        
                        if (i % 2 == 0)
                        {
                            des.SetRoundKeys(k1);
                        }
                        else
                        {
                            des.SetRoundKeys(k2);
                        }
                        roundKeys[i] = des.EncryptBlock(roundCounterBlock);
                    }
                    break;
                }
                case KeyType.KEY_SIZE_192:
                {
                    byte[] k1 = GetSubKey(inputKey, 0, 8);
                    byte[] k2 = GetSubKey(inputKey, 8, 8);
                    byte[] k3 = GetSubKey(inputKey, 16, 8);
                    XorWithConstant(k1, C1);
                    XorWithConstant(k2, C2);
                    XorWithConstant(k3, C3);

                    for (int i = 0; i < _rounds; i++)
                    {
                        roundCounterBlock[7] = (byte)(i + 1);
                        
                        des.SetRoundKeys((i % 3) switch
                        {
                            0 => k1,
                            1 => k2,
                            _ => k3
                        });
                        roundKeys[i] = des.EncryptBlock(roundCounterBlock);
                    }
                    break;
                }
                case KeyType.KEY_SIZE_256:
                {

                    for (int i = 0; i < _rounds; i++)
                    {
                        byte[] subKey = GetSubKey(inputKey, (i % 4) * 8, 8);
                        roundKeys[i] = subKey;
                    }
                    break;
                }
            }

            return roundKeys;
        }

        /// <summary>
        /// Вспомогательный метод для извлечения части ключа.
        /// </summary>
        private byte[] GetSubKey(byte[] key, int offset, int length)
        {
            byte[] subKey = new byte[length];
            Array.Copy(key, offset, subKey, 0, length);
            return subKey;
        }

        /// <summary>
        /// Вспомогательный метод для выполнения операции XOR над ключом и константой (in-place).
        /// </summary>
        private void XorWithConstant(byte[] key, byte[] constant)
        {
            for (int i = 0; i < key.Length; i++)
            {
                key[i] ^= constant[i];
            }
        }
        
        /// <summary>
        /// Проверяет, соответствует ли длина предоставленного ключа типу, указанному в конструкторе.
        /// </summary>
        private void ValidateKeySize(byte[] key)
        {
            int expectedSize = _keyType switch
            {
                KeyType.KEY_SIZE_128 => 16,
                KeyType.KEY_SIZE_192 => 24,
                KeyType.KEY_SIZE_256 => 32,
                _ => throw new InvalidOperationException("Unknown key type")
            };

            if (key.Length != expectedSize)
                throw new ArgumentException($"Key must be {expectedSize} bytes for {_keyType}");
        }
    }
}