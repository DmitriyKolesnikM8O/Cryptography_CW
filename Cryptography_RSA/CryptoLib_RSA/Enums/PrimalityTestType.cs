namespace CryptoLib.RSA.Enums
{
    /// <summary>
    /// Определяет тип вероятностного теста простоты для использования
    /// при генерации ключей RSA.
    /// </summary>
    public enum PrimalityTestType
    {
        Fermat,
        SoloveyStrassen,
        MillerRabin
    }
}