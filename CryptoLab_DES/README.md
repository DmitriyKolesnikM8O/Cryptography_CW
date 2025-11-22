Структура:

```
CryptoLab_DES/
│
├── CryptoLib/                   # библиотека с реализацией DES/DEAL
│   ├── Core/
│   │   └── BitPermutation.cs
│   ├── Interfaces/
│   │   ├── IKeyScheduler.cs
│   │   ├── IFeistelFunction.cs
│   │   ├── ISymmetricCipher.cs
│   ├── Algorithms/
│   │   ├── FeistelNetwork.cs
│   │   ├── FeistelNetworkDeal.cs
│   │   ├── DES/
│   │   │   ├── DESTables.cs
│   │   │   ├── DESKeyScheduler.cs
│   │   │   ├── DESFeistelFunction.cs
│   │   │   └── DESAlgorithm.cs
│   │   └── DEAL/
│   │       ├── DEALAlgorithm.cs
│   │       ├── DEALKeyScheduler.cs
│   │       ├── DESAdapter.cs
│   │       └── DEALFeistelFunction.cs
│   ├── Modes/
│   │   ├── CipherContext.cs
│   │   ├── CipherMode.cs
│   │   └── PaddingMode.cs
│   └── CryptoLib.csproj
│
├── CryptoDemo/                   # консольное демо для лабораторной
│   ├── Program.cs
│   └── CryptoDemo.csproj
│
├── CryptoTests/                  # модульные тесты
│   ├── BitPermutationTests.cs
│   ├── DESTests.cs
│   ├── DEALTests.cs
│   └── CryptoTests.csproj
│
├── CryptoLab_DES.sln
│
├── README.md
│
└── ...
```


