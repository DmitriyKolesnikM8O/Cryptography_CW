тутььь будетььььь лабаьььь (мммммм, может бытьььььь)

```
Cryptography_RSA/
│
├── Cryptography_RSA.sln                 # Файл решения (Solution)
│
├── CryptoLib/                           # Проект: Библиотека классов (ядро)
│   │
│   ├── Interfaces/                      # Директория для всех публичных интерфейсов
│   │   ├── ICryptoMathService.cs        # (Задание 1) Интерфейс базовых мат. операций
│   │   ├── IPrimalityTest.cs            # (Задание 2) Интерфейс для тестов простоты
│   │   ├── IRsaService.cs               # (Задание 3) Интерфейс для RSA сервиса
│   │   └── IWienersAttackService.cs     # (Задание 4) Интерфейс для атаки Винера
│   │
│   ├── Core/                            # Директория для базовых сервисов и утилит
│   │   └── CryptoMathService.cs         # (Задание 1) Реализация ICryptoMathService
│   │
│   ├── Primality/                       # Директория для всего, что связано с тестами простоты
│   │   ├── PrimalityTestBase.cs         # (Задание 2) Абстрактный класс ("Шаблонный метод")
│   │   └── Implementations/             # Реализации конкретных тестов
│   │       ├── FermatTest.cs            #   - Тест Ферма
│   │       ├── SoloveyStrassenTest.cs   #   - Тест Соловея-Штрассена
│   │       └── MillerRabinTest.cs       #   - Тест Миллера-Рабина
│   │
│   ├── RSA/                             # Директория для реализации алгоритма RSA
│   │   ├── RsaService.cs                # (Задание 3) Основной сервис (шифрование/дешифрование)
│   │   ├── RsaKeyGenerator.cs           # (Задание 3) Вложенный сервис для генерации ключей
│   │   └── Models/                      # Модели данных для RSA
│   │       ├── RsaPublicKey.cs          #   - Модель открытого ключа (E, N)
│   │       ├── RsaPrivateKey.cs         #   - Модель закрытого ключа (D, N)
│   │       └── RsaKeyPair.cs            #   - Модель для хранения пары ключей
│   │
│   ├── Attacks/                         # Директория для реализации криптографических атак
│   │   ├── WienersAttackService.cs      # (Задание 4) Реализация атаки Винера
│   │   └── Models/                      # Модели данных для результатов атаки
│   │       ├── ContinuedFraction.cs     #   - Модель для подходящих дробей
│   │       └── WienersAttackResult.cs   #   - Модель для хранения результата атаки
│   │
│   ├── Enums/                           # Директория для общих перечислений
│   │   └── PrimalityTestType.cs         # (Задание 3) Типы тестов (Fermat, SoloveyStrassen, MillerRabin)
│   │
│   └── CryptoLib.csproj                 # Файл проекта библиотеки
│
├── CryptoDemo/                          # Проект: Консольное приложение для демонстрации
│   │
│   ├── Program.cs                       # Точка входа, оркестратор демонстраций
│   ├── Demos/                           # Классы для демонстрации каждого задания
│   │   ├── Task1_MathServiceDemo.cs     # Демонстрация работы CryptoMathService
│   │   ├── Task2_PrimalityTestsDemo.cs  # Демонстрация тестов простоты
│   │   ├── Task3_RsaDemo.cs             # Демонстрация генерации ключей, шифрования и дешифрования
│   │   └── Task4_WienersAttackDemo.cs   # Демонстрация атаки Винера на уязвимый ключ
│   │
│   └── CryptoDemo.csproj                # Файл проекта демонстрации
│
├── CryptoTests/                         # Проект: Модульные тесты (xUnit/NUnit/MSTest)
│   │
│   ├── Core/                            # Тесты для базовых сервисов
│   │   └── CryptoMathServiceTests.cs
│   │
│   ├── Primality/                       # Тесты для тестов простоты
│   │   └── PrimalityTests.cs
│   │
│   ├── RSA/                             # Тесты для RSA
│   │   ├── RsaKeyGeneratorTests.cs
│   │   └── RsaServiceTests.cs
│   │
│   ├── Attacks/                         # Тесты для атак
│   │   └── WienersAttackServiceTests.cs
│   │
│   └── CryptoTests.csproj               # Файл проекта тестов
│
└── README.md                            # Описание проекта
```



доказательства для всего:
теорема ферма, малая теорема ферма
мультипликативность эйлера
китайская теорема об остатках