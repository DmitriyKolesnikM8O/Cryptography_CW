Батарейки

```
CryptoCoursework/
│
├── CryptoCoursework.sln
│
├─📂 1_DES_Project/  
│  ├─ CryptoLib_DES/
│  │  ├─ ... (все папки Core, Interfaces, Modes)
│  │  └─ Algorithms/
│  │     ├─ DES/
│  │     ├─ DEAL/
│  │     └─ TripleDES/                     # [П.1 НОВОЕ]
│  │        └─ TripleDESAlgorithm.cs
│  ├─ CryptoDemo_DES/                      
│  └─ CryptoTests_DES/                     
│     └─ TripleDESTests.cs                 # [П.1 НОВОЕ]
│
├─📂 2_RSA_Project/  (Solution Folder)
│  ├─ CryptoLib_RSA/                       
│  ├─ CryptoDemo_RSA/                      
│  └─ CryptoTests_RSA/                     
│
├─📂 3_Rijndael_Project/ (Solution Folder)
│  ├─ CryptoLib_Rijndael/                  
│  ├─ CryptoDemo_Rijndael/                 
│  └─ CryptoTests_Rijndael/                
│
├─📂 4_Coursework_New/ (Solution Folder для новых заданий)
│  ├─ CryptoLib_New/                       # Библиотека для RC4, LOKI97, DH
│  │  ├─ Interfaces/                       # [СКОПИРОВАНО из CryptoLib_DES]
│  │  ├─ Modes/                            # [СКОПИРОВАНО из CryptoLib_DES]
│  │  ├─ Algorithms/
│  │  │  ├─ LOKI97/
│  │  │  └─ RC4/
│  │  └─ Protocols/
│  │     └─ DiffieHellman/
│  └─ CryptoTests_New/                     # [НОВОЕ] Проект для тестов RC4, LOKI97, DH
│     ├─ LOKI97Tests.cs
│     ├─ RC4Tests.cs
│     └─ DiffieHellmanTests.cs
│
└─📂 5_Final_Demonstration/ (Solution Folder)
   └─ CryptoConsole/                       # Главное консольное приложение курсовой
      ├─ Program.cs                        # Меню для запуска демонстраций
      └─ Demos/
         ├─ Task1_DesDemo.cs
         ├─ Task2_RsaDemo.cs
         ├─ Task3_RijndaelDemo.cs
         ├─ Task4_DiffieHellmanDemo.cs
         ├─ Task5_Rc4Demo.cs
         └─ Task6_Loki97Demo.cs
```


TO_DO:
- добавить аналогичные тесты Advanced в RSA