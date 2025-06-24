#include <iostream>
#include <string>
#include <codecvt>
#include <locale>
#include <vector>
#include <fstream>
#include <cstdint>
#include <random>
#include "dlfcn.h"

using namespace std;

enum class CipherType
{
    AES = 1,
    TRANSPOSITION,
    VIGINERE
};

enum class AESOption
{
    INPUTKEY = 1,
    FILEKEY,
    RANDOMKEY,
    ENCRYPTTEXT,
    ENCRYPTFILE,
    DECRYPT
};
typedef void (*aesReadBlock)(ifstream&, vector<vector<uint8_t>>&);
typedef void (*aesWriteBlock)(ofstream&, const vector<vector<uint8_t>>&);
typedef void (*aesEncryptCBCText)(const string&, ofstream&, const vector<vector<uint8_t>>&, const vector<vector<uint8_t>>&);
typedef void (*aesEncryptCBCFile)(ifstream&, ofstream&, const vector<vector<uint8_t>>&, const vector<vector<uint8_t>>&);
typedef void (*aesDecryptCBC)(ifstream&, ofstream&, const vector<vector<uint8_t>>&, const vector<vector<uint8_t>>&);
typedef vector<vector<uint8_t>> (*aesGenerateBlock)(mt19937&);
typedef void (*aesTextToBlock)(const string&, vector<vector<uint8_t>>&, size_t);

enum class TranspositionOption
{
    INPUTKEY = 1,
    FILEKEY,
    RANDOMKEY,
    ENCRYPTTEXT,
    ENCRYPTFILE,
    DECRYPT
};
typedef void (*transpositionEncryptText)(const string&, ofstream&, size_t, const vector<int>&);
typedef void (*transpositionEncryptFile)(ifstream&, ofstream&, size_t, const vector<int>&);
typedef void (*transpositionDecrypt)(ifstream&, ofstream&, size_t, const vector<int>&);
typedef vector<int>(*transpositionGenerateKey)(size_t, mt19937&);

enum class ViginereOption
{
    INPUTKEY = 1,
    FILEKEY,
    RANDOMKEY,
    ENCRYPTTEXT,
    ENCRYPTFILE,
    DECRYPT
};
typedef void (*viginereEncryptText)(const string&, ofstream&, const vector<char>&);
typedef void (*viginereEncryptFile)(ifstream&, ofstream&, const vector<char>&);
typedef void (*viginereDecrypt)(ifstream&, ofstream&, const vector<char>&);
typedef vector<char>(*viginereGenerateKey)(size_t, mt19937&);

bool openLibrary(void* &libraryHandle, const char* libraryName)
{
    libraryHandle = dlopen(libraryName, RTLD_LAZY);
    return libraryHandle;
}

template<typename T>
bool getFunction(void* &libraryHandle, T &function, const char *functionName)
{
    function = reinterpret_cast<T>(dlsym(libraryHandle, functionName));
    return function;
}

int main()
{
    while(1)
    {
        cout << "1 - AES128CBC\n";
        cout << "2 - Шифрование зафиксированной перестановкой\n";
        cout << "3 - Шифр Вижинера\n";
        cout << "Иначе - Выход\n";
        int cipherCode;
        cin >> cipherCode;
        CipherType cipher = static_cast<CipherType>(cipherCode);

        switch (cipher)
        {
        case CipherType::AES:
        {
            void* libraryHandle;
            if(!openLibrary(libraryHandle, "rgraes.so"))
            {
                cout << "Не удалось открыть библиотеку: " << dlerror() << "\n";
                break;
            }

            aesDecryptCBC decryptFunc;
            aesEncryptCBCFile encryptFileFunc;
            aesEncryptCBCText encryptTextFunc;
            aesGenerateBlock generateBlockFunc;
            aesReadBlock readBlockFunc;
            aesWriteBlock writeblockFunc;
            aesTextToBlock textToBlockFunc;
            if(!getFunction(libraryHandle, decryptFunc, "aesDecryptCBC") ||
            !getFunction(libraryHandle, encryptFileFunc, "aesEncryptCBCFile") ||
            !getFunction(libraryHandle, encryptTextFunc, "aesEncryptCBCText") ||
            !getFunction(libraryHandle, generateBlockFunc, "aesGenerateBlock") ||
            !getFunction(libraryHandle, readBlockFunc, "aesReadBlock") ||
            !getFunction(libraryHandle, writeblockFunc, "aesWriteBlock") ||
            !getFunction(libraryHandle, textToBlockFunc, "aesTextToBlock"))
            {
                cout << "Не удалось найти функцию: " << dlerror() << "\n";
                if(dlclose(libraryHandle) != 0)
                {
                    cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                    std::exit(1);
                }
                break;
            }

            vector<vector<uint8_t>> key(4, vector<uint8_t>(4));
            vector<vector<uint8_t>> iv(4, vector<uint8_t>(4));
            bool hasKey = false;
            bool exit = false;
            while(!exit)
            {
                cout << "1 - Ввод ключей\n";
                cout << "2 - Получение ключей из файла\n";
                cout << "3 - Генерация ключей\n";
                cout << "4 - Шифрование текста\n";
                cout << "5 - Шифрование файла\n";
                cout << "6 - Дешифрование\n";
                cout << "Иначе - Назад\n";

                int optionCode;
                cin >> optionCode;
                AESOption option = static_cast<AESOption>(optionCode);
                switch(option)
                {
                    case AESOption::INPUTKEY:
                    {
                        cout << "Введите ключ(будет обрезан до 128 бит)\n";
                        string keyStr;
                        cin >> keyStr;
                        textToBlockFunc(keyStr, key, 0);
                        cout << "Введите IV(будет обрезан до 128бит)\n";
                        string ivStr;
                        cin >> ivStr;
                        textToBlockFunc(ivStr, iv, 0);
                        cout << "Записать в файл(Y/N)?\n";
                        string choice;
                        cin >> choice;
                        if(choice == "Y" || choice == "y")
                        {
                            cout << "Введите файл для ключей\n";
                            string keyFile;
                            cin >> keyFile;
                            ofstream ofs(keyFile, ios::trunc | ios::binary);
                            if(!ofs.is_open())
                            {
                                cout << "Файл не существует\n";
                                break;
                            }
                            writeblockFunc(ofs, key);
                            writeblockFunc(ofs, iv);
                            ofs.close();
                        }
                        hasKey = true;
                        break;
                    }
                    case AESOption::FILEKEY:
                    {
                        cout << "Введите файл с ключами\n";
                        string keyFile;
                        cin >> keyFile;
                        ifstream ifs(keyFile, ios::binary);
                        if(ifs.is_open())
                        {
                            cout << "Не удалось открыть файл\n";
                            break;
                        }
                        readBlockFunc(ifs, key);
                        readBlockFunc(ifs, iv);
                        ifs.close();
                        hasKey = true;
                        break;
                    }
                    case AESOption::RANDOMKEY:
                    {
                        cout << "Введите файл для ключей\n";
                        string keyFile;
                        cin >> keyFile;
                        ofstream ofs(keyFile, ios::binary | ios::trunc);
                        mt19937 rng(time(0));
                        key = generateBlockFunc(rng);
                        iv = generateBlockFunc(rng);
                        writeblockFunc(ofs, key);
                        writeblockFunc(ofs, iv);
                        ofs.close();
                        hasKey = true;
                        break;
                    }
                    case AESOption::ENCRYPTTEXT:
                    {
                        if(!hasKey)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }

                        cout << "Введите текст для шифрования\n";
                        string text;
                        cin.ignore();
                        getline(cin, text);
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptTextFunc(text, ofs, key, iv);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ofs.close();
                            break;
                        }
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case AESOption::ENCRYPTFILE:
                    {
                        if(!hasKey)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }

                        cout << "Введите файл для шифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        if(originalFile == encryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptFileFunc(ifs,ofs, key, iv);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case AESOption::DECRYPT:
                    {
                        if(!hasKey)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }

                        cout << "Введите файл для дешифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для расшифрованного текста\n";
                        string decryptFile;
                        cin >> decryptFile;
                        if(originalFile == decryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(decryptFile, ios::trunc | ios::binary);
                        try
                        {
                            decryptFunc(ifs,ofs, key, iv);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Расшифровано\n";
                        break;
                    }
                    default:
                        exit = true;
                        break;
                }
            }

            if(dlclose(libraryHandle) != 0)
            {
                cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                std::exit(1);
            }
            break;
        }
        case CipherType::TRANSPOSITION:
        {
            void* libraryHandle;
            if(!openLibrary(libraryHandle, "rgrtransposition.so"))
            {
                cout << "Не удалось открыть библиотеку: " << dlerror() << "\n";
                break;
            }

            transpositionEncryptFile encryptFileFunc;
            transpositionEncryptText encryptTextFunc;
            transpositionDecrypt decryptFunc;
            transpositionGenerateKey generateKeyFunc;
            if(!getFunction(libraryHandle, encryptFileFunc, "transpositionEncryptFile") ||
            !getFunction(libraryHandle, encryptTextFunc, "transpositionEncryptText") ||
            !getFunction(libraryHandle, decryptFunc, "transpositionDecrypt") ||
            !getFunction(libraryHandle, generateKeyFunc, "transpositionGenerateKey"))
            {
                cout << "Не удалось найти функцию: " << dlerror() << "\n";
                if(dlclose(libraryHandle) != 0)
                {
                    cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                    std::exit(1);
                }
                break;
            }

            vector<int> key;
            size_t keySize;
            bool exit = false;
            while(!exit)
            {
                cout << "1 - Ввод ключа\n";
                cout << "2 - Получение ключа из файла\n";
                cout << "3 - Генерация ключа\n";
                cout << "4 - Шифрование текста\n";
                cout << "5 - Шифрование файла\n";
                cout << "6 - Дешифрование\n";
                cout << "Иначе - Назад\n";

                int optionCode;
                cin >> optionCode;
                TranspositionOption option = static_cast<TranspositionOption>(optionCode);

                switch(option)
                {
                    case TranspositionOption::INPUTKEY:
                    {
                        cout << "Введите размер ключа\n";
                        cin >> keySize;
                        if(keySize < 2)
                        {
                            cout << "Неверный размер ключа\n";
                            break;
                        }
                        key = vector<int>(keySize);
                        cout << "Введите числа задающие перестановку\n";
                        for(auto i = 0; i < keySize; i++)
                        {
                            cin >> key[i];
                        }

                        cout << "Записать в файл(Y/N)?\n";
                        string choice;
                        cin >> choice;
                        if(choice == "Y" || choice == "y")
                        {
                            cout << "Введите файл для ключа\n";
                            string keyFile;
                            cin >> keyFile;
                            ofstream ofs(keyFile, ios::trunc | ios::binary);
                            if(!ofs.is_open())
                            {
                                cout << "Файл не существует\n";
                                break;
                            }
                            ofs.write(reinterpret_cast<char*>(&keySize), sizeof(keySize));
                            for(auto k : key)
                            {
                                ofs.write(reinterpret_cast<char*>(&k), sizeof(k));
                            }
                            ofs.close();
                        }
                        break;
                    }
                    case TranspositionOption::FILEKEY:
                    {
                        cout << "Введите файл с ключом\n";
                        string keyFile;
                        cin >> keyFile;
                        ifstream ifs(keyFile, ios::binary);
                        if(!ifs.is_open())
                        {
                            cout << "Файл не существует\n";
                            break;
                        }
                        ifs.read(reinterpret_cast<char*>(&keySize), sizeof(keySize));
                        key = vector<int>(keySize);
                        for(int i = 0; i < keySize; i++)
                        {
                            ifs.read(reinterpret_cast<char*>(&key[i]), sizeof(key[i]));
                        }
                        ifs.close();
                        break;
                    }
                    case TranspositionOption::RANDOMKEY:
                    {
                        cout << "Введите файл для ключа\n";
                        string keyFile;
                        cin >> keyFile;
                        ofstream ofs(keyFile, ios::trunc | ios::binary);
                        if(!ofs.is_open())
                        {
                            cout << "Файл не существует\n";
                            break;
                        }
                        cout << "Введите размер ключа\n";
                        cin >> keySize;
                        mt19937 rng(time(0));
                        try
                        {
                            key = generateKeyFunc(keySize, rng);
                        }
                        catch(invalid_argument e)
                        {
                            keySize = 0;
                            cout << e.what() << "\n";
                            ofs.close();
                            break;
                        }
                        ofs.write(reinterpret_cast<char*>(&keySize), sizeof(keySize));
                        cout << "Ключ: ";
                        for(auto k : key)
                        {
                            cout << k << " ";
                            ofs.write(reinterpret_cast<char*>(&k), sizeof(k));
                        }
                        cout << "\n";
                        ofs.close();
                        break;
                    }
                    case TranspositionOption::ENCRYPTTEXT:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }
                        cout << "Введите текст для шифрования\n";
                        string text;
                        cin.ignore();
                        getline(cin, text);
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptTextFunc(text, ofs, keySize, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ofs.close();
                            break;
                        }
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case TranspositionOption::ENCRYPTFILE:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }
                        cout << "Введите файл для шифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        if(originalFile == encryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptFileFunc(ifs,ofs, keySize, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case TranspositionOption::DECRYPT:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }
                        cout << "Введите файл для дешифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для расшифрованного текста\n";
                        string decryptFile;
                        cin >> decryptFile;
                        if(originalFile == decryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(decryptFile, ios::trunc | ios::binary);
                        try
                        {
                            decryptFunc(ifs,ofs, keySize, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Расшифровано\n";
                        break;
                    }
                    default:
                        exit = true;
                        break;
                }
            }

            if(dlclose(libraryHandle) != 0)
            {
                cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                std::exit(1);
            }
            break;
        }
        case CipherType::VIGINERE:
        {
            void* libraryHandle;
            if(!openLibrary(libraryHandle, "rgrviginere.so"))
            {
                cout << "Не удалось открыть библиотеку: " << dlerror() << "\n";
                break;
            }

            viginereDecrypt decryptFunc;
            viginereEncryptFile encryptFileFunc;
            viginereEncryptText encryptTextFunc;
            viginereGenerateKey generateKeyFunc;
            if(!getFunction(libraryHandle, decryptFunc, "viginereDecrypt") ||
            !getFunction(libraryHandle, encryptTextFunc, "viginereEncryptText") ||
            !getFunction(libraryHandle, encryptFileFunc, "viginereEncryptFile") ||
            !getFunction(libraryHandle, generateKeyFunc, "viginereGenerateKey"))
            {
                cout << "Не удалось найти функцию: " << dlerror() << "\n";
                if(dlclose(libraryHandle) != 0)
                {
                    cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                    std::exit(1);
                }
                break;
            }

            vector<char> key;
            bool exit = false;
            while(!exit)
            {
                cout << "1 - Ввести ключ\n";
                cout << "2 - Получить ключ из файла\n";
                cout << "3 - Генерация ключа\n";
                cout << "4 - Шифрование текста\n";
                cout << "5 - Шифрование файла\n";
                cout << "6 - Дешифрование\n";
                cout << "Иначе - Назад\n";
                int optionCode;
                cin >> optionCode;
                ViginereOption option = static_cast<ViginereOption>(optionCode);
                switch(option)
                {
                    case ViginereOption::INPUTKEY:
                    {
                        cout << "Введите ключ\n";
                        string tkey;
                        cin >> tkey;
                        key = vector<char>(tkey.begin(), tkey.end());
                        cout << "Записать в файл(Y/N)?\n";
                        string choice;
                        cin >> choice;
                        if(choice == "Y" || choice == "y")
                        {
                            cout << "Введите файл для ключа\n";
                            string keyFile;
                            cin >> keyFile;
                            ofstream ofs(keyFile, ios::trunc | ios::binary);
                            if(!ofs.is_open())
                            {
                                cout << "Файл не существует\n";
                                break;
                            }
                            for(char k : key)
                            {
                                ofs.write(&k, 1);
                            }
                            ofs.close();
                        }
                        break;
                    }
                    case ViginereOption::FILEKEY:
                    {
                        cout << "Введите файл с ключом\n";
                        string keyFile;
                        cin >> keyFile;
                        ifstream ifs(keyFile, ios::binary);
                        if(!ifs.is_open())
                        {
                            cout << "Файл не существует\n";
                            break;
                        }
                        key = vector<char>((istreambuf_iterator<char>(ifs)), istreambuf_iterator<char>());
                        ifs.close();
                        break;
                    }
                    case ViginereOption::RANDOMKEY:
                    {
                        cout << "Введите файл для ключа\n";
                        string keyFile;
                        cin >> keyFile;
                        ofstream ofs(keyFile, ios::binary | ios::trunc);
                        if(!ofs.is_open())
                        {
                            cout << "Файл не существует\n";
                            break;
                        }
                        cout << "Введите размер ключа\n";
                        size_t keySize;
                        cin >> keySize;
                        mt19937 rng(time(0));
                        try
                        {
                            key = generateKeyFunc(keySize, rng);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ofs.close();
                            break;
                        }
                        for(char k : key)
                        {
                            ofs.write(&k, 1);
                        }
                        ofs.close();
                        break;
                    }
                    case ViginereOption::ENCRYPTTEXT:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }

                        cout << "Введите текст для шифрования\n";
                        string text;
                        cin.ignore();
                        getline(cin, text);
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptTextFunc(text, ofs, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ofs.close();
                            break;
                        }
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case ViginereOption::ENCRYPTFILE:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }
                        cout << "Введите файл для шифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для зашифрованного текста\n";
                        string encryptFile;
                        cin >> encryptFile;
                        if(originalFile == encryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(encryptFile, ios::trunc | ios::binary);
                        try
                        {
                            encryptFileFunc(ifs,ofs, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Зашифровано\n";
                        break;
                    }
                    case ViginereOption::DECRYPT:
                    {
                        if(key.size() == 0)
                        {
                            cout << "Ключ не задан\n";
                            break;
                        }
                        cout << "Введите файл для дешифрования\n";
                        string originalFile;
                        cin >> originalFile;
                        cout << "Введите файл для расшифрованного текста\n";
                        string decryptFile;
                        cin >> decryptFile;
                        if(originalFile == decryptFile)
                        {
                            cout << "Файлы не должны совпадать\n";
                        }
                        ifstream ifs(originalFile, ios::binary);
                        ofstream ofs(decryptFile, ios::trunc | ios::binary);
                        try
                        {
                            decryptFunc(ifs, ofs, key);
                        }
                        catch(invalid_argument e)
                        {
                            cout << e.what() << "\n";
                            ifs.close();
                            ofs.close();
                            break;
                        }
                        ifs.close();
                        ofs.close();
                        cout << "Расшифровано\n";
                        break;
                        break;
                    }
                    default:
                        exit = true;
                        break;
                }
            }

            if(dlclose(libraryHandle) != 0)
            {
                cout << "Не удалось закрыть библиотеку: " << dlerror() << "\n";
                std::exit(1);
            }
            break;
        }
        default:
            return 0;
        }
    }
    return 2;//idk
}