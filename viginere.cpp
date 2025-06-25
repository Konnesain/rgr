#include "viginere.h"

void viginereEncryptText(const std::string &text, std::ofstream &ofs, const std::vector<char> &key)
{
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для зашифрованного текста не существует");

    auto blockSize = key.size();
    char block[blockSize];
    size_t textSize = text.size();
    for(int offset = 0; offset < textSize; offset += blockSize)
    {
        auto count = std::min(textSize - offset, blockSize);
        for(auto i = 0; i < count; i++)
        {
            block[i] = text[i+offset];
        }
        for(auto i = 0; i < count; i++)
        {
            block[i] += key[i];
        }
        ofs.write(reinterpret_cast<char*>(block), count);
    }
}

void viginereEncryptFile(std::ifstream &ifs, std::ofstream &ofs, const std::vector<char> &key)
{
    if(!ifs.is_open())
        throw std::invalid_argument("Файл для шифрования не существует");
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для зашифрованного текста не существует");

    auto blockSize = key.size();
    char block[blockSize];
    while(ifs.peek() != EOF)
    {
        auto count = ifs.read(reinterpret_cast<char*>(block), blockSize).gcount();
        for(auto i = 0; i < count; i++)
        {
            block[i] += key[i];
        }
        ofs.write(reinterpret_cast<char*>(block), count);
    }
}

void viginereDecrypt(std::ifstream &ifs, std::ofstream &ofs, const std::vector<char> &key)
{
    if(!ifs.is_open())
        throw std::invalid_argument("Файл для расшифрования не существует");
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для расшифрованного текста не существует");
    
    auto blockSize = key.size();
    char block[blockSize];
    while(ifs.peek() != EOF)
    {
        auto count = ifs.read(reinterpret_cast<char*>(block), blockSize).gcount();
        for(auto i = 0; i < count; i++)
        {
            block[i] -= key[i];
        }
        ofs.write(reinterpret_cast<char*>(block), count);
    }
}

std::vector<char> viginereGenerateKey(size_t keySize, std::mt19937 &rng)
{
    std::vector<char> key;
    if(keySize < 1 || keySize > key.max_size())
    {
        throw std::invalid_argument("Неверный размер ключа, размер должен быть в диапазоне [1;" + std::to_string(key.max_size()) + "]");
    }
    
    key.resize(keySize);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for(int i = 0; i < keySize; i++)
    {
        key[i] = dist(rng);
    }
    return key;
}