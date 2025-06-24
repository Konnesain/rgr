#include "transposition.h"

bool transpositionKeyCheck(size_t keySize, const std::vector<int> &key)
{
	if(keySize < 2)
		return false;

	for(int i = 1; i <= keySize; i++)
	{
		if(std::find(key.begin(), key.end(), i) == key.end())
		{
			return false;
		}
	}
	return true;
}

void transpositionEncryptText(const std::string &text, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key)
{
	if(!ofs.is_open())
		throw std::invalid_argument("Файл для зашифрованного текста не существует");
	if(!transpositionKeyCheck(blockSize, key))
		throw std::invalid_argument("Неверный ключ");
	
	char encryptedBlock[blockSize];
	char block[blockSize];
	auto textSize = text.size();
	for(auto offset = 0; offset < textSize; offset += blockSize)
	{
		int count = std::min(textSize - offset, blockSize);
		for(size_t i = 0; i < count; i++)
		{
			block[i] = text[i + offset];
		}
		for(size_t i = count; i < blockSize; i++)
		{
			block[i] = 0x00;
		}
		for (size_t i = 0; i < blockSize; i++)
		{
			encryptedBlock[i] = block[key[i]-1];
		}
		ofs.write(encryptedBlock, blockSize);
	}
}

void transpositionEncryptFile(std::ifstream &ifs, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key)
{
	if(!ifs.is_open())
		throw std::invalid_argument("Файл для шифрования не существует");
	if(!ofs.is_open())
		throw std::invalid_argument("Файл для зашифрованного текста не существует");
	if(!transpositionKeyCheck(blockSize, key))
		throw std::invalid_argument("Неверный ключ");
	
	char encryptedBlock[blockSize];
	char block[blockSize];
	while(ifs.peek() != EOF)
	{
		int count = ifs.read(block, blockSize).gcount();
		for(size_t i = count; i < blockSize; i++)
		{
			block[i] = 0x00;
		}
		for (size_t i = 0; i < blockSize; i++)
		{
			encryptedBlock[i] = block[key[i]-1];
		}
		ofs.write(encryptedBlock, blockSize);
	}
}

void transpositionDecrypt(std::ifstream &ifs, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key)
{
	if(!ifs.is_open())
		throw std::invalid_argument("Файл для расшифрования не существует");
	if(!ofs.is_open())
		throw std::invalid_argument("Файл для расшифрованного текста не существует");
	if(!transpositionKeyCheck(blockSize, key))
		throw std::invalid_argument("Неверный ключ");

	char decryptedBlock[blockSize];
	char block[blockSize];
	while(ifs.peek() != EOF)
	{
		if(ifs.read(block, blockSize).gcount() != blockSize)
		{
			throw std::invalid_argument("Проблема с зашифрованным файлом");
		}
		for (size_t i = 0; i < blockSize; i++)
		{
			decryptedBlock[key[i]-1] = block[i];
		}
		ofs.write(decryptedBlock, blockSize);
	}
}

std::vector<int> transpositionGenerateKey(size_t keySize, std::mt19937 &rng)
{
	if(keySize < 2)
	{
		throw std::invalid_argument("Неверный размер ключа");
	}
	
	std::vector<int> key(keySize);
    std::iota(key.begin(), key.end(), 1);
    std::shuffle(key.begin(), key.end(), rng);
    return key;
}