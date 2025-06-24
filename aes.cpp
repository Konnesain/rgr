#include "aes.h"

void aesAddRoundKey(std::vector<std::vector<uint8_t>>& block, const std::vector<std::vector<uint8_t>>& key)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            block[i][j] ^= key[i][j];
        }
    }
}

void aesSubBytes(std::vector<std::vector<uint8_t>>& block, bool inverted)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            uint8_t a = block[i][j] / 16;
            uint8_t b = block[i][j] % 16;
            if (inverted)
                block[i][j] = INV_SBOX[a][b];
            else
                block[i][j] = SBOX[a][b];
        }
    }
}

void aesShift(std::vector<uint8_t>& row)
{
    uint8_t t = row[0];
    for (int i = 0; i < 3; i++)
    {
        row[i] = row[i + 1];
    }
    row[3] = t;
}

void aesInvShift(std::vector<uint8_t>& row)
{
    uint8_t t = row[3];
    for (int i = 3; i >= 1; i--)
    {
        row[i] = row[i - 1];
    }
    row[0] = t;
}

void aesShiftRows(std::vector<std::vector<uint8_t>>& block, bool inverted)
{
    for (int i = 1; i < 4; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (inverted)
                aesInvShift(block[i]);
            else
                aesShift(block[i]);
        }
    }
}

void aesMixColumns(std::vector<std::vector<uint8_t>>& block, bool inverted)
{
    uint8_t t[4];
    for (int i = 0; i < 4; i++)
    {
        if (inverted)
        {
            t[0] = MULTABLE_E[block[0][i]] ^ MULTABLE_B[block[1][i]] ^ MULTABLE_D[block[2][i]] ^ MULTABLE_9[block[3][i]];
            t[1] = MULTABLE_9[block[0][i]] ^ MULTABLE_E[block[1][i]] ^ MULTABLE_B[block[2][i]] ^ MULTABLE_D[block[3][i]];
            t[2] = MULTABLE_D[block[0][i]] ^ MULTABLE_9[block[1][i]] ^ MULTABLE_E[block[2][i]] ^ MULTABLE_B[block[3][i]];
            t[3] = MULTABLE_B[block[0][i]] ^ MULTABLE_D[block[1][i]] ^ MULTABLE_9[block[2][i]] ^ MULTABLE_E[block[3][i]];
        }
        else
        {
            t[0] = MULTABLE_2[block[0][i]] ^ MULTABLE_3[block[1][i]] ^ block[2][i] ^ block[3][i];
            t[1] = block[0][i] ^ MULTABLE_2[block[1][i]] ^ MULTABLE_3[block[2][i]] ^ block[3][i];
            t[2] = block[0][i] ^ block[1][i] ^ MULTABLE_2[block[2][i]] ^ MULTABLE_3[block[3][i]];
            t[3] = MULTABLE_3[block[0][i]] ^ block[1][i] ^ block[2][i] ^ MULTABLE_2[block[3][i]];
        }
        for (int j = 0; j < 4; j++)
        {
            block[j][i] = t[j];
        }
    }
}

std::vector<std::vector<std::vector<uint8_t>>> aesGenerateRoundKeys(const std::vector<std::vector<uint8_t>>& key)
{
    std::vector<std::vector<std::vector<uint8_t>>> keys;
    keys.push_back(key);
    for (int k = 1; k <= 10; k++)
    {
        keys.push_back(std::vector<std::vector<uint8_t>>(4, std::vector<uint8_t>(4)));
        std::vector<uint8_t> rot{ keys[k - 1][0][3], keys[k - 1][1][3], keys[k - 1][2][3], keys[k - 1][3][3] };
        aesShift(rot);
        for (int i = 0; i < 4; i++)
        {
            rot[i] = SBOX[rot[i] / 16][rot[i] % 16];
        }
        keys[k][0][0] = keys[k - 1][0][0] ^ rot[0] ^ RCON[k - 1];
        keys[k][1][0] = keys[k - 1][1][0] ^ rot[1] ^ 0x0;
        keys[k][2][0] = keys[k - 1][2][0] ^ rot[2] ^ 0x0;
        keys[k][3][0] = keys[k - 1][3][0] ^ rot[3] ^ 0x0;
        for (int i = 1; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                keys[k][j][i] = keys[k - 1][j][i] ^ keys[k][j][i - 1];
            }
        }
    }
    return keys;
}

void aesReadBlock(std::ifstream &ifs, std::vector<std::vector<uint8_t>> &block)
{
    char textBlock[16];
    ifs.read(reinterpret_cast<char*>(&textBlock), 16);
    for(int i = ifs.gcount(); i < 16; i++)
    {
        textBlock[i] = 0;
    }
    for (int i = 0; i < 16; i++)
    {
        int c = i / 4;
        int r = i % 4;
        block[r][c] = textBlock[i];//input[r+4c];
    }
}

void aesWriteBlock(std::ofstream &ofs, const std::vector<std::vector<uint8_t>> &block)
{
    char textBlock[16];
    for (int i = 0; i < 16; i++)
    {
        int c = i / 4;
        int r = i % 4;
        textBlock[i] = block[r][c];
    }
    ofs.write(textBlock, 16);
}

void aesEncryptBlock(std::vector<std::vector<uint8_t>>& block, const std::vector<std::vector<std::vector<uint8_t>>>& keys)
{
    aesAddRoundKey(block, keys[0]);
    for (int i = 1; i <= 9; i++)
    {
        aesSubBytes(block, false);
        aesShiftRows(block, false);
        aesMixColumns(block, false);
        aesAddRoundKey(block, keys[i]);
    }
    aesSubBytes(block, false);
    aesShiftRows(block, false);
    aesAddRoundKey(block, keys[10]);
}

void aesEncryptCBCText(const std::string &text, std::ofstream &ofs, const std::vector<std::vector<uint8_t>>& key, const std::vector<std::vector<uint8_t>>& iv)
{
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для зашифрованного текста не существует");
    if(text == "")
        return;

    auto keys = aesGenerateRoundKeys(key);
    std::vector<std::vector<uint8_t>> prevBlock(4, std::vector<uint8_t>(4));
    aesTextToBlock(text, prevBlock, 0);
    aesAddRoundKey(prevBlock, iv);
    aesEncryptBlock(prevBlock, keys);
    aesWriteBlock(ofs, prevBlock);

    std::vector<std::vector<uint8_t>> block(4, std::vector<uint8_t>(4));
    for(size_t offset = 16; offset < text.size(); offset += 16)
    {
        aesTextToBlock(text, block, offset);
        aesAddRoundKey(block, prevBlock);
        aesEncryptBlock(block, keys);
        aesWriteBlock(ofs, block);
        prevBlock = block;
    }
}

void aesEncryptCBCFile(std::ifstream &ifs, std::ofstream &ofs, const std::vector<std::vector<uint8_t>>& key, const std::vector<std::vector<uint8_t>>& iv)
{
    if(!ifs.is_open())
        throw std::invalid_argument("Файл для шифрования не существует");
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для зашифрованного текста не существует");
    if(ifs.peek() == EOF)
        return;

    auto keys = aesGenerateRoundKeys(key);
    std::vector<std::vector<uint8_t>> prevBlock(4, std::vector<uint8_t>(4));
    aesReadBlock(ifs,prevBlock);
    aesAddRoundKey(prevBlock, iv);
    aesEncryptBlock(prevBlock, keys);
    aesWriteBlock(ofs, prevBlock);

    std::vector<std::vector<uint8_t>> block(4, std::vector<uint8_t>(4));
    while(ifs.peek() != EOF)
    {
        aesReadBlock(ifs, block);
        aesAddRoundKey(block, prevBlock);
        aesEncryptBlock(block, keys);
        aesWriteBlock(ofs, block);
        prevBlock = block;
    }
}

void aesDecryptBlock(std::vector<std::vector<uint8_t>>& block, const std::vector<std::vector<std::vector<uint8_t>>>& keys)
{
    aesAddRoundKey(block, keys[10]);
    aesShiftRows(block, true);
    aesSubBytes(block, true);
    for (int i = 9; i >= 1; i--)
    {
        aesAddRoundKey(block, keys[i]);
        aesMixColumns(block, true);
        aesShiftRows(block, true);
        aesSubBytes(block, true);
    }
    aesAddRoundKey(block, keys[0]);
}

void aesDecryptCBC(std::ifstream &ifs, std::ofstream &ofs, const std::vector<std::vector<uint8_t>>& key, const std::vector<std::vector<uint8_t>>& iv)
{
    if(!ifs.is_open())
        throw std::invalid_argument("Файл для расшифрования не существует");
    if(!ofs.is_open())
        throw std::invalid_argument("Файл для расшифрованного текста не существует");
    if(ifs.peek() == EOF)
        return;

    std::vector<std::vector<uint8_t>> block(4, std::vector<uint8_t>(4));
    aesReadBlock(ifs, block);
    std::vector<std::vector<uint8_t>> prevBlock = block;
    auto keys = aesGenerateRoundKeys(key);
    aesDecryptBlock(block, keys);
    aesAddRoundKey(block, iv);
    aesWriteBlock(ofs, block);
    while(ifs.peek() != EOF)
    {
        aesReadBlock(ifs, block);
        std::vector<std::vector<uint8_t>> copyBlock = block;
        aesDecryptBlock(block, keys);
        aesAddRoundKey(block, prevBlock);
        aesWriteBlock(ofs, block);
        prevBlock = copyBlock;
    }
}

void aesTextToBlock(const std::string &text, std::vector<std::vector<uint8_t>> &block, size_t offset)
{
    size_t size = std::min(text.size() - offset, (size_t)16);
    for (size_t i = 0; i < size; i++)
    {
        auto c = i / 4;
        auto r = i % 4;
        block[r][c] = text[i + offset];
    }
    for(size_t i = text.size() - offset; i < 16; i++)
    {
        auto c = i / 4;
        auto r = i % 4;
        block[r][c] = 0;
    }
}

std::vector<std::vector<uint8_t>> aesGenerateBlock(std::mt19937 &rng)
{
    std::uniform_int_distribution<uint8_t> dist(1, 255);
    std::vector<std::vector<uint8_t>> block(4, std::vector<uint8_t>(4));
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            block[i][j] = dist(rng);
        }
    }
    return block;
}