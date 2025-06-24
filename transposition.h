#pragma once
#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include <algorithm>
#include <random>

#ifdef __cplusplus
extern "C" {
#endif

bool transpositionKeyCheck(size_t keySize, const std::vector<int> &key);

void transpositionEncryptText(const std::string &text, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key);

void transpositionEncryptFile(std::ifstream &ifs, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key);

void transpositionDecrypt(std::ifstream &ifs, std::ofstream &ofs, size_t blockSize, const std::vector<int> &key);

std::vector<int> transpositionGenerateKey(size_t keySize, std::mt19937 &rng);

#ifdef __cplusplus
}
#endif