#pragma once

#include <fstream>
#include <vector>
#include <exception>
#include <random>

#ifdef __cplusplus
extern "C" {
#endif

void viginereEncryptText(const std::string &text, std::ofstream &ofs, const std::vector<char> &key);

void viginereEncryptFile(std::ifstream &ifs, std::ofstream &ofs, const std::vector<char> &key);

void viginereDecrypt(std::ifstream &ifs, std::ofstream &ofs, const std::vector<char> &key);

std::vector<char> viginereGenerateKey(size_t keySize, std::mt19937 &rng);

#ifdef __cplusplus
}
#endif