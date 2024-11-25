#ifndef DECRYPT_H
#define DECRYPT_H

#include <string>
#include <vector>
#include <openssl/bn.h>

std::vector<unsigned char> FromZip(const std::string& filePath, const std::string& Name);
std::vector<unsigned char> montgomery_decrypt(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& d, const std::vector<unsigned char>& N);
std::vector<unsigned char> hash_data(const std::vector<unsigned char>& data);
// Основная функция для шифрования файла
bool Decrypt(std::string filePath, std::string password, BIGNUM* N, BIGNUM* e, std::string TofilePath);

#endif // DECRYPT_H
