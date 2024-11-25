#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <vector>
#include <string>
//#include "Decrypt-ClKey.cpp"
// Функция для преобразования строки в вектор байтов
std::vector<unsigned char> string_to_byte_vector( std::string str);
// Функция для XOR-шифрования/расшифрования
std::vector<unsigned char> xor_encrypt_decrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);
// Структура для хранения закрытого ключа и ключа N
struct KeyPair {
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> NKey;
};
// Функция для дешифровки закрытого ключа
KeyPair GetKey(std::string password);

#endif // CRYPTOUTILS_H