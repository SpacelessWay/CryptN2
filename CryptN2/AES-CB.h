#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <vector>
#include <string>

// Функция для генерации случайного вектора инициализации (IV)
//std::vector<unsigned char> generate_iv();

// Функция для генерации случайной соли
//std::vector<unsigned char> generate_salt();

// Функция для генерации ключа из парольной фразы и соли
std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt);

// Простая функция для шифрования данных с использованием AES-256 в режиме CBC
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
void GenBox(std::string password, std::vector<unsigned char> private_key, std::vector<unsigned char> N);

#endif // AES_ENCRYPTION_H
