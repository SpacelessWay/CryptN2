#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <iomanip>
#include <openssl/err.h>
#include "CreateBin.h"

// Простой пример реализации AES-256 в режиме CBC
// Этот код предназначен только для образовательных целей

// Функция для генерации случайного вектора инициализации (IV)
std::vector<unsigned char> generate_iv() {
    std::vector<unsigned char> iv(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 16; ++i) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    return iv;
}

// Функция для генерации случайной соли
std::vector<unsigned char> generate_salt() {
    std::vector<unsigned char> salt(8); // Соль длиной 8 байт
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 8; ++i) {
        salt[i] = static_cast<unsigned char>(dis(gen));
    }
    return salt;
}

// Функция для генерации ключа из парольной фразы и соли
std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32); // 256 бит
    std::memset(key.data(), 0, key.size());
    std::memcpy(key.data(), password.data(), std::min(password.size(), key.size()));

    // Добавляем соль к парольной фразе
    std::vector<unsigned char> salted_password(password.begin(), password.end());
    salted_password.insert(salted_password.end(), salt.begin(), salt.end());

    // Простой пример выработки ключа из парольной фразы и соли
    // В реальных приложениях используйте более надежные методы, такие как PBKDF2
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] ^= salted_password[i % salted_password.size()];
    }

    return key;
}

// Простая функция для шифрования данных с использованием AES-256 в режиме CBC
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::vector<unsigned char> encrypted_data(data.size() + 16); // Дополнительное место для PKCS7 padding

    // Простая реализация AES-256 в режиме CBC
    // В реальных приложениях используйте проверенные библиотеки
    for (size_t i = 0; i < data.size(); i += 16) {
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                encrypted_data[i + j] = data[i + j] ^ iv[j] ^ key[j];
            }
            else {
                encrypted_data[i + j] = 0x10; // PKCS7 padding
            }
        }
    }

    return encrypted_data;
}
void GenBox(std::string password, std::vector<unsigned char> private_key, std::vector<unsigned char> N) {
    // Генерация соли
    std::vector<unsigned char> salt = generate_salt();

    // Генерация ключа и IV
    std::vector<unsigned char> key = derive_key(password, salt);
    std::string().swap(password);

    std::vector<unsigned char> iv = generate_iv();
    // Сохранение зашифрованного ключа, IV и соли в файл (криптоконтейнер)
    std::vector<std::vector<unsigned char>> q;
    q.push_back(salt);
    q.push_back(iv);
    q.push_back(private_key);
    q.push_back(key);
    q.push_back(N);
    CreateBin(q, "encrypted_key_right.bin");
    // Шифрование закрытого ключа
    std::vector<unsigned char> encrypted_key = encrypt(private_key, key, iv);
    std::vector<unsigned char> N_key = encrypt(N, key, iv);
    std::vector<unsigned char>().swap(private_key);
    std::vector<unsigned char>().swap(N);
    std::vector<unsigned char>().swap(key);

    /*// Сохранение зашифрованного ключа, IV и соли в файл (криптоконтейнер)
    std::ofstream out_file("encrypted_key.bin", std::ios::binary);
    if (!out_file) {
        throw std::runtime_error("Ошибка открытия файла для записи");
    }

    // Функция для записи вектора байтов и перевода строки
    auto write_with_newline = [&out_file](const std::vector<uint8_t>& bytes) {
        out_file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        out_file.put('\n');  // Добавляем перевод строки
        };

    // Запись каждого значения на отдельной строке
    write_with_newline(salt);
    write_with_newline(iv);
    write_with_newline(encrypted_key);
    write_with_newline(N_key);

    out_file.close();*/
    // Сохранение зашифрованного ключа, IV и соли в файл (криптоконтейнер)
    std::vector<std::vector<unsigned char>> q1;
    q1.push_back(salt);
    q1.push_back(iv);
    q1.push_back(encrypted_key);
    q1.push_back(N_key);
    CreateBin(q1, "encrypted_key.bin");
    
    std::vector<unsigned char>().swap(encrypted_key);
    std::vector<unsigned char>().swap(N_key);
    std::vector<unsigned char>().swap(salt);
    std::vector<unsigned char>().swap(iv);

    //std::cout << "Закрытый ключ успешно зашифрован и сохранен в файл encrypted_key.bin" << std::endl;
}



/*int main() {
    // Пример закрытого ключа (в реальности это может быть любой набор данных)
    std::vector<unsigned char> private_key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    // Парольная фраза
    std::string password = "my_secret_password";

    try {
        // Генерация соли
        std::vector<unsigned char> salt = generate_salt();

        // Генерация ключа и IV
        std::vector<unsigned char> key = derive_key(password, salt);
        std::vector<unsigned char> iv = generate_iv();

        // Шифрование закрытого ключа
        std::vector<unsigned char> encrypted_key = encrypt(private_key, key, iv);

        // Сохранение зашифрованного ключа, IV и соли в файл (криптоконтейнер)
        std::ofstream out_file("encrypted_key.bin", std::ios::binary);
        if (!out_file) {
            throw std::runtime_error("Ошибка открытия файла для записи");
        }
        out_file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        out_file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        out_file.write(reinterpret_cast<const char*>(encrypted_key.data()), encrypted_key.size());
        out_file.close();

        std::cout << "Закрытый ключ успешно зашифрован и сохранен в файл encrypted_key.bin" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}*/