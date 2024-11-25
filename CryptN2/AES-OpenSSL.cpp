#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <vector>
#include <string>

// Функция для генерации ключа и IV из парольной фразы
void derive_key_and_iv(const std::string& password, const std::vector<unsigned char>& salt,
    unsigned char* key, unsigned char* iv) {
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    int key_len = EVP_CIPHER_key_length(cipher);
    int iv_len = EVP_CIPHER_iv_length(cipher);

    EVP_BytesToKey(cipher, EVP_sha256(), salt.data(),
        reinterpret_cast<const unsigned char*>(password.data()), password.size(),
        1, key, iv);
}

// Функция для шифрования данных
std::vector<unsigned char> encrypt(const std::string& password, const std::vector<unsigned char>& data) {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    std::vector<unsigned char> salt(8);
    std::vector<unsigned char> encrypted_data;

    // Генерация случайной соли
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw std::runtime_error("Ошибка генерации соли");
    }

    // Генерация ключа и IV из парольной фразы и соли
    derive_key_and_iv(password, salt, key, iv);

    // Инициализация контекста шифрования
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Ошибка создания контекста шифрования");
    }

    // Инициализация шифрования
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка инициализации шифрования");
    }

    // Резервирование места для зашифрованных данных
    encrypted_data.resize(data.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int encrypted_len;
    if (EVP_EncryptUpdate(ctx, encrypted_data.data(), &encrypted_len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка шифрования данных");
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted_data.data() + encrypted_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка завершения шифрования");
    }

    encrypted_len += final_len;
    encrypted_data.resize(encrypted_len);

    // Добавление соли в начало зашифрованных данных
    encrypted_data.insert(encrypted_data.begin(), salt.begin(), salt.end());

    EVP_CIPHER_CTX_free(ctx);
    return encrypted_data;
}

/*int main() {
    // Пример закрытого ключа (в реальности это может быть любой набор данных)
    std::vector<unsigned char> private_key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    // Парольная фраза
    std::string password = "my_secret_password";

    try {
        // Шифрование закрытого ключа
        std::vector<unsigned char> encrypted_key = encrypt(password, private_key);

        // Сохранение зашифрованного ключа в файл (криптоконтейнер)
        std::ofstream out_file("encrypted_key.bin", std::ios::binary);
        if (!out_file) {
            throw std::runtime_error("Ошибка открытия файла для записи");
        }
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