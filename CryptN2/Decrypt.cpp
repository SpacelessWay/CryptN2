#include <iostream>
#include <fstream>
#include <zip.h>
#include <vector>
#include "Decrypt-ClKey.h"
#include "AES-CB.h"
#include "Encrypt.h"
#include <openssl/sha.h>
#include "GeneratePublicKey.h"
#include <openssl/bn.h>
#include <filesystem> // Для работы с путями


namespace fs = std::filesystem;

std::vector<unsigned char> FromZip(const std::string& filePath, const std::string& Name) {
    std::vector<unsigned char> encryptedKey;
    int err = 0;
    zip_t* zip = zip_open(filePath.c_str(), 0, &err);
    if (!zip) {
        std::cerr << "Ошибка открытия ZIP-архива: " << filePath << std::endl;
        return encryptedKey; // Возвращаем пустой вектор в случае ошибки
    }

    // Открываем файл в архиве по имени
    zip_file_t* file = zip_fopen(zip, Name.c_str(), 0);
    if (!file) {
        std::cerr << "Ошибка открытия файла " << Name << " в архиве" << std::endl;
        zip_close(zip);
        return encryptedKey; // Возвращаем пустой вектор в случае ошибки
    }

    // Получаем информацию о файле
    struct zip_stat file_stat;
    if (zip_stat(zip, Name.c_str(), 0, &file_stat) < 0) {
        std::cerr << "Ошибка получения информации о файле " << Name << std::endl;
        zip_fclose(file);
        zip_close(zip);
        return encryptedKey; // Возвращаем пустой вектор в случае ошибки
    }

    // Читаем содержимое файла
    std::vector<char> buffer(file_stat.size);
    if (zip_fread(file, buffer.data(), file_stat.size) < 0) {
        std::cerr << "Ошибка чтения файла " << Name << std::endl;
        zip_fclose(file);
        zip_close(zip);
        return encryptedKey; // Возвращаем пустой вектор в случае ошибки
    }

    // Преобразуем содержимое файла в std::vector<unsigned char>
    encryptedKey.assign(reinterpret_cast<unsigned char*>(buffer.data()), reinterpret_cast<unsigned char*>(buffer.data()) + file_stat.size);

    // Закрываем файл и архив
    zip_fclose(file);
    zip_close(zip);

    return encryptedKey;
}
// Функция для зашифрования хеша закрытым ключом по алгоритму Монтгомери
std::vector<unsigned char> montgomery_decrypt(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& d, const std::vector<unsigned char>& N) {
    // Простая реализация алгоритма Монтгомери
    // В реальных приложениях используйте проверенные библиотеки
    std::vector<unsigned char> result(hash.size());
    for (size_t i = 0; i < hash.size(); ++i) {
        result[i] = hash[i] ^ d[i % d.size()] ^ N[i % N.size()];
    }
    return result;
}

// Функция для хеширования данных в формате std::vector<unsigned char>
std::vector<unsigned char> hash_data(const std::vector<unsigned char>&data) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, data.data(), data.size());

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash.data(), &sha256);

    return hash;
}


// Простая функция для дешифрования данных с использованием XOR и PKCS7 padding
std::vector<unsigned char> decrypt(const std::vector<unsigned char>&encrypted_data, const std::vector<unsigned char>&key, const std::vector<unsigned char>&iv) {
    std::vector<unsigned char> decrypted_data(encrypted_data.size());

    // Простая реализация дешифрования
    for (size_t i = 0; i < encrypted_data.size(); i += 16) {
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < encrypted_data.size()) {
                decrypted_data[i + j] = encrypted_data[i + j] ^ iv[j] ^ key[j];
            }
        }
    }

    // Удаление PKCS7 padding
    size_t padding_length = decrypted_data.back();
    if (padding_length > 0 && padding_length <= 16) {
        decrypted_data.resize(decrypted_data.size() - padding_length);
    }

    return decrypted_data;
}


bool Decrypt( std::string filePath, std::string password,  BIGNUM* N, BIGNUM* e,  std::string TofilePath) {
    std::vector<unsigned char> encryptedKey = FromZip(filePath, "encrypted_key");
    std::vector<unsigned char> encryptedKey_iv = FromZip(filePath, "encrypted_key_iv");
    KeyPair k;
    std::vector<unsigned char> d;
    std::vector<unsigned char> Nd;
    std::vector<unsigned char> decrypted_key;
    std::vector<unsigned char> decrypted_key_iv;
    std::vector<unsigned char> En = bignum_to_vector(e);
    
    if (!encryptedKey.empty()) {
         k = GetKey(password);
         d = k.privateKey;
         Nd = k.NKey;
         std::string().swap(password);
         decrypted_key = montgomery_decrypt(encryptedKey, d, Nd);
         decrypted_key_iv = montgomery_decrypt(encryptedKey, d, Nd);
         std::vector<unsigned char>().swap(d);
         std::vector<unsigned char>().swap(Nd);
         std::cerr << "Succsess key" << std::endl;
    }
    std::string().swap(password);
    std::vector<unsigned char> encrypted_file = FromZip(filePath, "encrypted_file");

    // Deшифровка файла симметричным ключом
    std::vector<unsigned char> decrypted_data = decrypt(encrypted_file, decrypted_key, decrypted_key_iv);
    if (decrypted_data.empty()) {
        std::cerr << "Error shifr" << std::endl;
        std::vector<unsigned char>().swap(decrypted_key);
        std::vector<unsigned char>().swap(decrypted_key_iv);
        std::string().swap(filePath);
        return false;
    }
    std::vector<unsigned char>().swap(decrypted_key);
    std::vector<unsigned char>().swap(decrypted_key_iv);
   
    std::vector<unsigned char> h_file = hash_data(decrypted_data);
    std::vector<unsigned char> Nn = bignum_to_vector(N);
    

    std::vector<unsigned char> sig = FromZip(filePath, "signature");
    std::vector<unsigned char> h_file_2 = montgomery_decrypt(sig, En, Nn);
    /*if (h_file != h_file_2) {
        std::cerr << "Error hesh" << std::endl;
        std::vector<unsigned char>().swap(decrypted_data);
        std::vector<unsigned char>().swap(sig);
        std::vector<unsigned char>().swap(h_file);
        std::vector<unsigned char>().swap(h_file_2);
        return false;
    }*/
    
    std::vector<unsigned char>().swap(sig);
    std::vector<unsigned char>().swap(h_file);
    std::vector<unsigned char>().swap(h_file_2);

    // Создание полного пути к файлу
    fs::path originalFilePath(filePath);
    std::string fFileName = originalFilePath.filename().string();

    // Удаление расширения .zip, если оно есть
    size_t pos = fFileName.find(".zip");
    if (pos != std::string::npos) {
        fFileName = fFileName.substr(0, pos);
    }

    std::string fFilePath = TofilePath + "/" + fFileName;
    std::string().swap(filePath);
    // Сохранение расшифрованного файла
    std::ofstream outFile(fFilePath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Ошибка открытия файла для записи: " << fFilePath << std::endl;
        return false;
    }
    outFile.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
    outFile.close();
    std::vector<unsigned char>().swap(decrypted_data);

    std::cout << "Файл успешно расшифрован и сохранен как " << fFilePath << std::endl;
    return true; // Возвращаем true, если вектор не пустой
}

