#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <iomanip>
#include <openssl/sha.h>
#include "Decrypt-ClKey.h"
#include "GeneratePublicKey.h"
#include "AES-CB.h"
#include <zip.h>
#include <filesystem> // ��� ������ � ������
#include <openssl/types.h>


namespace fs = std::filesystem;

// ������� ��� ����������� �����
std::vector<unsigned char> hash_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error �����: " << filename << std::endl;
        return std::vector<unsigned char>();
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[1024];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash.data(), &sha256);

    file.close();
    return hash;
}

// ������� ��� ������������ ���� �������� ������ �� ��������� ����������
std::vector<unsigned char> montgomery_encrypt(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& d, const std::vector<unsigned char>& N) {
    // ������� ���������� ��������� ����������
    // � �������� ����������� ����������� ����������� ����������
    std::vector<unsigned char> result(hash.size());
    for (size_t i = 0; i < hash.size(); ++i) {
        result[i] = hash[i] ^ d[i % d.size()] ^ N[i % N.size()];
    }
    return result;
}

// ������� ��� ��������� ���������������� �������� ������������� ����� 128 ���
std::vector<unsigned char> generate_symmetric_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);

    std::vector<unsigned char> key(16); // 128 ��� = 16 ����
    for (unsigned char& byte : key) {
        byte = static_cast<unsigned char>(dis(gen));
    }

    return key;
}

// ������� ��� ���������� ����� ������������ ������
std::vector<unsigned char> encrypt_file(const std::string& filePath, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "������ �������� �����: " << filePath << std::endl;
        return std::vector<unsigned char>();
    }

    std::vector<unsigned char> file_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::vector<unsigned char> encrypted_data = encrypt(file_data, key, iv);

    return encrypted_data;
}

// ������� ��� �������� ZIP-������
bool create_zip(const std::string& zipFilePath, const std::vector<unsigned char>& encData, const std::vector<unsigned char>& keyData, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& signatureData) {
    int err = 0;
    zip_t* zip = zip_open(zipFilePath.c_str(), ZIP_CREATE | ZIP_TRUNCATE, &err);
    if (!zip) {
        std::cerr << "������ �������� ZIP-������: " << zipFilePath << std::endl;
        return false;
    }

    // ���������� �������������� ����� � ZIP
    zip_source_t* source = zip_source_buffer(zip, encData.data(), encData.size(), 0);
    if (!source) {
        std::cerr << "������ �������� ��������� ������ ��� �������������� �����" << std::endl;
        zip_close(zip);
        return false;
    }
    if (zip_file_add(zip, "encrypted_file", source, ZIP_FL_ENC_UTF_8) < 0) {
        std::cerr << "������ ���������� �������������� ����� � ZIP" << std::endl;
        zip_source_free(source);
        zip_close(zip);
        return false;
    }

    // ���������� �������������� �����  � ZIP
    source = zip_source_buffer(zip, keyData.data(), keyData.size(), 0);
    if (!source) {
        std::cerr << "������ �������� ��������� ������ ��� �������������� �����" << std::endl;
        zip_close(zip);
        return false;
    }
    if (zip_file_add(zip, "encrypted_key", source, ZIP_FL_ENC_UTF_8) < 0) {
        std::cerr << "������ ���������� �������������� ����� � ZIP" << std::endl;
        zip_source_free(source);
        zip_close(zip);
        return false;
    }
    // ���������� IV � ZIP
    source = zip_source_buffer(zip, iv.data(), iv.size(), 0);
    if (!source) {
        std::cerr << "������ �������� ��������� ������ ��� iv" << std::endl;
        zip_close(zip);
        return false;
    }
    if (zip_file_add(zip, "encrypted_key_iv", source, ZIP_FL_ENC_UTF_8) < 0) {
        std::cerr << "������ ���������� �������������� ����� � ZIP" << std::endl;
        zip_source_free(source);
        zip_close(zip);
        return false;
    }

    // ���������� �������� ������� � ZIP
    source = zip_source_buffer(zip, signatureData.data(), signatureData.size(), 0);
    if (!source) {
        std::cerr << "������ �������� ��������� ������ ��� �������� �������" << std::endl;
        zip_close(zip);
        return false;
    }
    if (zip_file_add(zip, "signature", source, ZIP_FL_ENC_UTF_8) < 0) {
        std::cerr << "������ ���������� �������� ������� � ZIP" << std::endl;
        zip_source_free(source);
        zip_close(zip);
        return false;
    }

    if (zip_close(zip) < 0) {
        std::cerr << "������ �������� ZIP-������" << std::endl;
        return false;
    }

    return true;
}

// �������� ������� ��� ���������� �����
bool Encrypt(std::string filePath, std::string password, BIGNUM* N, BIGNUM* e, std::string TofilePath) {
     KeyPair k = GetKey(password);
     std::vector<unsigned char> d= k.privateKey;
     std::vector<unsigned char> Nd = k.NKey;
    if (d.empty()) {
        std::cerr << "Error key" << std::endl;
        std::string().swap(password);
        return false;
    }
    std::string().swap(password);
    std::vector<unsigned char> Nn = bignum_to_vector(N);
    std::vector<unsigned char> En = bignum_to_vector(e);
    std::vector<unsigned char> hash = hash_file(filePath);
    if (hash.empty()) {
        std::cerr << "Error hesh" << std::endl;
        return false;
    }
    std::vector<unsigned char> encrypted_hash = montgomery_encrypt(hash, d, Nd);
    std::vector<unsigned char>().swap(d);
    std::vector<unsigned char>().swap(hash);

    // ��������� ������������� ����� � IV
    std::vector<unsigned char> symmetric_key = generate_symmetric_key();
    std::vector<unsigned char> iv = generate_symmetric_key(); // IV ����� ������ ���� ���������

    // ���������� ����� ������������ ������
    std::vector<unsigned char> encrypted_data = encrypt_file(filePath, symmetric_key, iv);
    if (encrypted_data.empty()) {
        std::cerr << "Error shifr" << std::endl;
        std::vector<unsigned char>().swap(symmetric_key);
        std::vector<unsigned char>().swap(iv);
        std::string().swap(filePath);
        return false;
    }
    // �������� ������� ���� � ZIP-�����
    fs::path originalFilePath(filePath);
    std::string zipFileName = originalFilePath.filename().string();
    std::string zipFilePath = TofilePath + "/" + zipFileName;
    //std::cerr << TofilePath << std::endl;
    std::string().swap(filePath);
    // �������� ZIP-������
    if (!create_zip(zipFilePath + "!!!.zip", encrypted_data, symmetric_key, iv, encrypted_hash)) {
        std::cerr << "������ �������� ZIP-������" << std::endl;
        return false;
    }
    

    // ���������� ������������� ����� (����� ����� ������������ �������� ���������� ��� ������ ������������� ��������)
    std::vector<unsigned char> encrypted_symmetric_key = montgomery_encrypt(symmetric_key, En, Nn);
    std::vector<unsigned char>().swap(symmetric_key);
    std::vector<unsigned char> encrypted_symmetric_iv = montgomery_encrypt(iv, En, Nn);
    std::vector<unsigned char>().swap(iv);

    // �������� ZIP-������
    if (!create_zip(zipFilePath + ".zip", encrypted_data, encrypted_symmetric_key, encrypted_symmetric_iv, encrypted_hash)) {
        std::cerr << "������ �������� ZIP-������" << std::endl;
        return false;
    }

    return true;
}