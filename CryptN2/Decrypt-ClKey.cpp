#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include "AES-CB.h"
#include "CreateBin.h"

// ��������� ��� �������� ��������� ����� � ����� N
struct KeyPair {
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> NKey;
};


// ������� ��� �������������� ������ � ������ ������
std::vector<unsigned char> string_to_byte_vector( std::string str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

// ������� ��� ������ ����, IV � �������������� ��������� ����� �� �����
bool read_encrypted_key_file(const std::string& filename, std::vector<unsigned char>& salt, std::vector<unsigned char>& iv, std::vector<unsigned char>& encrypted_key, std::vector<unsigned char>& N_key) {
    std::ifstream inFile(filename);
    if (!inFile.is_open()) {
        std::cerr << "������ �������� �����: " << filename << std::endl;
        return false;
    }

    std::string line;

    // ������ ����
    if (std::getline(inFile, line)) {
        salt = string_to_byte_vector(line);
    }
    else {
        std::cerr << "������ ������ ���� �� �����." << std::endl;
        return false;
    }

    // ������ IV
    if (std::getline(inFile, line)) {
        iv = string_to_byte_vector(line);
    }
    else {
        std::cerr << "������ ������ IV �� �����." << std::endl;
        return false;
    }

    // ������ �������������� ��������� �����
    if (std::getline(inFile, line)) {
        encrypted_key = string_to_byte_vector(line);
    }
    else {
        std::cerr << "������ ������ �������������� ��������� ����� �� �����." << std::endl;
        return false;
    }
    // ������ �������������� ��������� �����
    if (std::getline(inFile, line)) {
        N_key = string_to_byte_vector(line);
    }
    else {
        std::cerr << "������ ������ N ��������� ����� �� �����." << std::endl;
        return false;
    }

    return true;
}
// ������� ��� ��������� ����� �� ��������� ����� � ����
/*std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32); // 256 ���
    std::memset(key.data(), 0, key.size());
    std::memcpy(key.data(), password.data(), std::min(password.size(), key.size()));

    // ��������� ���� � ��������� �����
    std::vector<unsigned char> salted_password(password.begin(), password.end());
    salted_password.insert(salted_password.end(), salt.begin(), salt.end());

    // ������� ������ ��������� ����� �� ��������� ����� � ����
    // � �������� ����������� ����������� ����� �������� ������, ����� ��� PBKDF2
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] ^= salted_password[i % salted_password.size()];
    }

    return key;
}*/
// ������� ��� XOR-����������/�������������
std::vector<unsigned char> xor_encrypt_decrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

KeyPair GetKey(std::string password) {
    std::vector<unsigned char> salt;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> encrypted_key;
    std::vector<unsigned char> N_key;

    // ������ ����, IV � �������������� ��������� ����� �� �����
    std::vector<std::vector<unsigned char>> q = Read("encrypted_key.bin");
    if (q.empty()) {
        std::vector<unsigned char>().swap(salt);
        std::vector<unsigned char>().swap(iv);
        std::vector<unsigned char>().swap(encrypted_key);
        std::vector<unsigned char>().swap(N_key);
        return { encrypted_key, N_key };
    }
    salt = q[0];
    iv = q[1];
    encrypted_key = q[2];
    N_key = q[3];

    std::vector<unsigned char> key = derive_key(password, salt);
    std::vector<unsigned char>().swap(salt);
    std::string().swap(password);

    encrypted_key = encrypt(encrypted_key, key, iv);
    N_key = encrypt(N_key, key, iv);
    std::vector<unsigned char>().swap(key);
    return { encrypted_key, N_key };
}


