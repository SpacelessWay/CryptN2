#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string>
#include <vector>
#include <openssl/bn.h>
std::vector<unsigned char> hash_file(const std::string& filename);
// ������� ��� ���������� ����� ������������ ������
std::vector<unsigned char> encrypt_file(const std::string& filePath, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);

// �������� ������� ��� ���������� �����
bool Encrypt(std::string filePath, std::string password, BIGNUM* N, BIGNUM* e, std::string TofilePath);

#endif // ENCRYPT_H
