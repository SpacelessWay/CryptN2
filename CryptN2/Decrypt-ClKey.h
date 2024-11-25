#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <vector>
#include <string>
//#include "Decrypt-ClKey.cpp"
// ������� ��� �������������� ������ � ������ ������
std::vector<unsigned char> string_to_byte_vector( std::string str);
// ������� ��� XOR-����������/�������������
std::vector<unsigned char> xor_encrypt_decrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);
// ��������� ��� �������� ��������� ����� � ����� N
struct KeyPair {
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> NKey;
};
// ������� ��� ���������� ��������� �����
KeyPair GetKey(std::string password);

#endif // CRYPTOUTILS_H