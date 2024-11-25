#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <vector>
#include <string>

// ������� ��� ��������� ���������� ������� ������������� (IV)
//std::vector<unsigned char> generate_iv();

// ������� ��� ��������� ��������� ����
//std::vector<unsigned char> generate_salt();

// ������� ��� ��������� ����� �� ��������� ����� � ����
std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt);

// ������� ������� ��� ���������� ������ � �������������� AES-256 � ������ CBC
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
void GenBox(std::string password, std::vector<unsigned char> private_key, std::vector<unsigned char> N);

#endif // AES_ENCRYPTION_H
