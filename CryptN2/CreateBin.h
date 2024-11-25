#ifndef HEADER_H
#define HEADER_H

#include <vector>
#include <string>

// ���������� ������ ��� ������ ������ �������
extern std::vector<unsigned char> marker;

// ����������� ������ ��� �������������
extern const unsigned char escapeChar;

// ������� ��� ������������� ������� � ������
std::vector<unsigned char> escapeMarker(const std::vector<unsigned char>& data);

// ������� ��� �������������� ������� � ������
std::vector<unsigned char> unescapeMarker(const std::vector<unsigned char>& escapedData);

// ������� ��� ������ ������ �� �����
std::vector<std::vector<unsigned char>> Read(std::string Name);

// ������� ��� ������ ������ � ����
bool CreateBin(std::vector<std::vector<unsigned char>> q,  std::string Name);

#endif // HEADER_H