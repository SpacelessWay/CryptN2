#include <iostream>
#include <fstream>
#include <vector>

// ���������� ������ ��� ������ ������ �������
std::vector<unsigned char> marker = { 0xDE, 0xAD, 0xBE, 0xEF };

// ����������� ������ ��� �������������
const unsigned char escapeChar = 0x1B;

// ������� ��� ������������� ������� � ������
std::vector<unsigned char> escapeMarker(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> escapedData;
    size_t pos = 0;

    while (pos < data.size()) {
        if (data.size() - pos >= marker.size() && std::equal(marker.begin(), marker.end(), data.begin() + pos)) {
            // ������ ������, ���������� ���
            escapedData.push_back(escapeChar);
            escapedData.insert(escapedData.end(), marker.begin(), marker.end());
            pos += marker.size();
        }
        else {
            // ������ ��������� ���� ������
            escapedData.push_back(data[pos]);
            ++pos;
        }
    }

    return escapedData;
}

// ������� ��� �������������� ������� � ������
std::vector<unsigned char> unescapeMarker(const std::vector<unsigned char>& escapedData) {
    std::vector<unsigned char> data;
    size_t pos = 0;

    while (pos < escapedData.size()) {
        if (escapedData[pos] == escapeChar && escapedData.size() - pos >= marker.size() + 1 &&
            std::equal(marker.begin(), marker.end(), escapedData.begin() + pos + 1)) {
            // ������ �������������� ������, ��������������� ���
            data.insert(data.end(), marker.begin(), marker.end());
            pos += marker.size() + 1;
        }
        else {
            // ������ ��������� ���� ������
            data.push_back(escapedData[pos]);
            ++pos;
        }
    }

    return data;
}

std::vector<std::vector<unsigned char>> Read(std::string Name) {
    std::vector<std::vector<unsigned char>> q;
    // ������ ������ �� �����
    std::ifstream fileRead(Name, std::ios::binary);
    if (!fileRead.is_open()) {
        std::cerr << "�� ������� ������� ���� ��� ������." << std::endl;
        return q;
    }

    while (!fileRead.eof()) {
        std::vector<unsigned char> buffer;
        unsigned char byte;

        // ������ ������ �� �������
        while (fileRead.read(reinterpret_cast<char*>(&byte), 1)) {
            buffer.push_back(byte);
            if (buffer.size() >= marker.size()) {
                bool match = true;
                for (size_t i = 0; i < marker.size(); ++i) {
                    if (buffer[buffer.size() - marker.size() + i] != marker[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    buffer.resize(buffer.size() - marker.size()); // ������� ������ �� ������
                    break;
                }
            }
        }

        // �������������� ������
        std::vector<unsigned char> data = unescapeMarker(buffer);

        q.push_back(data);
    }

    fileRead.close();
    return q;
}

bool CreateBin(std::vector<std::vector<unsigned char>> q, std:: string Name) {
    std::ofstream file(Name, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "�� ������� ������� ���� ��� ������." << std::endl;
        return false;
    }
    for (std::vector<unsigned char> x : q) {
        // ������������� ������ � ������ � ����
        std::vector<unsigned char> escapedData1 = escapeMarker(x);

        file.write(reinterpret_cast<const char*>(escapedData1.data()), escapedData1.size());
        file.write(reinterpret_cast<const char*>(marker.data()), marker.size());
    }
    file.close();
    return true;
}

