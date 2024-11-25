#ifndef HEADER_H
#define HEADER_H

#include <vector>
#include <string>

// Уникальный маркер для начала нового массива
extern std::vector<unsigned char> marker;

// Специальный символ для экранирования
extern const unsigned char escapeChar;

// Функция для экранирования маркера в данных
std::vector<unsigned char> escapeMarker(const std::vector<unsigned char>& data);

// Функция для восстановления маркера в данных
std::vector<unsigned char> unescapeMarker(const std::vector<unsigned char>& escapedData);

// Функция для чтения данных из файла
std::vector<std::vector<unsigned char>> Read(std::string Name);

// Функция для записи данных в файл
bool CreateBin(std::vector<std::vector<unsigned char>> q,  std::string Name);

#endif // HEADER_H