#include <iostream>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <fstream>
#include "AES-CB.h"

// Функция для быстрого возведения в степень по модулю
BIGNUM* modPow(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mod_exp(result, base, exp, mod, ctx);
    return result;
}

// Оптимизированный тест Миллера-Рабина с использованием OpenSSL
bool millerRabinTest(const BIGNUM* n, int k) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* d = BN_dup(n);
    BN_sub_word(d, 1);

    while (BN_is_bit_set(d, 0) == 0) {
        BN_rshift1(d, d);
    }

    for (int i = 0; i < k; i++) {
        BIGNUM* a = BN_new();
        BIGNUM* x = BN_new();
        BIGNUM* n_minus_4 = BN_new();
        BN_sub_word(n_minus_4, 4);
        BN_rand_range(a, n_minus_4);
        BN_add_word(a, 2);

        x = modPow(a, d, n, ctx);

        if (BN_cmp(x, BN_value_one()) == 0 || BN_cmp(x, d) == 0) {
            BN_free(a);
            BN_free(x);
            BN_free(n_minus_4);
            continue;
        }

        bool prime = false;
        BIGNUM* r = BN_new();
        BN_set_word(r, 1);

        BIGNUM* two = BN_new();
        BN_set_word(two, 2);

        while (BN_cmp(r, d) < 0) {
            x = modPow(x, two, n, ctx);
            if (BN_cmp(x, d) == 0) {
                prime = true;
                break;
            }
            BN_lshift1(r, r);
        }

        BN_free(a);
        BN_free(x);
        BN_free(n_minus_4);
        BN_free(r);
        BN_free(two);

        if (!prime) {
            BN_CTX_free(ctx);
            BN_free(d);
            return false;
        }
    }

    BN_CTX_free(ctx);
    BN_free(d);
    return true;
}

// Функция для генерации случайного числа заданной длины
BIGNUM* generateRandomNumber(int bits) {
    BIGNUM* num = BN_new();
    unsigned char* buffer = new unsigned char[bits / 8];
    RAND_bytes(buffer, bits / 8);
    BN_bin2bn(buffer, bits / 8, num);
    delete[] buffer;
    return num;
}

// Функция для генерации простого числа заданной длины
BIGNUM* generatePrimeNumber(int bits) {
    BIGNUM* prime = BN_new();
    do {
        BN_free(prime);
        prime = generateRandomNumber(bits);
        BN_add_word(prime, 1);
    } while (!millerRabinTest(prime, 20));
    return prime;
}

// Функция для генерации числа FN = (p-1) * (q-1)
BIGNUM* generateFN(const BIGNUM* p, const BIGNUM* q) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p_minus_1 = BN_dup(p);
    BIGNUM* q_minus_1 = BN_dup(q);
    BIGNUM* N = BN_new();

    BN_sub_word(p_minus_1, 1);
    BN_sub_word(q_minus_1, 1);

    BN_mul(N, p_minus_1, q_minus_1, ctx);

    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);

    return N;
}
BIGNUM* generateN(const BIGNUM* p, const BIGNUM* q) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N = BN_new();
    BN_mul(N, p, q, ctx);
    BN_CTX_free(ctx);
    return N;
}
// Функция для генерации числа e, которое меньше FN и взаимно простое с FN
BIGNUM* generateE(const BIGNUM* FN) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* e = BN_new();
    BIGNUM* gcd = BN_new();

    do {
        // Генерируем случайное число e, которое меньше FN
        BN_pseudo_rand_range(e, FN);

        // Проверяем, что e взаимно простое с FN
        BN_gcd(gcd, e, FN, ctx);
    } while (BN_cmp(gcd, BN_value_one()) != 0);

    BN_free(gcd);
    BN_CTX_free(ctx);

    return e;
}

// Функция для генерации закрытого ключа d
BIGNUM* generateCloseKey(const BIGNUM* e, const BIGNUM* FN) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* d = BN_mod_inverse(NULL, e, FN, ctx);
    if (d == NULL) {
        std::cerr << "Ошибка при вычислении обратного элемента." << std::endl;
    }
    BN_CTX_free(ctx);
    return d;
}
std::vector<unsigned char> bignum_to_vector(const BIGNUM* bn) {
    int len = BN_num_bytes(bn);
    std::vector<unsigned char> result(len);
    BN_bn2bin(bn, result.data());
    return result;
}

void generatePublicKey(std::string password, BIGNUM** N, BIGNUM** e) {
    int bits = 512; // Длина простых чисел в битах

    BIGNUM* p = generatePrimeNumber(bits);
    BIGNUM* q = generatePrimeNumber(bits);
    *e = generatePrimeNumber(bits);
    BIGNUM* FN= generateFN(p, q);
    *N = generateN(p, q);
    //BN_free(p);
    //BN_free(q);
    char* N_str = BN_bn2dec(*N);
    char* e_str = BN_bn2dec(*e);

    std::ofstream outFile("public_key.txt");
    if (outFile.is_open()) {
        outFile << "N:" << N_str << std::endl;
        outFile << "e:" << e_str << std::endl;
        outFile.close();
        std::cout << "Значения N и e save в файл public_key.txt" << std::endl;
    }
    else {
        std::cerr << "Не удалось открыть файл для записи." << std::endl;
    }
    //OPENSSL_free(N_str);
    //OPENSSL_free(e_str);

    BIGNUM* d = generateCloseKey(*e, FN);
    //BN_free(FN);
    
    
    std::vector<unsigned char> ds = bignum_to_vector(d);
    std::vector<unsigned char> Ns = bignum_to_vector(*N);
    std::ofstream outFile1("public_key_r.txt");
    if (outFile1.is_open()) {
        outFile1 << "p:" << BN_bn2dec(p) << std::endl;
        outFile1 << "q:" << BN_bn2dec(q) << std::endl;
        outFile1 << "N:" << N_str << std::endl;
        outFile1 << "e:" << e_str << std::endl;
        outFile1 << "FN:" << BN_bn2dec(FN) << std::endl;
        outFile1 << "d:" << BN_bn2dec(d) << std::endl;
        outFile1.close();
        std::cout << "Значения N и e save в файл public_key.txt" << std::endl;
    }
    else {
        std::cerr << "Не удалось открыть файл для записи." << std::endl;
    }
    BN_free(d);
    GenBox(password, ds,Ns);
    std::vector<unsigned char>().swap(ds);
    

    
}


