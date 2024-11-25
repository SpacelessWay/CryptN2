#ifndef GENERATEPUBLICKEY_H
#define GENERATEPUBLICKEY_H

#include <openssl/bn.h>
#include <vector>


std::vector<unsigned char> bignum_to_vector(const BIGNUM* bn);

void generatePublicKey(std::string password, BIGNUM** N, BIGNUM** e);

#endif // GENERATEPUBLICKEY_H
