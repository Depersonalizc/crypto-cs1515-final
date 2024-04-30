#pragma once

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <tuple>

#include <cryptopp/cryptlib.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/hmac.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/sha.h>

#include "../../include-shared/messages.hpp"

using namespace CryptoPP;

class CryptoDriver {
public:
    DHParams_Message DH_generate_params();

    std::tuple<DH, SecByteBlock, SecByteBlock>
    DH_initialize(const DHParams_Message &DH_params);

    SecByteBlock
    DH_generate_shared_key(const DH &DH_obj, const SecByteBlock &DH_private_value,
                           const SecByteBlock &DH_other_public_value);

    SecByteBlock AES_generate_key(const SecByteBlock &sharedKey);

    std::pair<std::string, SecByteBlock> AES_encrypt(SecByteBlock key,
                                                     std::string plaintext);

    std::string AES_decrypt(SecByteBlock key, SecByteBlock iv,
                            std::string ciphertext);

    SecByteBlock HMAC_generate_key(const SecByteBlock &sharedKey);

    std::string HMAC_generate(SecByteBlock key, std::string ciphertext);

    bool HMAC_verify(SecByteBlock key, std::string ciphertext, std::string hmac);
};
