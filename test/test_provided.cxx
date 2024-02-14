#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "doctest/doctest.h"

#include "drivers/crypto_driver.hpp"

TEST_CASE("sample1")
{
    CHECK(true);
}

TEST_CASE("sample2")
{
    auto driver = CryptoDriver{};
    const auto &[dh, sk, pk] = driver.DH_initialize(driver.DH_generate_params());

    const auto dhShared = driver.DH_generate_shared_key(dh, sk, pk);

    auto aeskey = driver.AES_generate_key(dhShared);
    auto plaintext = std::string{"abcdefg"};

    const auto &[ciphertext, iv] = driver.AES_encrypt(aeskey, std::move(plaintext));

}

TEST_CASE("sample3")
{

}