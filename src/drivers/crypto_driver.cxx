#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/crypto_driver.hpp"

using namespace CryptoPP;

static auto rngp = AutoSeededRandomPool{};

/**
 * @brief Returns (p, q, g) DH parameters. This function should:
 * 1) Initialize a `CryptoPP::AutoSeededRandomPool` object
 *    and a `CryptoPP::PrimeAndGenerator` object.
 * 2) Generate a prime p, sub-prime q, and generator g
 *    using `CryptoPP::PrimeAndGenerator::Generate(...)`
 *    with a `delta` of 1, a `pbits` of 512, and a `qbits` of 511.
 * 3) Store and return the parameters in a `DHParams_Message` object.
 * @return `DHParams_Message` object that stores Diffie-Hellman parameters
 */
DHParams_Message CryptoDriver::DH_generate_params()
{
    // TO.DO: implement me!
    using namespace CryptoPP;

    const auto primeGen = PrimeAndGenerator{1, rngp, 512, 511};

    auto params = DHParams_Message{};
    params.p = primeGen.Prime();
    params.q = primeGen.SubPrime();
    params.g = primeGen.Generator();

    return params;
}

/**
 * @brief Generate DH keypair. This function should
 * 1) Create a DH object and `SecByteBlock`s for the private and public keys.
 * Use `DH_obj.PrivateKeyLength()` and `PublicKeyLength()` to get key sizes.
 * 2) Generate a DH keypair using the `GenerateKeyPair(...)` method.
 * @param DH_params Diffie-Hellman parameters
 * @return Tuple containing DH object, private value, public value.
 */
std::tuple<DH, SecByteBlock, SecByteBlock>
CryptoDriver::DH_initialize(const DHParams_Message &DH_params)
{
    // TO.DO: implement me!
    auto dh = DH{DH_params.p, DH_params.q, DH_params.g};
    auto sk = SecByteBlock{dh.PrivateKeyLength()};
    auto pk = SecByteBlock{dh.PublicKeyLength()};

    dh.GenerateKeyPair(rngp, sk, pk);

    return {std::move(dh), std::move(sk), std::move(pk)};
}

/**
 * @brief Generates a shared secret. This function should
 * 1) Allocate space in a `SecByteBlock` of size `DH_obj.AgreedValueLength()`.
 * 2) Run `DH_obj.Agree(...)` to store the shared key in the allocated space.
 * 3) Throw an `std::runtime_error` if failed to agree.
 * @param DH_obj Diffie-Hellman object
 * @param DH_private_value user's private value for Diffie-Hellman
 * @param DH_other_public_value other user's public value for Diffie-Hellman
 * @return Diffie-Hellman shared key
 */
SecByteBlock CryptoDriver::DH_generate_shared_key(
        const DH &DH_obj, const SecByteBlock &DH_private_value,
        const SecByteBlock &DH_other_public_value)
{
    // TO.DO: implement me!
    auto shared = SecByteBlock{DH_obj.AgreedValueLength()};
    if (!DH_obj.Agree(shared, DH_private_value, DH_other_public_value)) {
        throw std::runtime_error{"Failed to agree on other party's public key"};
    }
    return shared;
}

/**
 * @brief Generates AES key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `AES::DEFAULT_KEYLENGTH`.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for AES using the
 * provided salt. See the `DeriveKey` function. (Use NULL for the "info"
 * argument and 0 for "infolen".)
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key Diffie-Hellman shared key
 * @return AES key
 */
SecByteBlock CryptoDriver::AES_generate_key(const SecByteBlock &DH_shared_key)
{
    const auto aesSalt = std::string{"salt0000"};

    // TO.DO: implement me!
    auto aesKey = SecByteBlock{AES::DEFAULT_KEYLENGTH};

    HKDF<SHA256>{}.DeriveKey(aesKey, aesKey.size(),
                             DH_shared_key, DH_shared_key.size(),
                             reinterpret_cast<const byte *>(aesSalt.data()), aesSalt.size(), nullptr, 0);

    return aesKey;
}

/**
 * @brief Encrypts the given plaintext. This function should:
 * 1) Initialize `CBC_Mode<AES>::Encryption` using GetNextIV and SetKeyWithIV.
 * 1.5) IV should be of size `AES::BLOCKSIZE`
 * 2) Run the plaintext through a `StreamTransformationFilter` using
 * the AES encryptor.
 * 3) Return ciphertext and iv used in encryption or throw an
 * `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param plaintext text to encrypt
 * @return Pair of ciphertext and iv
 */
std::pair<std::string, SecByteBlock>
CryptoDriver::AES_encrypt(SecByteBlock key, std::string plaintext)
{
    try {
        using namespace CryptoPP;

        // TODO: implement me!
        CBC_Mode<AES>::Encryption enc;

        // Set key with IV
        auto iv = SecByteBlock{AES::BLOCKSIZE};
        enc.GetNextIV(rngp, iv);
        enc.SetKeyWithIV(key, key.size(), iv, iv.size());

        // Encode
        std::string ciphertext;
        StringSource ss{plaintext, true,
                        new StreamTransformationFilter{enc,
                                                       new StringSink{ciphertext}
                        } // StreamTransformationFilter
        }; // StringSource

        return {std::move(ciphertext), std::move(iv)};

    } catch (const CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "This function was likely called with an incorrect shared key."
                  << std::endl;
        throw std::runtime_error("CryptoDriver AES encryption failed.");
    }
}

/**
 * @brief Decrypts the given ciphertext, encoded as a hex string. This function
 * should:
 * 1) Initialize `CBC_Mode<AES>::Decryption` using `SetKeyWithIV` on the key and
 * iv. 2) Run the decoded ciphertext through a `StreamTransformationFilter`
 * using the AES decryptor.
 * 3) Return the plaintext or throw an `std::runtime_error`.
 * 4) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param key AES key
 * @param iv iv used in encryption
 * @param ciphertext text to decrypt
 * @return decrypted message
 */
std::string CryptoDriver::AES_decrypt(SecByteBlock key, SecByteBlock iv,
                                      std::string ciphertext)
{
    try {
        using namespace CryptoPP;

        // TODO: implement me!
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, iv.size());

        std::string plaintext;
        StringSource ss{ciphertext, true,
                        new StreamTransformationFilter{dec,
                                                       new StringSink{plaintext}
                        } // StreamTransformationFilter
        }; // StringSource

        return plaintext;

    } catch (const CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "This function was likely called with an incorrect shared key."
                  << std::endl;
        throw std::runtime_error("CryptoDriver AES decryption failed.");
    }
}

/**
 * @brief Generates an HMAC key using HKDF with a salt. This function should
 * 1) Allocate a `SecByteBlock` of size `SHA256::BLOCKSIZE` for the shared key.
 * 2) Use an `HKDF<SHA256>` to derive and return a key for HMAC using the
 * provided salt. See the `DeriveKey` function.
 * 3) Important tip: use .size() on a SecByteBlock instead of sizeof()
 * @param DH_shared_key shared key from Diffie-Hellman
 * @return HMAC key
 */
SecByteBlock
CryptoDriver::HMAC_generate_key(const SecByteBlock &DH_shared_key)
{
    const auto hmacSalt = std::string{"salt0001"};
    // TODO: implement me!

    auto hmacKey = SecByteBlock{AES::DEFAULT_KEYLENGTH};

    HKDF<SHA256>{}.DeriveKey(hmacKey, hmacKey.size(),
                             DH_shared_key, DH_shared_key.size(),
                             reinterpret_cast<const byte *>(hmacSalt.data()), hmacSalt.size(), nullptr, 0);

    return hmacKey;
}

/**
 * @brief Given a ciphertext, generates an HMAC. This function should
 * 1) Initialize an HMAC<SHA256> with the provided key.
 * 2) Run the ciphertext through a `HashFilter` to generate an HMAC.
 * 3) Throw `std::runtime_error` upon failure.
 * @param key HMAC key
 * @param ciphertext message to tag
 * @return HMAC (Hashed Message Authentication Code)
 */
std::string CryptoDriver::HMAC_generate(SecByteBlock key,
                                        std::string ciphertext)
{
//    throw std::runtime_error{"CryptoDriver::HMAC_generate: NOT YET IMPLEMENTED"};

    try {
        // TODO: implement me!
        HMAC<SHA256> hasher{key, key.size()};

        std::string hmac;
        StringSource ss{ciphertext, true,
                        new HashFilter{hasher,
                                       new StringSink{hmac}
                        } // StreamTransformationFilter
        }; // StringSource

        return hmac;

    } catch (const CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        throw std::runtime_error("CryptoDriver HMAC generation failed.");
    }
}

/**
 * @brief Given a message and MAC, checks if the MAC is valid. This function
 * should 1) Initialize an `HMAC<SHA256>` with the provided key. 2) Run the
 * message through a `HashVerificationFilter` to verify the HMAC. 3) Return
 * false upon failure.
 * @param key HMAC key
 * @param ciphertext message to verify
 * @param mac associated MAC
 * @return true if MAC is valid, else false
 */
bool CryptoDriver::HMAC_verify(SecByteBlock key, std::string ciphertext,
                               std::string mac)
{
    const auto flags = HashVerificationFilter::PUT_RESULT |
                       HashVerificationFilter::HASH_AT_END;
    // TODO: implement me!
//    throw std::runtime_error{"CryptoDriver::HMAC_verify: NOT YET IMPLEMENTED"};

    HMAC<SHA256> hasher{key, key.size()};

    bool ok;
    StringSource ss(ciphertext + mac, true,
                    new HashVerificationFilter(hasher,
                                               new ArraySink(reinterpret_cast<byte *>(&ok), sizeof(ok)),
                                               flags
                    ) // HashVerificationFilter
    ); // StringSource

    return ok;
}
