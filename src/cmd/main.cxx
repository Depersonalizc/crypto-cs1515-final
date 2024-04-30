#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include "seal/seal.h"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "../../include/pkg/client.hpp"

/*
 * Usage: ./signal <accept|connect> [address] [port]
 * Ex: ./signal accept localhost 3000
 *     ./signal connect localhost 3000
 */
int main(int argc, char *argv[])
{
#if 0
    try
    {
        using namespace seal;

        EncryptionParameters params(scheme_type::bfv);
        params.set_poly_modulus_degree(1024); // m = 2^n; Mod polynomial by (x^m + 1)
        params.set_coeff_modulus(CoeffModulus::BFVDefault(1024)); // q
        params.set_plain_modulus(128);
        SEALContext context(params);

        // Connect: Generate sk, pk
        KeyGenerator keygen(context);
        const SecretKey &sk = keygen.secret_key();
        seal::PublicKey pk;
        keygen.create_public_key(pk);

        // TODO: Connect sends pk to Listen

        // Listen samples plaintext, encode pt, sends ct
        Encryptor encryptor(context, pk);
        Evaluator evaluator(context);
//        uint64_t x = 1026;
        Ciphertext ct;

        // c_i <-$- [0..1024)
        // c_4095 * x^4095 + c_4094 * x^4094 + ... c_1 * x^1 + c_0 * x^0
        Plaintext pt{"23x^1023 + 0x^666 + Fx^3 + 1x^1 + 3"};  // Hex 2047x^3 + x^1 + 3
        encryptor.encrypt(pt, ct);


        // TODO: Connect decrypts ct into k
        Plaintext decrypted;
        Decryptor decryptor(context, sk);
        decryptor.decrypt(ct, decrypted);

        const auto decryptedHexStr = decrypted.to_string();
        std::cout << decryptedHexStr << std::endl;

        decryptedHexStr;

    }
    catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        throw e;
    }
#endif

    // Input checking.
    if (argc != 4) {
        std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port]"
                  << std::endl;
        return 1;
    }
    std::string command = argv[1];
    std::string address = argv[2];
    int port = atoi(argv[3]);
    if (command != "listen" && command != "connect") {
        std::cout << "Usage: " << argv[0] << " <listen|connect> [address] [port]"
                  << std::endl;
        return 1;
    }

    // Connect to network driver.
    auto network_driver = std::make_shared<NetworkDriverImpl>();
    if (command == "listen") {
        network_driver->listen(port);
    } else if (command == "connect") {
        network_driver->connect(address, port);
    } else {
        throw std::runtime_error("Error: got invalid client command.");
    }
    auto crypto_driver = std::make_shared<CryptoDriver>();

    // Create client then run network, crypto, and cli.
    Client client = Client(std::move(network_driver), std::move(crypto_driver));
    client.run(command);

    return 0;
}
