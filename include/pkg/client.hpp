#pragma once

#include <iostream>
#include <mutex>

#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>

#include "../../include-shared/messages.hpp"
#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

class Client {
public:
    Client(std::shared_ptr<NetworkDriver> network_driver,
           std::shared_ptr<CryptoDriver> crypto_driver);

    void prepare_keys(CryptoPP::SecByteBlock sharedSecret);

    Message_Message send(std::string plaintext);

    std::pair<std::string, bool> receive(Message_Message ciphertext);

    void run(std::string command);

    void HandleKeyExchange(std::string command);

private:
    void ReceiveThread();

    void SendThread();

    std::mutex mtx;

    std::shared_ptr<CLIDriver> cli_driver;
    std::shared_ptr<CryptoDriver> crypto_driver;
    std::shared_ptr<NetworkDriver> network_driver;

    SecByteBlock AES_key;
    SecByteBlock HMAC_key;

    // DH Ratchet Fields
    DHParams_Message DH_params;
    bool DH_switched;
    SecByteBlock DH_current_private_value;
    SecByteBlock DH_current_public_value;
    SecByteBlock DH_last_other_public_value;
};
