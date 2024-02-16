#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver)
        : DH_switched{false},
          network_driver{std::move(network_driver)},
          crypto_driver{std::move(crypto_driver)},
          cli_driver{std::make_shared<CLIDriver>()}
{
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::DH DH_obj,
                          CryptoPP::SecByteBlock DH_private_value,
                          CryptoPP::SecByteBlock DH_other_public_value)
{
    // TO.DO: implement me!
    auto dhShared = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);
    AES_key = crypto_driver->AES_generate_key(dhShared);
    HMAC_key = crypto_driver->HMAC_generate_key(dhShared);
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext)
{
    // Grab the lock to avoid race conditions between the receive and send threads
    // Lock will automatically release at the end of the function.
    std::lock_guard<std::mutex> lck{mtx};

//    throw std::runtime_error{"Client::send: NOT YET IMPLEMENTED"};

    // TODO: 1) Check if the DH Ratchet keys need to change; if so, update them.

    // 2) Encrypt and tag the message.
    Message_Message msg;

    auto [ciphertext, iv] = crypto_driver->AES_encrypt(AES_key, std::move(plaintext));
    msg.ciphertext = std::move(ciphertext);
    msg.public_value = DH_current_public_value;
    msg.iv = iv;

    msg.mac = crypto_driver->HMAC_generate(
            HMAC_key, concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext));

    return msg;
}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message msg)
{
    // Grab the lock to avoid race conditions between the receive and send threads
    // Lock will automatically release at the end of the function.
    std::lock_guard<std::mutex> lck{mtx};

    // TODO: implement me!
//    throw std::runtime_error{"Client::receive: NOT YET IMPLEMENTED"};

    // TODO: 1) Check if the DH Ratchet keys need to change; if so, update them.

    // 2) Decrypt and verify the message.
    auto plaintext = crypto_driver->AES_decrypt(AES_key, msg.iv, msg.ciphertext);

    auto ivPkCiphertext = concat_msg_fields(msg.iv, msg.public_value, std::move(msg.ciphertext));
    auto ok = crypto_driver->HMAC_verify(HMAC_key, std::move(ivPkCiphertext), msg.mac);

    return {std::move(plaintext), ok};
}

/**
 * Run the client.
 */
void Client::run(std::string command)
{
    // Initialize cli_driver.
    cli_driver->init();

    // Run key exchange.
    HandleKeyExchange(std::move(command));

    // Start msgListener thread.
    boost::thread msgListener([this] { ReceiveThread(); });
    msgListener.detach();

    // Start sending thread.
    SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`.
 * `command` can be either "listen" or "connect"; the listener should `read()`
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command)
{
    // TODO: implement me!
//    throw std::runtime_error{"Client::HandleKeyExchange: NOT YET IMPLEMENTED"};

    using data_t = std::vector<unsigned char>;

    if (command == "listen") {
        // Read params
        data_t seParams = network_driver->read();

        // Deserialize
        DH_params.deserialize(seParams);

    } else if (command == "connect") {
        // Generate params
        DH_params = crypto_driver->DH_generate_params();

        // Serialize and send
        data_t seParams;
        DH_params.serialize(seParams);
        network_driver->send(seParams);

    } else {
        throw std::runtime_error{"Invalid command"};
    }

    // 2) Initialize DH object and keys
    const auto &[dh, sk, pk] = crypto_driver->DH_initialize(DH_params);
    DH_current_private_value = sk;
    DH_current_public_value = pk;

    // 3) Send my public value (pk)
    PublicValue_Message myPublic;
    myPublic.public_value = pk;

    data_t seMyPublic;
    myPublic.serialize(seMyPublic);
    network_driver->send(seMyPublic);

    // 4) Listen for the other party's public value
    PublicValue_Message otherPublic;
    data_t seOtherPublic = network_driver->read();
    otherPublic.deserialize(seOtherPublic);

    // 5) Generate AES & HMAC keys
    prepare_keys(dh, sk, DH_last_other_public_value = otherPublic.public_value);
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread()
{
    while (true) {
        // Try reading data from the other user.
        std::vector<unsigned char> data;
        try {
            data = network_driver->read();
        } catch (std::runtime_error &_) {
            // Exit cleanly.
            cli_driver->print_left("Received EOF; closing connection");
            network_driver->disconnect();
            return;
        }

        // Deserialize, decrypt, and verify message.
        Message_Message msg;
        msg.deserialize(data);
        auto decrypted_data = receive(msg);
        if (!decrypted_data.second) {
            cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
            throw std::runtime_error("Received invalid MAC!");
        }
        cli_driver->print_left(decrypted_data.first);
    }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread()
{
    std::string plaintext;
    while (true) {
        // Read from STDIN.
        std::getline(std::cin, plaintext);
        if (std::cin.eof()) {
            cli_driver->print_left("Received EOF; closing connection");
            network_driver->disconnect();
            return;
        }

        // Encrypt and send message.
        if (!plaintext.empty()) {
            Message_Message msg = send(plaintext);
            std::vector<unsigned char> data;
            msg.serialize(data);
            network_driver->send(data);
        }
        cli_driver->print_right(plaintext);
    }
}