#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <seal/seal.h>
#include <stdexcept>
#include <string>
#include <utility>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

static auto rngp = AutoSeededRandomPool{};

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
    cli_driver->init();
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call `DH_generate_shared_key`
 * 2) Use the resulting key in `AES_generate_key` and `HMAC_generate_key`
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::SecByteBlock sharedSecret)
{
    // TO.DO: implement me!
    AES_key = crypto_driver->AES_generate_key(sharedSecret);
    HMAC_key = crypto_driver->HMAC_generate_key(sharedSecret);
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

#if 0
    // 1) Check if the DH Ratchet keys need to change; if so, update them.
    if (DH_switched) {
        // Re-initialize DH object and keys
        const auto &[dh, sk, pk] = crypto_driver->DH_initialize(DH_params);
        DH_current_private_value = sk;
        DH_current_public_value = pk;
        prepare_keys(dh, DH_current_private_value, DH_last_other_public_value);

        DH_switched = false;
    }
#endif

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

    DH_switched = true;

#if 0
    // 1) Check if the DH Ratchet keys need to change; if so, update them.
    if (msg.public_value != DH_last_other_public_value) {
        prepare_keys({DH_params.p, DH_params.q, DH_params.g},
                     DH_current_private_value,
                     DH_last_other_public_value = msg.public_value);
    }
#endif

    // 2) Decrypt and verify the message.
    auto plaintext = crypto_driver->AES_decrypt(AES_key, msg.iv, msg.ciphertext);
    auto ok = crypto_driver->HMAC_verify(
            HMAC_key, concat_msg_fields(msg.iv, msg.public_value, std::move(msg.ciphertext)), msg.mac);

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
    // Each coefficient is one byte.
    static constexpr auto BFV_NUM_COEFFS = 1024;
    static constexpr auto BFV_PLAIN_MODULUS = 256; // 1 byte

    using namespace seal;
    using data_t = std::vector<unsigned char>;

    // Create SEAL context
    EncryptionParameters params(scheme_type::bfv);
    params.set_poly_modulus_degree(BFV_NUM_COEFFS); // m = 2^n; Mod polynomial by (x^m + 1)
    params.set_coeff_modulus(CoeffModulus::BFVDefault(BFV_NUM_COEFFS)); // q
    params.set_plain_modulus(BFV_PLAIN_MODULUS);
    SEALContext context(params);

    // Shared secret to derive AES/HMAC keys from
    CryptoPP::SecByteBlock k(BFV_NUM_COEFFS);

    if (command == "listen") {
        // Receive public key
        seal::PublicKey pk;
        const data_t pkSer = network_driver->read();
        pk.load(context, reinterpret_cast<const seal_byte *>(pkSer.data()), pkSer.size());

        // Generate random k (CryptoPP::SecByteBlock)
        rngp.GenerateBlock(k.data(), BFV_NUM_COEFFS);

        // Parse k into uint64_t[1024], each uint64_t is 1 byte from k
        // Then pass the array to create seal::Plaintext
        std::array<Plaintext::pt_coeff_type, BFV_NUM_COEFFS> coeffs{};
        for (int i = 0; i < BFV_NUM_COEFFS; i++) {
            coeffs[i] = static_cast<Plaintext::pt_coeff_type>(k[i]);
        }
        Plaintext pt{coeffs};

        // Encrypt seal::Plaintext, send seal::Ciphertext
        Encryptor encryptor(context, pk);
        Ciphertext ct;
        encryptor.encrypt(pt, ct);

        data_t ctSer(ct.save_size(), 0);
        ct.save(reinterpret_cast<seal_byte *>(ctSer.data()), ctSer.size());
        network_driver->send(std::move(ctSer));

    } else if (command == "connect") {
        // Keygen pk, sk
        KeyGenerator keygen(context);
        const SecretKey &sk = keygen.secret_key();
        seal::PublicKey pk;
        keygen.create_public_key(pk);

        // Send pk
        data_t pkSer(pk.save_size(), 0);
        pk.save(reinterpret_cast<seal_byte *>(pkSer.data()), pkSer.size());
        network_driver->send(std::move(pkSer));

        // Receive seal::Ciphertext
        const data_t ctSer = network_driver->read();
        Ciphertext ct;
        ct.load(context, reinterpret_cast<const seal_byte *>(ctSer.data()), ctSer.size());

        // Decrypt to get seal::Plaintext
        Plaintext pt;
        Decryptor decryptor(context, sk);
        decryptor.decrypt(ct, pt);

        // Convert Plaintext into SecByteBlock (k)
        for (int i = 0; i < BFV_NUM_COEFFS; i++) {
            k[i] = pt[i];
        }

    } else {
        throw std::runtime_error{"Invalid command"};
    }

    std::cout << "Shared secret: ";
    int n = 0;
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            std::cout << std::hex << (int)k[n++] << " ";
        }
    }
    std::cout << std::hex << std::endl;

    // 5) Generate AES & HMAC keys
    prepare_keys(DH_last_other_public_value = k);
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