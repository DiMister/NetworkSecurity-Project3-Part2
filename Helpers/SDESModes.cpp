#include "SDESModes.h"
#include <random>
#include <chrono>

using namespace std;

SDESModes::SDESModes(const bitset<10>& key) : sdes(key) {
}

// Electronic Codebook (ECB) Mode
vector<bitset<8>> SDESModes::encryptECB(const vector<bitset<8>>& plaintext) {
    vector<bitset<8>> ciphertext;
    ciphertext.reserve(plaintext.size());
    
    // ECB simply encrypts each block independently
    for (const auto& block : plaintext) {
        ciphertext.push_back(sdes.encrypt(block));
    }
    
    return ciphertext;
}

vector<bitset<8>> SDESModes::decryptECB(const vector<bitset<8>>& ciphertext) {
    vector<bitset<8>> plaintext;
    plaintext.reserve(ciphertext.size());
    
    // ECB simply decrypts each block independently
    for (const auto& block : ciphertext) {
        plaintext.push_back(sdes.decrypt(block));
    }
    
    return plaintext;
}

// Cipher Block Chaining (CBC) Mode
vector<bitset<8>> SDESModes::encryptCBC(const vector<bitset<8>>& plaintext, const bitset<8>& iv) {
    vector<bitset<8>> ciphertext;
    ciphertext.reserve(plaintext.size());
    
    bitset<8> previousBlock = iv;
    
    for (const auto& block : plaintext) {
        // XOR current plaintext block with previous ciphertext block (or IV if start)
        bitset<8> xorBlock = block ^ previousBlock;
        
        // Encrypt the XORed block
        bitset<8> encryptedBlock = sdes.encrypt(xorBlock);
        ciphertext.push_back(encryptedBlock);
        
        // Update previous block for next iteration
        previousBlock = encryptedBlock;
    }
    
    return ciphertext;
}

vector<bitset<8>> SDESModes::decryptCBC(const vector<bitset<8>>& ciphertext, const bitset<8>& iv) {
    vector<bitset<8>> plaintext;
    plaintext.reserve(ciphertext.size());
    
    bitset<8> previousBlock = iv;
    
    for (const auto& block : ciphertext) {
        // Decrypt the current ciphertext block
        bitset<8> decryptedBlock = sdes.decrypt(block);
        
        // XOR with previous ciphertext block (or IV if start) to get plaintext
        bitset<8> plaintextBlock = decryptedBlock ^ previousBlock;
        plaintext.push_back(plaintextBlock);
        
        // Update previous block for next iteration
        previousBlock = block;
    }
    
    return plaintext;
}

// Counter (CTR) Mode
vector<bitset<8>> SDESModes::processCTR(const vector<bitset<8>>& data, const bitset<8>& nonce) {
    vector<bitset<8>> result;
    result.reserve(data.size());
    
    bitset<8> counter = nonce;
    
    for (const auto& block : data) {
        // Encrypt the counter value to generate keystream
        bitset<8> keystream = sdes.encrypt(counter);
        
        // XOR keystream with input data (works for both encryption and decryption)
        bitset<8> outputBlock = block ^ keystream;
        result.push_back(outputBlock);
        
        // Increment counter for next block
        counter = incrementCounter(counter);
    }
    
    return result;
}

// Generic Encrypt/Decrypt Functions
vector<bitset<8>> SDESModes::decrypt(const vector<bitset<8>>& ciphertext, EncryptionMode mode, const bitset<8>& param) {
    switch (mode) {
        case ECB:
            return decryptECB(ciphertext); // ECB doesn't use param
        case CBC:
            return decryptCBC(ciphertext, param); // param is IV
        case CTR:
            return processCTR(ciphertext, param); // param is nonce
        default:
            return vector<bitset<8>>(); // Return empty vector for invalid mode
    }
}

vector<bitset<8>> SDESModes::encrypt(const vector<bitset<8>>& plaintext, EncryptionMode mode, const bitset<8>& param) {
    switch (mode) {
        case ECB:
            return encryptECB(plaintext); // ECB doesn't use param
        case CBC:
            return encryptCBC(plaintext, param); // param is IV
        case CTR:
            return processCTR(plaintext, param); // param is nonce
        default:
            return vector<bitset<8>>(); // Return empty for invalid mode
    }
}

// Utility Functions
bitset<8> SDESModes::incrementCounter(const bitset<8>& counter) {
    // Simple increment - convert to unsigned long, add 1, convert back
    unsigned long value = counter.to_ulong();
    value = (value + 1) % 256;  // Keep it within 8-bit range
    return bitset<8>(value);
}

// I asked for a random 8-bit number and this seems a bit overkill but okay
bitset<8> SDESModes::generateRandom8Bit() {
    // Use high-resolution clock as seed for better randomness
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<int> dis(1, 255); // Avoid 0 to ensure non-zero IV/nonce
    
    return bitset<8>(dis(gen));
}