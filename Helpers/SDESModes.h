#ifndef SDESMODES_H
#define SDESMODES_H

#include "SDES.h"
#include <bitset>
#include <vector>
#include <string>

using namespace std;

enum EncryptionMode {
    ECB,
    CBC,
    CTR
};

class SDESModes {
private:
    SDES sdes;

public:
    // Constructor - takes the same 10-bit key as SDES
    SDESModes(const bitset<10>& key);
    
    // Electronic Codebook (ECB) Mode
    vector<bitset<8>> encryptECB(const vector<bitset<8>>& plaintext);
    vector<bitset<8>> decryptECB(const vector<bitset<8>>& ciphertext);
    
    // Cipher Block Chaining (CBC) Mode
    vector<bitset<8>> encryptCBC(const vector<bitset<8>>& plaintext, const bitset<8>& iv);
    vector<bitset<8>> decryptCBC(const vector<bitset<8>>& ciphertext, const bitset<8>& iv);
    
    // Counter (CTR) Mode
    vector<bitset<8>> processCTR(const vector<bitset<8>>& data, const bitset<8>& nonce);
    
    // Generic encrypt/decrypt functions
    vector<bitset<8>> encrypt(const vector<bitset<8>>& plaintext, EncryptionMode mode, const bitset<8>& param);
    vector<bitset<8>> decrypt(const vector<bitset<8>>& ciphertext, EncryptionMode mode, const bitset<8>& param);
    
    // Utility functions
    bitset<8> incrementCounter(const bitset<8>& counter);
    bitset<8> generateRandom8Bit();
};

#endif // SDESMODES_H