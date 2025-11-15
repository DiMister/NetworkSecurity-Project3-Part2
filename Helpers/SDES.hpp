#ifndef SDES_H
#define SDES_H

#include <bitset>
#include <vector>
#include <string>

using namespace std;

class SDES {
private:
    // P10 permutation table for 10-bit key
    static const int P10[10];
    
    // P8 permutation table for 8-bit subkey generation
    static const int P8[8];
    
    // Initial Permutation (IP) table
    static const int IP[8];
    
    // Final Permutation (IP-1) table  
    static const int IP_INV[8];
    
    // Expansion/Permutation (EP) table
    static const int EP[8];
    
    // P4 permutation table
    static const int P4[4];
    
    // S-Box 0
    static const int S0[4][4];
    
    // S-Box 1
    static const int S1[4][4];
    
    bitset<10> masterKey;
    bitset<8> k1, k2;
    
    // Helper functions
    bitset<10> permute10(const bitset<10>& input, const int* table);
    bitset<8> permute8(const bitset<8>& input, const int* table);
    bitset<8> permute8(const bitset<10>& input, const int* table);
    bitset<4> permute4(const bitset<4>& input, const int* table);
    bitset<8> expandPermute(const bitset<4>& input);
    bitset<10> leftShift(const bitset<10>& input, int positions);
    bitset<2> sboxLookup(const bitset<4>& input, const int sbox[4][4]);
    bitset<4> fFunction(const bitset<4>& right, const bitset<8>& subkey);
    
    void generateSubkeys();
    
public:
    // Constructor
    SDES(const bitset<10>& key);
    
    // Main encryption/decryption functions
    bitset<8> encrypt(const bitset<8>& plaintext);
    bitset<8> decrypt(const bitset<8>& ciphertext);
    
    // Utility functions
    string binaryToString(const bitset<8>& bits);
    bitset<8> charToBinary(char c);
};

#endif // SDES_H