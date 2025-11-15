// hash_driver.cpp
#include "./Helpers/SDESModes.h"
#include <iostream>
#include <string>
#include <vector>
#include <bitset>

int main(int argc, char* argv[]) {
    std::bitset<10> hash_key("1000000000");
    if (argc >= 2) {
        hash_key = std::bitset<10>(std::string(argv[1]));
    }

    std::cout << "Using S-DES key for hashing: " << hash_key << " (" << hash_key.to_ulong() << ")\n";

    // Fixed key for hashing (all hash functions use fixed key)
    SDESModes sdes(hash_key);
    
    // Fixed IV for consistency
    std::bitset<8> iv("00000000");
        
    std::cout << "S-DES CBC Hash Function Demo\n";
    std::cout << "============================\n";
    
    while (true) {
        std::cout << "Enter input string (or 'quit' to exit): ";
        std::vector<std::bitset<8>> input;
        std::string temp;
        std::getline(std::cin, temp);
        if (temp == "quit") break;
        for (char c : temp) {
            input.push_back(std::bitset<8>(c));
        }
        std::cout << "Input: " << temp << "\n";
        auto hash = sdes.encrypt(input, EncryptionMode::CBC, iv).back();
        std::cout << "Hash:  " << hash << " (" << hash.to_ulong() << ")\n\n";
    }
    
    return 0;
}