#pragma once

#include <vector>
#include <string>

class DiffeHellman {
public:
    // constructor sets modulus (p) and generator (g)
    DiffeHellman(int modulus = 23, int generator = 5);

    // Compute public key from private key: g^private mod p
    int calculatePublicKey(int privateKey) const;

    // Compute shared secret: otherPublic^private mod p
    int calculateSharedSecret(int otherPublicKey, int privateKey) const;

    int getModulus() const;
    int getGenerator() const;

private:
    int p;
    int g;
};
