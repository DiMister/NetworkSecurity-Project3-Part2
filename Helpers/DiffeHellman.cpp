
#include "DiffeHellman.h"
#include "FastModExp.h"
#include <fstream>
#include <string>
#include <cctype>
#include <random>
#include <set>
using namespace std;

// Implementation of DiffeHellman
DiffeHellman::DiffeHellman(int modulus, int generator)
    : p(modulus), g(generator) {}



int DiffeHellman::calculatePublicKey(int privateKey) const {
    return FastModExp::powmod(g, privateKey, p);
}

int DiffeHellman::calculateSharedSecret(int otherPublicKey, int privateKey) const {
    return FastModExp::powmod(otherPublicKey, privateKey, p);
}

int DiffeHellman::getModulus() const { return p; }
int DiffeHellman::getGenerator() const { return g; }