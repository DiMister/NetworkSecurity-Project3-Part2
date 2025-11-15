#include <cstdint>
#include <utility>
#include <vector>
#include <string>


namespace pki487 {
    struct keypair{
        uint32_t n;
        uint32_t exponent;
    };

    class Rsa {
    public:
        keypair publicKey;
        keypair privateKey;

        Rsa(); 
        std::pair<uint32_t, uint32_t> PickPrimes();
        std::tuple<uint32_t, uint32_t, uint32_t> GenerateKeypair(uint32_t p_rsa, uint32_t q_rsa);
        // Utility: modular exponentiation (base^exp mod mod)
        static uint32_t mod_pow(uint32_t base, uint32_t exp, uint32_t mod);

        // Compute a small deterministic digest from the canonical TBS string.
        // Digest is an integer in [0, mod-1] and should be computed from the message and modulus.
        static uint32_t compute_digest(const std::string& msg, uint32_t mod);

        // Sign a message TBS using a private keypair: returns signature bytes (big-endian, 4 bytes)
        static std::vector<unsigned char> sign_message(const std::string& tbs, const keypair& priv);

        // Verify signature bytes against TBS and public keypair
        static bool verify_message(const std::string& tbs, const keypair& pub, const std::vector<unsigned char>& sig_bytes);
    };
}