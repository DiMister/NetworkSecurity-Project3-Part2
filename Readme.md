# NetworkSecurity-Project2
This project implements a Diffie-Hellman key exchange and RSA signtures demonstration with client-server communication and S-DES encryption.
### Compilation wsl
```bash
# Compile server
g++ -std=c++17 -o server server.cpp Helpers/DiffeHellman.cpp Helpers/net_utils.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp Helpers/FastModExp.cpp Helpers/MathUtils.cpp

# Compile client  
g++ -std=c++17 -o client client.cpp Helpers/DiffeHellman.cpp Helpers/net_utils.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp Helpers/FastModExp.cpp Helpers/MathUtils.cpp

# Compile CBC Hash demo
g++ -std=c++17 -o cbchash CBCHash.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp
```
### Compilation Mac
```bash
# Compile server
clang++ -std=c++17 -o server server.cpp Helpers/DiffeHellman.cpp Helpers/net_utils.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp Helpers/FastModExp.cpp Helpers/MathUtils.cpp

# Compile client  
clang++ -std=c++17 -o client client.cpp Helpers/DiffeHellman.cpp Helpers/net_utils.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp Helpers/FastModExp.cpp Helpers/MathUtils.cpp

# Compile CBC Hash demo
clang++ -std=c++17 -o cbchash CBCHash.cpp Helpers/SDESModes.cpp Helpers/SDES.cpp
```


### Running the Diffie-Hellman Demo

**Note**: Ensure `primes.csv` is in the project root directory before running.

**Terminal 1 - Start the server:**
```bash
./server [port]
# Example: ./server 8421
# Default port is 8421 if not specified
```

**Terminal 2 - Run the client:**
```bash
./client [server_ip] [port]
# Example: ./client 127.0.0.1 8421
# Default: connects to localhost:8421
```

### Running the CBC Hash Demo
```bash
./cbchash [key]
# Example: ./cbchash 1000000000
# Default key is 1000000000 if not specified
# Enter strings to hash, type 'quit' to exit
```

   

