g++ -std=c++17 client.cpp Helpers/*.cpp certs/*.cpp -pthread -o client
g++ -std=c++17 server.cpp Helpers/*.cpp certs/*.cpp -pthread -o server

clang++ -std=c++17 client.cpp Helpers/*.cpp certs/*.cpp -pthread -O2 -o client
clang++ -std=c++17 server.cpp Helpers/*.cpp certs/*.cpp -pthread -O2 -o server

// alice
-----BEGIN RSA PUBLIC KEY-----
N: 769864357
E: 142112703
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
N: 769864357
D: 409609311
-----END RSA PRIVATE KEY-----

// wurth
-----BEGIN RSA PUBLIC KEY-----
N: 747139123
E: 59166705
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
N: 747139123
D: 742962953
-----END RSA PRIVATE KEY-----

// zach
-----BEGIN RSA PUBLIC KEY-----
N: 29151883
E: 26453285
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
N: 29151883
D: 19482893
-----END RSA PRIVATE KEY-----

// bob
-----BEGIN RSA PUBLIC KEY-----
N: 836287813
E: 663980159
-----END RSA PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
N: 836287813
D: 707411039
-----END RSA PRIVATE KEY-----

