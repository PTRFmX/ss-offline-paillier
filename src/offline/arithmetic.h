#include "../globals.h"
#include "../crypto/paillier.h"
#include "../network/netio.h"
#include <gmp.h>
#include <string>
#include <chrono>
#include <cstdlib>
#include <algorithm>

#define DEBUG 1

using namespace std;

class ArithmeticOffline {
public:
    ArithmeticOffline(int n, int d, int active, string peer_addr, int port) : n(n), d(d), active(active) {
        // 1. Initialize NetIO
        if (active) io = new NetIO(peer_addr.c_str(), port);
        else io = new NetIO(nullptr, port);
        // 2. Generate HE keys (TODO: only active party needs to generate keys)
        paillier_keygen(modulus_len, &pubKey, &secKey, paillier_get_rand_devurandom);
        ciphertext_len = PAILLIER_BITS_TO_BYTES(pubKey->bits) * 2;
        // 3. Send public keys to each other
        if (active) {
            string pubKey_hex = paillier_pubkey_to_hex(pubKey);
            size_t pubKey_len = pubKey_hex.length();
            io->send_data_internal((void*) &pubKey_len, sizeof(size_t));
            io->send_data_internal((void*) pubKey_hex.c_str(), pubKey_len);
        } else {
            size_t peerKey_len;
            io->recv_data_internal((void*) &peerKey_len, sizeof(size_t));
            char peerKey_hex[peerKey_len];
            io->recv_data_internal((void*) peerKey_hex, peerKey_len);
            peerKey_hex[peerKey_len] = '\0';
            peerKey = paillier_pubkey_from_hex(peerKey_hex);
        }
        // 4. Initialize matrices
        if (!active) {
            // Initialize A, R
            A.resize(n, vector<paillier_plaintext_t*>(d));
            R.resize(n, vector<paillier_plaintext_t*>(1));
            R_enc.resize(n, vector<paillier_ciphertext_t*>(1));
            for (auto &row : A) for (auto &element : row) element = paillier_plaintext_from_ui(rand() % mpz_get_ui(peerKey->n));
            for (auto &row : R) for (auto &element : row) element = paillier_plaintext_from_ui(rand() % mpz_get_ui(peerKey->n));
            R_enc = encryptMatrix(R, peerKey);
        } else {
            // Initialize B
            B.resize(d, vector<paillier_plaintext_t*>(1));
            for (auto &row : B) for (auto &element : row) element = paillier_plaintext_from_ui(rand() % mpz_get_ui(pubKey->n));
        }
    }
    ~ArithmeticOffline() {
        delete io;
        if (active) {
            paillier_freepubkey(pubKey);
            deleteMatrix(B);
            deleteMatrix(C);
        }
        else {
            paillier_freepubkey(peerKey);
            deleteMatrix(R_enc);
            deleteMatrix(A);
            deleteMatrix(R);
            // deleteMatrix(C); // No need to delete C since C = R
        }
        paillier_freeprvkey(secKey);
    }

    matrix<paillier_ciphertext_t*> encryptMatrix(matrix<paillier_plaintext_t*> a, paillier_pubkey_t* pk);
    matrix<paillier_plaintext_t*> decryptMatrix(matrix<paillier_ciphertext_t*> a, paillier_pubkey_t* pk, paillier_prvkey_t* sk);

    char* matrix_to_bytes(matrix<paillier_ciphertext_t*> a);
    char* matrix_to_bytes(matrix<paillier_plaintext_t*> a);
    matrix<paillier_ciphertext_t*> bytes_to_cipher_matrix(char* char_arr, int row, int col);
    matrix<paillier_plaintext_t*> bytes_to_plain_matrix(char* char_arr, int row, int col);

    void* deleteMatrix(matrix<paillier_ciphertext_t*> a);
    void* deleteMatrix(matrix<paillier_plaintext_t*> a);

    // void printCipherMatrix(matrix<paillier_ciphertext_t*> a, paillier_pubkey_t* key);
    void printPlainMatrix(matrix<paillier_plaintext_t*> a);

    void generateMTsPassive();
    void generateMTsActive();
    void generateMTs();


private:
    int n, d;
    bool active;
    matrix<paillier_plaintext_t*> A, B, C, R;
    matrix<paillier_ciphertext_t*> R_enc;
    paillier_pubkey_t* pubKey, *peerKey;
    paillier_prvkey_t* secKey;
    int ciphertext_len;
    NetIO* io; 
};