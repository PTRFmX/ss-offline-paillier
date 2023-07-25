#include "arithmetic.h"

/**
* We adopt the optimized protocol LHE_MT from Secure-ML for MT generation instead of the protocol from ABY because:
* 1. The ABY's approach does not apply to matrices
* 2. The adopted protocol only needs to calculate <A0 * B1> and <A1 * B0> with reduced communication complexity
*
* Denote P0 as passive and P1 as active, this file only implements for <A0 * B1> since the other one is symmetric
*/

void* ArithmeticOffline::deleteMatrix(matrix<paillier_ciphertext_t*> a) {
    for (auto row : a) for (auto element : row) paillier_freeciphertext(element);
}

void* ArithmeticOffline::deleteMatrix(matrix<paillier_plaintext_t*> a) {
    for (auto row : a) for (auto element : row) paillier_freeplaintext(element);
}

char* ArithmeticOffline::matrix_to_bytes(matrix<paillier_ciphertext_t*> a) {
    int arr_len = a.size() * a[0].size() * ciphertext_len;
    char* res = (char*) malloc(arr_len);
    size_t index = 0;
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) {
            memcpy(res + index, (const char*) paillier_ciphertext_to_bytes(ciphertext_len, a[i][j]), ciphertext_len);
            index += ciphertext_len;
        }
    }
    return res;
}

char* ArithmeticOffline::matrix_to_bytes(matrix<paillier_plaintext_t*> a) {
    int arr_len = a.size() * a[0].size() * ciphertext_len;
    char* res = (char*) malloc(arr_len);
    size_t index = 0;
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) {
            memcpy(res + index, (const char*) paillier_plaintext_to_bytes(ciphertext_len, a[i][j]), ciphertext_len);
            index += ciphertext_len;
        }
    }
    return res;
}

matrix<paillier_ciphertext_t*> ArithmeticOffline::bytes_to_cipher_matrix(char* char_arr, int row, int col) {
    matrix<paillier_ciphertext_t*> a(row, vector<paillier_ciphertext_t*>(col));
    int index = 0;
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) {
            a[i][j] = paillier_ciphertext_from_bytes((void*) char_arr + index, ciphertext_len);
            index += ciphertext_len;
        }
    }
    return a;
}

matrix<paillier_plaintext_t*> ArithmeticOffline::bytes_to_plain_matrix(char* char_arr, int row, int col) {
    matrix<paillier_plaintext_t*> a(row, vector<paillier_plaintext_t*>(col));
    int index = 0;
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) {
            a[i][j] = paillier_plaintext_from_bytes((void*) char_arr + index, ciphertext_len);
            index += ciphertext_len;
        }
    }
    return a;
}

void ArithmeticOffline::printPlainMatrix(matrix<paillier_plaintext_t*> a) {
    for (auto row : a) {
        for (auto element : row) {
            gmp_printf("%Zd ", element);
        }
        printf("\n");
    }
}

matrix<paillier_ciphertext_t*> ArithmeticOffline::encryptMatrix(matrix<paillier_plaintext_t*> a, paillier_pubkey_t* pk) {
    matrix<paillier_ciphertext_t*> res(a.size(), vector<paillier_ciphertext_t*>(a[0].size()));
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) 
            res[i][j] = paillier_enc(NULL, pk, a[i][j], paillier_get_rand_devurandom);
    }
    return res;
}

matrix<paillier_plaintext_t*> ArithmeticOffline::decryptMatrix(matrix<paillier_ciphertext_t*> a, paillier_pubkey_t* pk, paillier_prvkey_t* sk) {
    matrix<paillier_plaintext_t*> res(a.size(), vector<paillier_plaintext_t*>(a[0].size()));
    for (int i = 0; i < a.size(); i++) {
        for (int j = 0; j < a[0].size(); j++) 
            res[i][j] = paillier_dec(NULL, pk, sk, a[i][j]);
    }
    return res;
}

void ArithmeticOffline::generateMTsPassive() {
    // 1. Recv B_enc from peer
    char* B_enc_bytes = (char*) malloc(d * ciphertext_len);
    io->recv_data_internal(B_enc_bytes, d * ciphertext_len);
    matrix<paillier_ciphertext_t*> B_enc = bytes_to_cipher_matrix(B_enc_bytes, d, 1);
    
    // 2. Calculate homomorphic constant multiplication 
    matrix<paillier_ciphertext_t*> C_enc(n, vector<paillier_ciphertext_t*>(1));
    for (int i = 0; i < n; i++) {
        // plaintext: C[i] = B[j] * A[i][j] + r
        paillier_ciphertext_t* encrypted_mul, *powered_res;
        encrypted_mul = paillier_enc(NULL, peerKey, paillier_plaintext_from_ui(1), paillier_get_rand_devurandom);
        for (int j = 0; j < d; j++) {
            powered_res = paillier_create_enc_zero();
            paillier_exp(peerKey, powered_res, B_enc[j][0], A[i][j]);
            paillier_mul(peerKey, encrypted_mul, encrypted_mul, powered_res);
        }
        paillier_mul(peerKey, encrypted_mul, encrypted_mul, R_enc[i][0]);
        C_enc[i][0] = encrypted_mul;
    }
    
    // 3. Send C_enc to peer
    char* C_enc_bytes = matrix_to_bytes(C_enc);
    io->send_data_internal(C_enc_bytes, n * ciphertext_len); 

    // 4. Set C0 = R
    C = R;
    printf("Generated share C0: \n");
    printPlainMatrix(C);

    // Clean up
    free(C_enc_bytes);
    deleteMatrix(B_enc);
    deleteMatrix(C_enc);
}

void ArithmeticOffline::generateMTsActive() {
    // 1. Encrypted B and send B_enc to peer
    matrix<paillier_ciphertext_t*> B_enc = encryptMatrix(B, pubKey);
    char* B_enc_bytes = matrix_to_bytes(B_enc);
    io->send_data_internal(B_enc_bytes, d * ciphertext_len);
    free(B_enc_bytes);
    
    // 2. Recv C_enc from peer
    char* C_enc_bytes = (char*) malloc(n * ciphertext_len);
    io->recv_data_internal(C_enc_bytes, n * ciphertext_len);

    // 3. Set C1 = A0 * B1 - R
    C = decryptMatrix(bytes_to_cipher_matrix(C_enc_bytes, n, 1), pubKey, secKey);
    printf("Generated share C1: \n");
    printPlainMatrix(C);

    // Clean up
    free(C_enc_bytes);
    deleteMatrix(B_enc);
}

void ArithmeticOffline::generateMTs() {
    if (active)
        generateMTsActive();
    else
        generateMTsPassive();
}