// Constants

#include <vector>

template<typename T>
using matrix = std::vector<std::vector<T>>;

static const int modulus_len = 1024;
static const int key_len = 1024;

static const int prime = 39607;

// bool equalSize(matrix<T> a, matrix<T> b) {
//     size_t n1 = a.size(), n2 = b.size();
//     assert(n1 > 0 && n2 > 0);
//     size_t d1 = a[0].size(), d2 = b[0].size();
//     return (d1 == d2 && n1 == n2);
// }

// template<typename T>
// void plaintextMatMul(matrix<T> a, matrix<T> b, matrix<T> &c) {
//     size_t n = a.size();
//     assert(n > 0);
//     size_t d = a[0].size();
//     assert(b.size() == d && c.size() == n);
//     for (int i = 0; i < n; i++) {
//         auto sum = 0;
//         for (int j = 0; j < d; j++) {
//             sum += a[i][j] * b[j];
//         }
//         c[i] = sum;
//     }
// }

// template<typename T>
// void plaintextMatAdd(matrix<T> a, matrix<T> b, matrix<T> &c) {
//     assert(equalSize(a, b) && equalSize(b, c));
//     for (int i = 0; i < n; i++) {
//         for (int j = 0; j < d; j++) {
//             c[i][j] += a[i][j] + b[i][j];
//         }
//     }
// }