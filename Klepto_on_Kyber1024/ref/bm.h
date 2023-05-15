/*
  This file is for the Berlekamp-Massey algorithm
  用来求解一个数列的最短线性递推式
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

#ifndef BM_H
#define BM_H
#define bm CRYPTO_NAMESPACE(bm)

void bm(gf *, gf *);

#endif

