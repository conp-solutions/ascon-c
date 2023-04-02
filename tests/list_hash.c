#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"

#include "crypto_hash.h"

#define MAX_LEN (1 << 11)

#ifndef MAX_INPUT_SIZE
#define MAX_INPUT_SIZE 37
#endif

unsigned char __attribute__((aligned(16))) m[MAX_LEN+1];
unsigned char __attribute__((aligned(16))) h[CRYPTO_BYTES];

int main(int argc, char* argv[]) {

  if (argc <= 1) return 1; // too few args
  const unsigned char* in = argv[1];

  unsigned long long len = strlen(in);
  unsigned long long uselen = len < MAX_LEN ? len : MAX_LEN;
  for (int i = 0 ; i < CRYPTO_BYTES; ++i) h[i] = 0;
  for (int i = 0 ; i < uselen; ++i) {
      if (i >= MAX_LEN) break; // allow to reduce amount of input
      m[i] = in[i];
  }
  m[uselen] = 0;
  
  int r = crypto_hash(h, m, len);
  fprintf(stderr, "Hasing return code: %d\n", r);
  fprintf(stderr, "Hashing '%s' results in hash:\n", m);
  
  for (int i = 0 ; i < CRYPTO_BYTES; ++i) {
    printf("h[%d] == %d", i, (int)h[i]);
    if (i+1 < CRYPTO_BYTES) printf(" && ");
  }
  printf("\n");

  return 0;
}
