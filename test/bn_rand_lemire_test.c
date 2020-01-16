/*
 * Copyrights (C) 2019 Siemens AG all rights reserved
 *
 * gcc -I../include -o bn_rand_lemire_test bn_rand_lemire_test.c ../libssl.a ../libcrypto.a -ldl -lpthread
 */

#include <stdio.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/bn.h>

/*
   Use a pregenerated test vector to verify the implementation for
   the lemire mapping of the raw random number against an independend
   implementation.

   Set USE_TESTVEC to 1 inside crypto/bn/bn_rand.c for testing.

   The implementation shall be tested with a significant amount of
   test vectors.

   The required test files "rdnraw.in", "rndrange.in", and "rnd.in"
   are generated using the following Python script:

       import random

       # rndrange = int('0x169b64ead46b5420ae228af4e2105a5ae', 16)

       # select some random range
       rndrange = random.getrandbits(223)
       n = rndrange.bit_length()

       # generate random number (64 additional bits according to BSI TR 02102-1 B.4 Verfahren 2)
       rndraw = random.getrandbits(n+64)

       # calculate lemire mapping
       rnd = (rndraw*rndrange) >> (n+64)
       #print(format(rnd, "X"))

       # write test vectors to files
       frndraw = open("rndraw.in","w+")
       frndrange = open("rndrange.in","w+")
       frnd = open("rnd.in", "w+")
       frndraw.write(format(rndraw, "x"))
       frndraw.write("\n")
       frndrange.write(format(rndrange, "x"))
       frndrange.write("\n")
       frnd.write(format(rnd, "x"))
       frnd.write("\n")

*/
#define USE_TESTVEC 1

int main(void)
{
  unsigned long long start, end;
  long i, j;

  FILE * frndrange = NULL;
  FILE * frnd = NULL;
  char buf[256] = { 0 };
  char * c;

  BIGNUM *range = NULL;
  BIGNUM *diff = NULL;
  BIGNUM *value = NULL;
  BIGNUM *test = NULL;
  int ret;

  SSL_library_init();

  value = BN_new();
  range = BN_new();

#if USE_TESTVEC
  /* get range from test vector file "rndrange.in" */
  frndrange = fopen("rndrange.in", "r");
  c = buf;
  do { fread(c, 1, 1, frndrange); } while(*c++ != '\n');
  fclose(frndrange);
  BN_hex2bn(&range, buf);
#else
  /* create arbitrary range (not aligned to 2^n boundary)
   * example: range = 2^192-237 */
  diff = BN_new();
  BN_one(range);
  BN_lshift(range, range, 192);
  BN_set_word(diff, 237);
  BN_sub(range, range, diff);
#endif
  printf("range = %s\n", BN_bn2hex(range));

  /* generate random number */
  ret = BN_rand_range(value, range);
  printf("rnd =   %s\n", BN_bn2hex(value));

#if USE_TESTVEC
  /* get anticipated result from test vector file "rnd.in" */
  test = BN_new();
  frnd = fopen("rnd.in", "r");
  c = buf;
  do { fread(c, 1, 1, frnd); } while(*c++ != '\n');
  fclose(frnd);
  BN_hex2bn(&test, buf);
  printf("test =  %s\n", BN_bn2hex(test));
  if (BN_cmp(value, test) != 0) printf("FAIL!\n");
#endif

  BN_free(test);
  BN_free(range);
  BN_free(diff);
  BN_free(value);

  return 1;
}
