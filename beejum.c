/**
 * Copyright (C) 2016 Yorick de Wid <ydw at x3 dot quenza dot net>
 * All rights reserved.
 *
 * Implemntationm of the Beejum algorithm
 *
 * Compile with: cc -O0 main.c -o main -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/sha.h>

#define BLOCKSZ		SHA384_DIGEST_LENGTH

/* Write hex presentation of bin data to screen */
static void print_bin(const unsigned char *str, size_t len) {
	int i;
	char *strhex = (char *)calloc(len * 2 + 1, sizeof(char));

	for (i = 0; i < len; ++i)
		sprintf(&strhex[i * 2], "%02x", (unsigned int)str[i]);

	printf("Hexdump: %s\n", strhex);
	free(strhex);
}

/* Calculate key from plaintext and fragment memory so
 * that both key and plaintext endup in different memory
 * sectors
 */
static unsigned char *hash(const unsigned char *str, size_t len) {
	int j, i = (len / BLOCKSZ) + 1;
	unsigned char *digest = (unsigned char *)calloc(i * BLOCKSZ, sizeof(char));

	SHA384(str, len, digest);

#ifdef DEBUG
	puts("hash(): chain");
	print_bin(digest, BLOCKSZ);
#endif
	/* Chain the digest in a multiple of the block size */
	for (j = 1; j < i; ++j) {
		SHA384(digest + (BLOCKSZ * (j - 1)), BLOCKSZ, digest + (BLOCKSZ * j));
#ifdef DEBUG
		printf("j:%d\n", j);
		print_bin(digest + (BLOCKSZ * j), BLOCKSZ);
#endif
	}

	/* Fragment memory heap */
	void *p = malloc(len * 4);
	void *x = malloc(len * 2);
	void *q = malloc(len / 2);
	void *r = malloc(len);

	memcpy(((char *)p) + len, digest, len);
	memcpy(((char *)x), digest, len);
	memcpy(q, digest, len / 2);
	memcpy(r, digest, len);

	free(p); free(x);
	free(q); free(r);
	return digest;
}

/* Encrypt block with key */
unsigned char *xor(const unsigned char *key, const unsigned char *str, size_t len) {
	int i;
	unsigned char *ctx = calloc(len, sizeof(char));

	/* XOR block */
	for(i = 0; i < len; ++i)
		ctx[i] = str[i] ^ key[i];

	return ctx;
}

/* Erase all memory by overriding the block with zero */
void nullify(void *data, size_t size) {
	memset(data, '\0', size);
	/* OPTIONAL: some tricks to prevent compiler optimization */
}

#ifdef UTIL

int util(char *str, size_t len) {
	/* Derive key from secret */
	unsigned char *key = hash(str, len);

	/* Encrypt secret and print result */
	unsigned char *encrypted = xor(key, str, len);
	print_bin(encrypted, len);

	/* Remove plaintext contents */
	nullify(str, len);

	/* Decrypt secret storage for usage */
	unsigned char *decrypted = xor(key, encrypted, len);
	printf("%.*s\n", len, decrypted);

	/* Remove any contents, the key is wiped for the most part */
	nullify(encrypted, len);
	nullify(decrypted, len);
	nullify(key, len);

	free((void *)decrypted);
	free((void *)encrypted);
	free((void *)key);
	return 1;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s [data]\n", argv[0]);
		return 1;
	}

	/* data is considered sensitive */
	char *data = argv[1];
	size_t datasz = strlen(argv[1]);

	return util(data, datasz);
}

#endif // UTIL

#ifdef TESTCASE

#include <assert.h>

#define INPUT_1	"ABC123"
#define INPUT_2	"7820daf4d110c5d2a71d17e078b5fe919159eb254d86822ffd51a1a7afa61489"
#define INPUT_3	"1d700857f0c7d0636274c3c4b35a160c6271602ba1b7df6687e396b4b29a93b852a0eacc50d5221dc46bad5ae630f4ec0f9e28e206c920a65042503c74b"

void test_1(void) {
	puts("[Test 1]");

	size_t dsz = strlen(INPUT_1);

	/* Derive key from secret */
	unsigned char *key = hash(INPUT_1, dsz);
	unsigned char *encrypted = xor(key, INPUT_1, dsz);
	assert(strncmp(encrypted, INPUT_1, dsz));

	/* Decrypt secret storage for usage */
	unsigned char *decrypted = xor(key, encrypted, dsz);
	assert(strncmp(decrypted, encrypted, dsz));
	assert(!strncmp(decrypted, INPUT_1, dsz));

	/* Remove any contents, the key is wiped for the most part */
	nullify(encrypted, dsz);
	nullify(decrypted, dsz);
	nullify(key, dsz);

	/* Ensure buffers are clean */
	assert(encrypted[0] == 0x0 && encrypted[dsz - 1] == 0x0);
	assert(decrypted[0] == 0x0 && decrypted[dsz - 1] == 0x0);
	assert(key[0] == 0x0 && key[dsz - 1] == 0x0);

	free((void *)decrypted);
	free((void *)encrypted);
	free((void *)key);
}

void test_2(void) {
	puts("[Test 2]");

	size_t dsz = strlen(INPUT_2);

	/* Derive key from secret */
	unsigned char *key = hash(INPUT_2, dsz);
	unsigned char *encrypted = xor(key, INPUT_2, dsz);

	/* Decrypt secret storage for usage */
	unsigned char *decrypted = xor(key, encrypted, dsz);
	assert(!strncmp(decrypted, INPUT_2, dsz));

	free((void *)decrypted);
	free((void *)encrypted);
	free((void *)key);
}

void test_3(void) {
	puts("[Test 3]");

	size_t dsz = strlen(INPUT_3);

	/* Derive key from secret */
	unsigned char *key = hash(INPUT_3, dsz);
	unsigned char *encrypted = xor(key, INPUT_3, dsz);

	/* Decrypt secret storage for usage */
	unsigned char *decrypted = xor(key, encrypted, dsz);
	assert(!strncmp(decrypted, INPUT_3, dsz));

	free((void *)decrypted);
	free((void *)encrypted);
	free((void *)key);
}

int main(void) {
	puts("Running testcases:");

	/* Running test scenarios */
	test_1();
	test_2();
	test_3();

	puts("Tests PASSED");
	return 0;
}

#endif // TESTCASE
