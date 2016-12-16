/**
 * Copyright (C) 2016 <ydw at x3 dot quenza dot net>
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
static const unsigned char *hash(const unsigned char *str, size_t len) {
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
	memcpy(((char *)x) + 10, digest, len);
	memcpy(q, digest, len / 2);
	memcpy(r, digest, len);

	free(p); free(x);
	free(q); free(r);
	return digest;
}

/* Encrypt block with key */
const unsigned char *xor(const unsigned char *key, const unsigned char *str, size_t len) {
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

int test(char *str, size_t len) {
	/* Derive key from secret */
	const unsigned char *key = hash(str, len);

	/* Encrypt secret and print result */
	const unsigned char *encrypted = xor(key, str, len);
	print_bin(encrypted, len);

	/* Remove plaintext contents */
	nullify(str, len);

	/* Decrypt secret storage for usage */
	const unsigned char *decrypted = xor(key, encrypted, len);
	printf("%.*s\n", len, decrypted);

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

	return test(data, datasz);
}
