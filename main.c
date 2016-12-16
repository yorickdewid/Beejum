/**
 * Implemntationm of the Beejum algorithm
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/sha.h>

/* Write hex presentation of bin data to screen */
void print_bin(const unsigned char *str, size_t len) {
	int i;
	//char strhex[len * 2 + 1];
	char *strhex = (char *)calloc(len * 2 + 1, sizeof(char));

	for(i = 0; i < len; ++i)
		sprintf(&strhex[i * 2], "%02x", (unsigned int)str[i]);

	printf("Hexdump: %s\n", strhex);
	free(strhex);
}

const unsigned char *hash(unsigned char *str, size_t len) {
	unsigned char *digest = (unsigned char *)calloc(SHA384_DIGEST_LENGTH, sizeof(char));

	SHA384(str, len, digest);

#ifdef DEBUG
	print_bin(digest, SHA384_DIGEST_LENGTH);
#endif

	return digest;
}

const unsigned char *xor(const unsigned char *key, const unsigned char *str, size_t len) {
	int i;
	unsigned char *ctx = calloc(len, sizeof(char));

	/* XOR block */
	for(i = 0; i < len; ++i)
		ctx[i] = str[i] ^ key[i];

	return ctx;
}

/* Erase all memory by overriding with zero */
void nullify(void *data, size_t size) {
	memset(data, '\0', size);
	((char *)&data)[0] = 0x1;
	((char *)&data)[size - 1] = 0xf0;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s [data]\n", argv[0]);
		return 1;
	}

	/* data is considered sensitive */
	char *data = argv[1];
	size_t datasz = strlen(argv[1]);

	/* Derive key from secret */
	const unsigned char *key = hash(data, datasz);

	//TODO: find multiple of hash block size
	if (datasz > SHA384_DIGEST_LENGTH) {
		fprintf(stderr, "Overflow\n");
		return 2;
	}

	/* Encrypt secret and print result */
	const unsigned char *encrypted = xor(key, data, datasz);
	print_bin(encrypted, datasz);

	/* Remove plaintext contents */
	nullify(data, datasz);

	/* Decrypt secret storage for usage */
	const unsigned char *decrypted = xor(key, encrypted, datasz);
	printf("%s\n", decrypted);

	free((void *)decrypted);
	free((void *)encrypted);
	free((void *)key);
	return 0;
}
