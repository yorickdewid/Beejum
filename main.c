/**
 * Implemntationm of the Beejum algorithm
 *
 * Compile with: cc -O0 main.c -o main -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/sha.h>

/* Write hex presentation of bin data to screen */
static void print_bin(const unsigned char *str, size_t len) {
	int i;
	char *strhex = (char *)calloc(len * 2 + 1, sizeof(char));

	for(i = 0; i < len; ++i)
		sprintf(&strhex[i * 2], "%02x", (unsigned int)str[i]);

	printf("Hexdump: %s\n", strhex);
	free(strhex);
}

/* Calculate key from plaintext and fragment memory so
 * that both key and plaintext endup in different memory
 * sectors
 */
static const unsigned char *hash(const unsigned char *str, size_t len) {
	unsigned char *digest = (unsigned char *)calloc(SHA384_DIGEST_LENGTH, sizeof(char));

	SHA384(str, len, digest);

#ifdef DEBUG
	print_bin(digest, SHA384_DIGEST_LENGTH);
#endif

	/* Fragment memory heap */
	void *p = malloc(len * 4);
	void *q = malloc(len / 2);

	memcpy(((char *)p) + len, digest, len);
	memcpy(q, digest, len / 2);

	free(p);
	free(q);
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

/* Erase all memory by overriding the block with zero, the
 * latter operations prevent any generic optimization the
 * compiler might invoke at stage 2 and 3
 */
void nullify(void *data, size_t size) {
	memset(data, '\0', size);
	((char *)&data)[0] = 0x1;
	((char *)&data)[size - 1] = 0xf0;
}

int test(char *str, size_t len) {
	/* Derive key from secret */
	const unsigned char *key = hash(str, len);

	//TODO: find multiple of hash block size
	if (len > SHA384_DIGEST_LENGTH) {
		fprintf(stderr, "Overflow\n");
		free((void *)key);
		return 2;
	}

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
