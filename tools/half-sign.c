#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// This program can be used to perform RSA public key signatures given only
// the hash of the file to be signed as input.

// To compile:
// gcc half-sign.c -lssl -lcrypto -o half-sign

// Sign with SHA256
#define HASH_SIZE 32

void usage() {
	printf("half-sign <private key file> [binary hash file]\n");
	printf("\n");
	printf("    Computes and prints a binary RSA signature over data given the SHA256 hash of\n");
	printf("    the data as input.\n");
	printf("\n");
	printf("    <private key file> should be PEM encoded.\n");
	printf("\n");
	printf("    The input SHA256 hash should be %d bytes in length. If no binary hash file is\n", HASH_SIZE);
	printf("    specified, it will be read from stdin.\n");
	exit(1);
}

void sign_hashed_data(EVP_PKEY *signing_key, unsigned char *md, size_t mdlen) {
	// cribbed from the openssl EVP_PKEY_sign man page
	EVP_PKEY_CTX *ctx;
	unsigned char *sig;
	size_t siglen;
	
	/* NB: assumes signing_key, md and mdlen are already set up
	 * and that signing_key is an RSA private key
	 */
	ctx = EVP_PKEY_CTX_new(signing_key, NULL);
	if ((!ctx) 
	|| (EVP_PKEY_sign_init(ctx) <= 0) 
	|| (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
	|| (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)) {
		fprintf(stderr, "Failure establishing ctx for signature\n");
		exit(1);
	}

	/* Determine buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, md, mdlen) <= 0) {
		fprintf(stderr, "Unable to determine buffer length for signature\n");
		exit(1);
	}

	sig = OPENSSL_malloc(siglen);

	if (!sig) {
		fprintf(stderr, "Malloc failed\n");
		exit(1);
	}

	if (EVP_PKEY_sign(ctx, sig, &siglen, md, mdlen) <= 0) {
		fprintf(stderr, "Signature error\n");
		exit(1);
	}

	/* Signature is siglen bytes written to buffer sig */
	fwrite(sig, siglen, 1, stdout);
}

EVP_PKEY *read_private_key(char *filename) {
	FILE *keyfile;
	EVP_PKEY *privkey;
	keyfile = fopen(filename, "r");
	if (!keyfile) {
		fprintf(stderr, "Failed to open private key.pem file %s\n", filename);
		exit(1);
	}
	privkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
	if (!privkey) {
		fprintf(stderr, "Failed to read PEM private key from %s\n", filename);
		exit(1);
	}
	if (EVP_PKEY_type(privkey->type) != EVP_PKEY_RSA) {
		fprintf(stderr, "%s was a non-RSA key\n", filename);
		exit(1);
	}
	return privkey;
}

int main(int argc, char *argv[]) {
	FILE *input;
	unsigned char *buffer;
	int test;
	EVP_PKEY *privkey;
	if (argc > 3 || argc < 2)
		usage();
	if (argc < 3 || strcmp(argv[2],"-") == 0) 
		input = stdin;
	else {
		input = fopen(argv[2], "r");
		if (!input) usage();
	}
	privkey = read_private_key(argv[1]);
	buffer = malloc(HASH_SIZE); 
	if (!buffer) {
		fprintf(stderr, "Argh, malloc failed\n");
		exit(1);
	}
	if (fread(buffer, HASH_SIZE, 1, input) != 1) {
		perror("half-sign: Failed to read SHA256 from input\n");
		exit(1);
	}

	test = fgetc(input);
	if (test != EOF && test != '\n') {
		fprintf(stderr,"Error, more than %d bytes fed to half-sign\n", HASH_SIZE);
		fprintf(stderr,"Last byte was :%d\n" , (int) test);
		exit(1);
	}
	sign_hashed_data(privkey, buffer, HASH_SIZE);
	return 0;
}
