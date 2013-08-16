#ifndef _verifier_
#define _verifier_

#include <iostream>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include "signature.hpp"
#include "key.hpp"

Signature sign(char* data, size_t length, Key key) {
	RSA* rsa = RSA_new();
    BIO* b = BIO_new_mem_buf(key.data, key.size);
    PEM_read_bio_RSAPrivateKey(b, &rsa, 0, 0);

	// Hash it
	unsigned char hash[32];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, length);
	SHA256_Final(hash, &sha256);

	// Sign digest
	unsigned int sig_len = 0;
	unsigned char* sig = new unsigned char[RSA_size(rsa)];

	if (!RSA_sign(NID_sha256, hash, 32, sig, &sig_len, rsa)) {
		throw;
	}

	return Signature {
		sig,
		sig_len
	};
}

bool verify(char* data, size_t length, Signature signature, Key key) {
    RSA* rsa = RSA_new();
    BIO* b = BIO_new_mem_buf(key.data, key.size);
    PEM_read_bio_RSA_PUBKEY(b, &rsa, 0, 0);

	// Hash it
	unsigned char hash[32];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, length);
	SHA256_Final(hash, &sha256);

	int result = RSA_verify(NID_sha256, hash, 32, signature.data, signature.size, rsa);

	if (!result) {
		std::cout << "OpenSSL Error: " <<  ERR_error_string(ERR_get_error(), NULL) << std::endl;
	}

	// Cleanup
	BIO_set_close(b, BIO_NOCLOSE);
 	BIO_free(b);

	delete rsa;
	return result;
}

#endif