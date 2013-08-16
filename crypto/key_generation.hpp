#ifndef _key_generation_
#define _key_generation_

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <iostream>
#include "key.hpp"

// Extracts the private key from an RSA object
Key getPrivateKey(RSA* rsa) {
	std::cout << "Extracting private key...";

	EVP_PKEY* key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, rsa);

	BIO* b = BIO_new(BIO_s_mem());

	if (!PEM_write_bio_PKCS8PrivateKey(b, key, 0, 0, 1, 0, 0)) {
		std::cout << "OpenSSL Error: " <<  ERR_error_string(ERR_get_error(), NULL) << std::endl;
		throw;
	}

	// Extract data
	BUF_MEM *ptr;
	BIO_get_mem_ptr(b, &ptr);
	BIO_set_close(b, BIO_NOCLOSE);
	BIO_free(b);

	std::cout << "Complete." << std::endl;
	return Key {
		ptr->data,
		ptr->length
	};
}

// Extracts the public key from an RSA object
Key getPublicKey(RSA* key) {
	std::cout << "Extracting public key...";

	BIO* b = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_RSA_PUBKEY(b, key)) {
		throw;
	}

	// Extract data
	BUF_MEM *ptr;
	BIO_get_mem_ptr(b, &ptr);
	BIO_set_close(b, BIO_NOCLOSE);
	BIO_free(b);

	std::cout << "Complete." << std::endl;

	return Key {
		ptr->data,
		ptr->length
	};
}

// Generates an RSA KeyPair, where keysize is bitsize.
KeyPair generateKeyPair(unsigned int bitSize) {
	RSA* pair = RSA_new();
	BIGNUM* f4 = BN_new();
	BN_set_word(f4, RSA_F4);

	std::cout << "Generating RSA keypair...";

	if (!RSA_generate_key_ex(pair, bitSize, f4, NULL)) {
		throw;
	}
	std::cout << "Generated." << std::endl;

	return KeyPair {
		getPublicKey(pair),
		getPrivateKey(pair),
		pair
	};
}

#endif