#ifndef _key_
#define _key_

struct Key {
	char* data;
	size_t size;
};

struct KeyPair {
	Key publicKey;
	Key privateKey;
	RSA* rsa;
};

#endif
