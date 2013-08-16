#include <iostream>
#include <string>
#include <array>
#include "crypto/key_generation.hpp"
#include "crypto/verifier.hpp"

using namespace std;

int main() {
	KeyPair pair = generateKeyPair(2048);
	std::cout << "Success." << std::endl;

	char message[] = "Hello, World!";

	std::cout << "Signing message...";
	Signature sig = sign(message, 13, pair.privateKey);
	std::cout << "Completed." << std::endl;

	std::cout << "Verifying signature...";
	if (verify(message, 13, sig, pair.publicKey)) {
		std::cout << "Verified" << std::endl;
	}
	else {
		std::cout << "Not verified" << std::endl;
	}
}