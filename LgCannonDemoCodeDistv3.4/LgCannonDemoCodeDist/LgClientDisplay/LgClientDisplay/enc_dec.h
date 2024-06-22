#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h> 

using namespace CryptoPP;

void EncryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]);
void DecryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE]);

std::string EncryptText(const std::string& plaintext,
						const byte key[AES::DEFAULT_KEYLENGTH],
						const byte iv[AES::BLOCKSIZE]);
std::string DecryptText(const std::string& ciphertext,
						const byte key[AES::DEFAULT_KEYLENGTH],
						const byte iv[AES::BLOCKSIZE]);

#endif
