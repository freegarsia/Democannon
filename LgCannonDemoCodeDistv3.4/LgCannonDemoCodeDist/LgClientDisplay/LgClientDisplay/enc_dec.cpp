#include "enc_dec.h"

void EncryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFilename.c_str(), true,
        new StreamTransformationFilter(encryption,
            new FileSink(outputFilename.c_str())
        )
    );
}

void DecryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFilename.c_str(), true,
        new StreamTransformationFilter(decryption,
            new FileSink(outputFilename.c_str())
        )
    );
}

std::string EncryptText(const std::string& plaintext, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    std::string ciphertext;
    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    StringSource(plaintext, true,
        new StreamTransformationFilter(encryption,
            new StringSink(ciphertext)
        )
    );

    return ciphertext;
}

std::string DecryptText(const std::string& ciphertext, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    std::string decryptedtext;
    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryption,
            new StringSink(decryptedtext)
        )
    );

    return decryptedtext;
}
