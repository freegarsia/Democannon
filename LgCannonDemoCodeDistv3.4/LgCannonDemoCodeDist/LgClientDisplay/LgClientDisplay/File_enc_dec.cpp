#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h> 
#include <cryptopp/files.h>

using namespace CryptoPP;

void EncryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    // 파일을 읽고 암호화하여 출력 파일에 저장
    std::ifstream inputFile(inputFilename, std::ios::binary);
    std::ofstream outputFile(outputFilename, std::ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open())
    {
        throw std::runtime_error("Failed to open input or output file.");
    }

    CBC_Mode<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

     FileSource(inputFile, true,
        new StreamTransformationFilter(encryption,
            new FileSink(outputFile)
        )
    );
}

void DecryptFile(const std::string& inputFilename, const std::string& outputFilename, const byte key[AES::DEFAULT_KEYLENGTH], const byte iv[AES::BLOCKSIZE])
{
    // 암호화된 파일을 읽고 복호화하여 출력 파일에 저장
    std::ifstream inputFile(inputFilename, std::ios::binary);
    std::ofstream outputFile(outputFilename, std::ios::binary);

    if (!inputFile.is_open() || !outputFile.is_open())
    {
        throw std::runtime_error("Failed to open input or output file.");
    }

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFile, true,
        new StreamTransformationFilter(decryption,
            new FileSink(outputFile)
        )
    );
}

int main()
{
    // AES 키와 IV 설정 (16 바이트 키 값과 16 바이트 IV 값)
    byte key[AES::DEFAULT_KEYLENGTH] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    byte iv[AES::BLOCKSIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    try
    {
        // 파일 암호화
        EncryptFile("plain.txt", "encrypted.dat", key, iv);
        std::cout << "File encrypted successfully." << std::endl;

        // 파일 복호화
        DecryptFile("encrypted.dat", "decrypted.txt", key, iv);
        std::cout << "File decrypted successfully." << std::endl;
    }
    catch (const CryptoPP::Exception& e)
    {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
