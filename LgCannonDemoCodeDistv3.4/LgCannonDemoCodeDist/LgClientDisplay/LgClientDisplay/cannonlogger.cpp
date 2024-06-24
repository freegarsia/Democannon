#include "cannonlogger.h"
#include "enc_dec.h"

byte* get_logger_key(void);
byte* get_logger_iv(void);

byte* logger_key = get_logger_key();
byte* logger_iv = get_logger_iv();

void cannonLogger_warning(const char* l)
{
	if (Logger == NULL)
		return;
	
	std::string ciphertext = EncryptText(l, logger_key, logger_iv);

	Logger->warn(ciphertext);
	Logger->flush();
	std::cout << l << std::endl;
}

void cannonLogger_error(const char* l)
{
	if (Logger == NULL)
		return;

	std::string ciphertext = EncryptText(l, logger_key, logger_iv);

	Logger->error(ciphertext);
	Logger->flush();
	std::cout << l << std::endl;
}

void cannonLogger_info(const char* l)
{
	if (Logger == NULL)
		return;
	
	std::string ciphertext = EncryptText(l, logger_key, logger_iv);

	Logger->info(ciphertext);
	Logger->flush();
	std::cout << l << std::endl;
}