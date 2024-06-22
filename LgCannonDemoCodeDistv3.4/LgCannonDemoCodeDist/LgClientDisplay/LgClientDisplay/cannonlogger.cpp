#include "cannonlogger.h"
#include "enc_dec.h"

void cannonLogger_warning(const char* l)
{
	if (Logger == NULL)
		return;
	//EncryptText(l, key, iv);
	Logger->warn(l);
	Logger->flush();
	std::cout << l << std::endl;
}

void cannonLogger_error(const char* l)
{
	if (Logger == NULL)
		return;

	Logger->error(l);
	Logger->flush();
	std::cout << l << std::endl;
}

void cannonLogger_info(const char* l)
{
	if (Logger == NULL)
		return;
	
	Logger->info(l);
	Logger->flush();
	std::cout << l << std::endl;
}