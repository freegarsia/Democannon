#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

int ReadDataTcp(SOCKET socket, unsigned char* data, int length);
int ReadDataTcpNoBlock(SOCKET socket, unsigned char* data, int length);
int ReadDataTLSNoBlock(SSL* bio, unsigned char* data, int length);
int WriteDataTcp(SOCKET socket, unsigned char* data, int length);
int WriteDataTLS(SSL* bio, unsigned char* data, int length);

//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------