#include "TcpSendRecv.h"
#include "cannonlogger.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


#if 0
//-----------------------------------------------------------------
// ReadDataTcp - Reads the specified amount TCP data 
//-----------------------------------------------------------------
int ReadDataTcp(SOCKET socket, unsigned char* data, int length)
{
    int bytes;

    for (size_t i = 0; i < length; i += bytes)
    {
        if ((bytes = recv(socket, (char*)(data + i), (int)(length - i), 0)) == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                std::cout << "recv WSAEWOULDBLOCK" << std::endl;
                bytes = 0;
                Sleep(10);
            }
            else return (SOCKET_ERROR);
        }
    }
    return(length);
}
//-----------------------------------------------------------------
// END ReadDataTcp
//-----------------------------------------------------------------
#endif
//-----------------------------------------------------------------
// ReadDataTcpNoBlock - Reads Available TCP data 
//-----------------------------------------------------------------
int ReadDataTcpNoBlock(SOCKET socket, unsigned char* data, int length)
{
    cannonLogger_info("ReadDataTCPNoBlock");
    return(recv(socket, (char*)data, length, 0));
}

int ReadDataTLSNoBlock(SSL* ssl, unsigned char* data, int length)
{
    cannonLogger_info("ReadDataTLSNoBlock");
    int bytes_read = SSL_read(ssl, (char *)data, length);
    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl, bytes_read);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Non-fatal error, indicates that the operation should be retried
            return -1; // You can choose an appropriate error code or handling
        }
        else {
            // Handle other errors
            ERR_print_errors_fp(stderr);
            return -1; // You can choose an appropriate error code or handling
        }
    }
    return bytes_read;
}
//-----------------------------------------------------------------
// END Reads Available TCP data
//-----------------------------------------------------------------
//-----------------------------------------------------------------
// WriteDataTcp - Writes the specified amount TCP data 
//-----------------------------------------------------------------
int WriteDataTcp(SOCKET socket, unsigned char* data, int length)
{
    int total_bytes_written = 0;
    unsigned int retry_count = 0;
    int bytes_written;

    cannonLogger_info((const char*)data);

    while (total_bytes_written != length)
    {
        bytes_written = send(socket,
            (char*)(data + total_bytes_written),
            (int)(length - total_bytes_written), 0);
        if (bytes_written == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                std::cout << "send WSAEWOULDBLOCK" << std::endl;
                bytes_written = 0;                
                retry_count++;
                if (retry_count > 15) return (SOCKET_ERROR);
                else Sleep(10);
            }
            else return (SOCKET_ERROR);
        }
        else retry_count = 0;
        total_bytes_written += bytes_written;        
    }
    return(total_bytes_written);
}
//-----------------------------------------------------------------
// END WriteDataTcp
//-----------------------------------------------------------------

int WriteDataTLS(SSL* ssl, unsigned char* message, int length)
{
    int len = sizeof(message);
    SSL_write(ssl, message, length);
    cannonLogger_info((const char*)message);
    return (length);
}

//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------