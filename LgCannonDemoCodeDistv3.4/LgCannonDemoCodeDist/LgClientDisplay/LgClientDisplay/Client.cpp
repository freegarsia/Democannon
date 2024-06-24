#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <atlstr.h>
#include < cstdlib >
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "Message.h"
#include "Client.h"
#include "LgClientDisplay.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>


enum InputMode { MsgHeader, Msg };
static  std::vector<uchar> sendbuff;//buffer for coding
static HANDLE hClientEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndClientEvent = INVALID_HANDLE_VALUE;
SOCKET Client = INVALID_SOCKET;
static SSL* ssl = NULL;
static SSL_CTX* ctx = NULL;

static cv::Mat ImageIn;
static DWORD ThreadClientID;
static HANDLE hThreadClient = INVALID_HANDLE_VALUE;

static DWORD WINAPI ThreadClient(LPVOID ivalue);
static void ClientSetExitEvent(void);
static void ClientCleanup(void);

static void ClientSetExitEvent(void)
{
    if (hEndClientEvent != INVALID_HANDLE_VALUE)
        SetEvent(hEndClientEvent);
}
static void ClientCleanup(void)
{
    std::cout << "ClientCleanup" << std::endl;

    if (hClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hClientEvent);
        hClientEvent = INVALID_HANDLE_VALUE;
    }
    if (hEndClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hEndClientEvent);
        hEndClientEvent = INVALID_HANDLE_VALUE;
    }
    if (Client != INVALID_SOCKET)
    {
        closesocket(Client);
        Client = INVALID_SOCKET;
    }
}
bool SendCodeToSever(unsigned char Code)
{
    if (IsClientConnected())
    {
        TMesssageCommands MsgCmd;
        int msglen = sizeof(TMesssageHeader) + sizeof(unsigned char);
        //printf("Message len %d\n", msglen);
        MsgCmd.Hdr.Len = htonl(sizeof(unsigned char));
        MsgCmd.Hdr.Type = htonl(MT_COMMANDS);
        MsgCmd.Commands = Code;
        //if (WriteDataTcp(Client, (unsigned char *)&MsgCmd, msglen)== msglen)
        if (WriteDataTLS(ssl, (unsigned char*)&MsgCmd, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendCalibToSever(unsigned char Code)
{
    if (IsClientConnected())
    {
        TMesssageCalibCommands MsgCmd;
        int msglen = sizeof(TMesssageHeader) + sizeof(unsigned char);
        //printf("Message len %d\n", msglen);
        MsgCmd.Hdr.Len = htonl(sizeof(unsigned char));
        MsgCmd.Hdr.Type = htonl(MT_CALIB_COMMANDS);
        MsgCmd.Commands = Code;

        //if (WriteDataTcp(Client, (unsigned char*)&MsgCmd, msglen) == msglen)
        if (WriteDataTLS(ssl, (unsigned char*)&MsgCmd, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendTargetOrderToSever(char* TargetOrder)
{
    if (IsClientConnected())
    {
        TMesssageTargetOrder MsgTargetOrder;
        int msglen = sizeof(TMesssageHeader) + (int)strlen((const char*)TargetOrder)+1;
        MsgTargetOrder.Hdr.Len = htonl((int)strlen((const char*)TargetOrder)+1);
        MsgTargetOrder.Hdr.Type = htonl(MT_TARGET_SEQUENCE);
        strcpy_s((char*)MsgTargetOrder.FiringOrder,sizeof(MsgTargetOrder.FiringOrder),TargetOrder);
        /*if (WriteDataTcp(Client, (unsigned char*)&MsgTargetOrder, msglen) == msglen)*/
        if (WriteDataTLS(ssl, (unsigned char*)&MsgTargetOrder, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendPreArmCodeToSever(char* Code)
{
    if (IsClientConnected())
    {
        TMesssagePreArm MsgPreArm;
        int msglen = sizeof(TMesssageHeader) + (int)strlen(Code) + 1;
        MsgPreArm.Hdr.Len = htonl((int)strlen(Code) + 1);
        MsgPreArm.Hdr.Type = htonl(MT_PREARM);
        strcpy_s((char*)MsgPreArm.Code, sizeof(MsgPreArm.Code), Code);
        //if (WriteDataTcp(Client, (unsigned char*)&MsgPreArm, msglen) == msglen)
        if (WriteDataTLS(ssl, (unsigned char*)&MsgPreArm, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

bool SendStateChangeRequestToSever(SystemState_t State)
{
    if (IsClientConnected())
    {
        TMesssageChangeStateRequest MsgChangeStateRequest;
        int msglen = sizeof(TMesssageChangeStateRequest);
        MsgChangeStateRequest.Hdr.Len = htonl(sizeof(MsgChangeStateRequest.State));
        MsgChangeStateRequest.Hdr.Type = htonl(MT_STATE_CHANGE_REQ);
        MsgChangeStateRequest.State = (SystemState_t)htonl(State);
        //if (WriteDataTcp(Client, (unsigned char*)&MsgChangeStateRequest, msglen) == msglen)
        if (WriteDataTLS(ssl, (unsigned char*)&MsgChangeStateRequest, msglen) == msglen)
        {
            return true;
        }

    }
    return false;
}

unsigned char* get_client_cert(void);
unsigned char* get_client_key(void);
char* get_ca_cert(void);

void ConfigureContext(SSL_CTX* ctx) {
    unsigned char* client_cert;
    unsigned char* client_key;
    char* ca_cert;
    
    client_cert = get_client_cert();
    client_key = get_client_key();
    ca_cert = get_ca_cert();

    tls_configure_context(ctx, client_cert, client_key, ca_cert);

    //if (SSL_CTX_use_certificate_file(ctx, "C:/keys/client-cert.pem", SSL_FILETYPE_PEM) <= 0) {
    //    ERR_print_errors_fp(stdout);
    //    exit(EXIT_FAILURE);
    //}
    //if (SSL_CTX_use_PrivateKey_file(ctx, "C:/keys/client-key.pem", SSL_FILETYPE_PEM) <= 0) {
    //    ERR_print_errors_fp(stdout);
    //    exit(EXIT_FAILURE);
    //}

    //if (SSL_CTX_load_verify_locations(ctx, "C:/keys/ca-cert.pem", NULL) <= 0) {
    //    ERR_print_errors_fp(stdout);
    //    exit(EXIT_FAILURE);
    //}

    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //SSL_CTX_set_verify_depth(ctx, 4);
}

bool ConnectToSever(const char* remotehostname, unsigned short remoteport)
{
    int iResult;
    struct addrinfo   hints;
    struct addrinfo* result = NULL;
    char remoteportno[128];
    struct sockaddr_in addr;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    tls_init_openssl();
    ctx = tls_create_context();
    ConfigureContext(ctx);

    
    sprintf_s(remoteportno, sizeof(remoteportno), "%d", remoteport);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo(remotehostname, remoteportno, &hints, &result);
    if (iResult != 0)
    {
        std::cout << "getaddrinfo: Failed" << std::endl;
        return false;
    }
    if (result == NULL)
    {
        std::cout << "getaddrinfo: Failed" << std::endl;
        return false;
    }

    if ((Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        std::cout << "video client socket() failed with error " << WSAGetLastError() << std::endl;
        return false;
    }

    //----------------------
    // Connect to server.
    iResult = connect(Client, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    if (iResult == SOCKET_ERROR) {
        std::cout << "connect function failed with error : " << WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error :" << WSAGetLastError() << std::endl;
        return false;
    }

    int yes = 1;
    iResult = setsockopt(Client,
        IPPROTO_TCP,
        TCP_NODELAY,
        (char*)&yes,
        sizeof(int));    // 1 - on, 0 - off
    if (iResult < 0)
    {
        printf("TCP NODELAY Failed\n");
    }
    else  printf("TCP NODELAY SET\n");

    
    /*
    if ((Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        freeaddrinfo(result);
        std::cout << "video client socket() failed with error " << WSAGetLastError() << std::endl;
        return false;
    }


    addr.sin_family = AF_INET;
    addr.sin_port = htons(4443);
    inet_pton(AF_INET, "172.20.50.137", &addr.sin_addr);

    if (connect(Client, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        return (false);
    }
    */

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, Client);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}
bool StartClient(void)
{
     hThreadClient = CreateThread(NULL, 0, ThreadClient, NULL, 0, &ThreadClientID);
     return true;
}

bool StopClient(void)
{
    ClientSetExitEvent();
    if (hThreadClient != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadClient, INFINITE);
        CloseHandle(hThreadClient);
        hThreadClient = INVALID_HANDLE_VALUE;

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(Client);
        SSL_CTX_free(ctx);
        tls_cleanup_openssl();

    }
;
    return true;
}
bool IsClientConnected(void)
{
    if (hThreadClient == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    else return true;
}
void ProcessMessage(char* MsgBuffer)
{
    TMesssageHeader *MsgHdr;
    MsgHdr = (TMesssageHeader*)MsgBuffer;
    MsgHdr->Len = ntohl(MsgHdr->Len);
    MsgHdr->Type = ntohl(MsgHdr->Type);

    switch (MsgHdr->Type)
    {
    case MT_IMAGE:
      {
        cv::imdecode(cv::Mat(MsgHdr->Len, 1, CV_8UC1, MsgBuffer + sizeof(TMesssageHeader)), cv::IMREAD_COLOR, &ImageIn);
        ProcessImage(ImageIn);
      }
    break;
    case MT_TEXT:
    {
        CStringW cstring(MsgBuffer + sizeof(TMesssageHeader));
        PRINT(_T("%s\r\n"), cstring);
    }
    break;
    case MT_STATE:
    {
        TMesssageSystemState* MsgState;
        MsgState = (TMesssageSystemState*)MsgBuffer;
        MsgState->State = (SystemState_t)ntohl(MsgState->State);
        PostMessage(hWndMain, WM_SYSTEM_STATE, MsgState->State, 0);

    }
    break;
    default:
    {
        printf("unknown message\n");
    }
    break;
    }


}

static DWORD WINAPI ThreadClient(LPVOID ivalue)
{
    HANDLE ghEvents[2];
    int NumEvents;
    int iResult;
    DWORD dwEvent;
    InputMode Mode = MsgHeader;
    unsigned int InputBytesNeeded = sizeof(TMesssageHeader);
    TMesssageHeader MsgHdr;
    char* InputBuffer = NULL;
    char* InputBufferWithOffset = NULL;
    unsigned int CurrentInputBufferSize = 1024 * 10;

    InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
    InputBufferWithOffset = InputBuffer;

    if (InputBuffer == NULL)
    {
        std::cout << "InputBuffer Realloc failed" << std::endl;
        ExitProcess(0);
        return 1;
    }

    hClientEvent = WSACreateEvent();
    hEndClientEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (WSAEventSelect(Client, hClientEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)
    {
        std::cout << "WSAEventSelect() failed with error " << WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error : " << WSAGetLastError() << std::endl;
        return 4;
    }
    ghEvents[0] = hEndClientEvent;
    ghEvents[1] = hClientEvent;
    NumEvents = 2;

    while (1) {
        {
            int iResult;
            //Sleep(10);
            //iResult = ReadDataTcpNoBlock(Client, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
            iResult = ReadDataTLSNoBlock(ssl, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
            if (iResult > 0)
            {
                if (iResult == 1)   // new line character is received
                {
                    Mode = MsgHeader;
                    InputBytesNeeded = sizeof(TMesssageHeader);
                    InputBufferWithOffset = InputBuffer;
                    PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                    std::cout << "Connection closed on Recv" << std::endl;
                    break;
                }
                else
                {
                    InputBytesNeeded -= iResult;
                    InputBufferWithOffset += iResult;
                    if (InputBytesNeeded == 0)
                    {
                        if (Mode == MsgHeader)
                        {
                            InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
                            memcpy(&MsgHdr, InputBuffer, sizeof(TMesssageHeader));
                            MsgHdr.Len = ntohl(MsgHdr.Len);
                            MsgHdr.Type = ntohl(MsgHdr.Type);
                            InputBytesNeeded = MsgHdr.Len;
                            Mode = Msg;
                            if ((InputBytesNeeded + sizeof(TMesssageHeader)) > CurrentInputBufferSize)
                            {
                                CurrentInputBufferSize = InputBytesNeeded + sizeof(TMesssageHeader) + (10 * 1024);
                                InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
                                if (InputBuffer == NULL)
                                {
                                    std::cout << "std::realloc failed " << std::endl;
                                    ExitProcess(0);
                                }
                                InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
                            }

                        }
                        else if (Mode == Msg)
                        {
                            ProcessMessage(InputBuffer);
                            // Setup for next message
                            Mode = MsgHeader;
                            InputBytesNeeded = sizeof(TMesssageHeader);
                            InputBufferWithOffset = InputBuffer;
                        }
                    }

                }
            }
        }
    }
#if 0
        dwEvent = WaitForMultipleObjects(
            NumEvents,        // number of objects in array
            ghEvents,       // array of objects
            FALSE,           // wait for any object
            INFINITE);  // INFINITE) wait

        if (dwEvent == WAIT_OBJECT_0) 
            break;
        else if (dwEvent == WAIT_OBJECT_0 + 1)
        {
            WSANETWORKEVENTS NetworkEvents;
            if (SOCKET_ERROR == WSAEnumNetworkEvents(Client, hClientEvent, &NetworkEvents))
            {
                std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError() << "dwEvent " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents << std::endl;
                NetworkEvents.lNetworkEvents = 0;
            }
            else
            {
                if (NetworkEvents.lNetworkEvents & FD_READ)
                {
                    if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
                    {
                        std::cout << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT] << std::endl;
                    }
                    else
                    {
                        int iResult;
                        //iResult = ReadDataTcpNoBlock(Client, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
                        iResult = ReadDataTLSNoBlock(ssl, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
                        if (iResult > 0)
                        {
                            if (iResult == 1)   // new line character is received
                            {
                                Mode = MsgHeader;
                                InputBytesNeeded = sizeof(TMesssageHeader);
                                InputBufferWithOffset = InputBuffer;
                                PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                                std::cout << "Connection closed on Recv" << std::endl;
                                break;
                            }
                            else
                            {
                                InputBytesNeeded -= iResult;
                                InputBufferWithOffset += iResult;
                                if (InputBytesNeeded == 0)
                                {
                                    if (Mode == MsgHeader)
                                    {
                                        InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
                                        memcpy(&MsgHdr, InputBuffer, sizeof(TMesssageHeader));
                                        MsgHdr.Len = ntohl(MsgHdr.Len);
                                        MsgHdr.Type = ntohl(MsgHdr.Type);
                                        InputBytesNeeded = MsgHdr.Len;
                                        Mode = Msg;
                                        if ((InputBytesNeeded + sizeof(TMesssageHeader)) > CurrentInputBufferSize)
                                        {
                                            CurrentInputBufferSize = InputBytesNeeded + sizeof(TMesssageHeader) + (10 * 1024);
                                            InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
                                            if (InputBuffer == NULL)
                                            {
                                                std::cout << "std::realloc failed " << std::endl;
                                                ExitProcess(0);
                                            }
                                            InputBufferWithOffset = InputBuffer + sizeof(TMesssageHeader);
                                        }

                                    }
                                    else if (Mode == Msg)
                                    {
                                        ProcessMessage(InputBuffer);
                                        // Setup for next message
                                        Mode = MsgHeader;
                                        InputBytesNeeded = sizeof(TMesssageHeader);
                                        InputBufferWithOffset = InputBuffer;
                                    }
                                }

                            }
                        }
                        else
                        {
                            int ssl_error = SSL_get_error(ssl, iResult);
                            std::cout << "ReadDataTcpNoBlock buff failed : " << ssl_error << std::endl;

                            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                                // Retry logic for non-blocking operations
                            }
                            
                        }
                    }

                }
                if (NetworkEvents.lNetworkEvents & FD_WRITE)
                {
                    if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
                    {
                        std::cout << "FD_WRITE failed with error " << NetworkEvents.iErrorCode[FD_WRITE_BIT] << std::endl;
                    }
                    else
                    {
                        std::cout << "FD_WRITE" << std::endl;
                    }
                }

                if (NetworkEvents.lNetworkEvents & FD_CLOSE)
                {
                    if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)

                    {
                        std::cout << "FD_CLOSE failed with error " << NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
                    }
                    else
                    {
                        std::cout << "FD_CLOSE" << std::endl;
                        PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                        break;
                    }

                }
            }

        }
    }
#endif
    if (InputBuffer)
    {
        std::free(InputBuffer);
        InputBuffer = nullptr;
    }
    ClientCleanup();
    std::cout << "Client Exiting" << std::endl;
    return 0;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------