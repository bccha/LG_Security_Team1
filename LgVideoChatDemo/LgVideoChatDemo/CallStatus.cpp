/*
## ���� ���� : 1 v n - multithread
1. socket()            : ���ϻ���
2. bind()            : ���ϼ���
3. listen()            : ���Ŵ�⿭����
4. accept()            : ������
*. CreateThread        : ������ ����
5. read()&write()
    WIN recv()&send    : ������ �а���
6. close()
    WIN closesocket    : ��������
*/

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "Crypto.h"
#include "CallStatus.h"

#define MAX_BUFFER        1024
#define CALL_STATUS_PORT 10002

static DWORD ThreadCallStatusID;
static HANDLE hThreadCallStatus = INVALID_HANDLE_VALUE;

static DWORD WINAPI MakeThread(void* data);
static DWORD WINAPI WaitCallRequest(LPVOID ivalue);
static bool isServerEnabled = false;

void StartWaitCallThread(void) {
    isServerEnabled = true;
    if (hThreadCallStatus == INVALID_HANDLE_VALUE)
    {
        hThreadCallStatus = CreateThread(NULL, 0, WaitCallRequest, NULL, 0, &ThreadCallStatusID);
    }
}
void StopWaitCall(void) {
    isServerEnabled = false;
    if (hThreadCallStatus != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadCallStatus, INFINITE);
        CloseHandle(hThreadCallStatus);
        hThreadCallStatus = INVALID_HANDLE_VALUE;
    }
}

static DWORD WINAPI WaitCallRequest(LPVOID ivalue)
{
    std::cout << "===== Waiting CallRequest Start ======" << std::endl;
    // 1. ���ϻ���    
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET)
    {
        std::cout << "socket() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }

    // �������� ��ü����
    SOCKADDR_IN serverAddr;
    memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
    serverAddr.sin_family = PF_INET;
    serverAddr.sin_port = htons(CALL_STATUS_PORT);
    serverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

    // 2. ���ϼ���
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
    {
        printf("Error - Fail bind\n");
        // 6. ��������
        closesocket(listenSocket);
        return 1;
    }

    // 3. ���Ŵ�⿭����
    if (listen(listenSocket, 5) == SOCKET_ERROR)
    {
        printf("Error - Fail listen\n");
        // 6. ��������
        closesocket(listenSocket);
        return 1;
    }

    // ������ �������� ����
    SOCKADDR_IN clientAddr;
    int addrLen = sizeof(SOCKADDR_IN);
    memset(&clientAddr, 0, addrLen);
    SOCKET clientSocket;

    // ���� ������ non-blocking ���� ����
    unsigned long mode = 1;
    if (ioctlsocket(listenSocket, FIONBIO, &mode) != 0) {
        // ���� ó��
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }

    // thread Handle ����
    HANDLE hThread;

    while (1)
    {
        // 4. ������
        //std::cout << "WaitCallRequest6" << std::endl;
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &addrLen);

        if (clientSocket == -1) {
            if (!isServerEnabled) {
                std::cout << "close waiting " << std::endl;
                break;
            }
        }
        else {
            std::cout << "Client request to connect" << std::endl;
            hThread = CreateThread(NULL, 0, MakeThread, (void*)clientSocket, 0, NULL);
            CloseHandle(hThread);
            std::cout << "Connenction done" << std::endl;
        }

    }

    // 6-2. ���� ��������
    closesocket(listenSocket);
    std::cout << "===== Waiting CallRequest End ======" << std::endl;
    return 0;
}

static DWORD WINAPI MakeThread(void* data)
{
    int call_status = 0;
    std::string token = "0123456789abcdef";
    unsigned char decrypted_data[MAX_BUFFER] = { 0 };
    unsigned char encrypted_data[MAX_BUFFER] = { 0 };
    size_t decrypted_data_size = 0;
    size_t encrypted_data_size = 0;
    SOCKET socket = (SOCKET)data;
    // 5-1. ������ �б�
    char messageBuffer[MAX_BUFFER];
    int receiveBytes;
    int err = errno;
    while (receiveBytes = recv(socket, messageBuffer, MAX_BUFFER, 0))
    {
        if (receiveBytes > 0)
        {
            RsaDecryptWithKey((const unsigned char *)messageBuffer, receiveBytes, decrypted_data, &decrypted_data_size);
            printf("Server TRACE - Receive message : %s (%d bytes)\n", decrypted_data, decrypted_data_size);

            if (strncmp((const char*)decrypted_data, token.c_str(), token.length())) {
                std::cout << "token is invalid" << std::endl;
                call_status = 1;
            }
            else {
                std::cout << "token is valid" << std::endl;
                call_status = 0;
            }
            GenerateEncryptedKeyData(call_status, encrypted_data, &encrypted_data_size);

            // 5-2. ������ ����
            Sleep(1000);
            int sendBytes = send(socket, (const char *)encrypted_data, encrypted_data_size, 0);
            if (sendBytes > 0)
            {
                printf("Server TRACE - Send message : %s (%d bytes)\n", messageBuffer, sendBytes);
            }
        }
        else
        {
            if ((err == EAGAIN) || (err == EWOULDBLOCK) || (receiveBytes == -1)) {
                std::cout << "Wait recv :" << receiveBytes << std::endl;
                continue;
            }
            else {
                std::cout << "Stop recv :" << receiveBytes << std::endl;
                break;
            }
        }
    }
    closesocket(socket);
    printf("End - makeThread\n");
    return 0;
}

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length)
{
    unsigned int callstatus = 1;
    unsigned char encrypted_data[1000] = { 0 };
    size_t encryted_data_size = 0;
    // 1. ���ϻ���
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        printf("Error - Invalid socket\n");
        return 1;
    }

    // �������� ��ü����
    SOCKADDR_IN serverAddr;
    memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(CALL_STATUS_PORT);
    inet_pton(AF_INET, remotehostname, &serverAddr.sin_addr);

    // encryption befor connect
    RsaEncryptWithKey((const unsigned char*)message, message_length, encrypted_data, &encryted_data_size);

    // 2. �����û
    if (connect(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        printf("Error - Fail to connect\n");
        // 4. ��������
        closesocket(listenSocket);
        return 1;
    }
    {
        // �޽��� �Է�
        char* messageBuffer;
        unsigned int bufferLen;

        messageBuffer = (char*)encrypted_data;
        bufferLen = encryted_data_size;
        printf("Clinet message:%s, len:%u\n", message, message_length);

        // 3-1. ������ ����
        int sendBytes = send(listenSocket, messageBuffer, bufferLen, 0);
        if (sendBytes > 0)
        {
            printf("Client TRACE - Send message(%d bytes) : %s \n", sendBytes, messageBuffer);
            // 3-2. ������ �б�
            int receiveBytes = recv(listenSocket, messageBuffer, MAX_BUFFER, 0);
            if (receiveBytes > 0)
            {
                printf("Client TRACE - Receive message : %s (%d bytes)\n* Enter Message\n->", messageBuffer, receiveBytes);
                ParsingEncryptedKeyData(callstatus, (unsigned char*)messageBuffer, receiveBytes);
                std::cout << "Call Status:" << callstatus << std::endl;

            }
        }
    }

    // 4. ��������
    closesocket(listenSocket);
    return callstatus;
}