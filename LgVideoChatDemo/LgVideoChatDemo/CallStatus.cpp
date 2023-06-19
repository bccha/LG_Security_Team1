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
#include "CallStatus.h"

#define MAX_BUFFER        1024
#define CALL_STATUS_PORT 10002
#define TOKEN "0123456789abcdef"

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
    std::cout << "WaitCallRequest1" << std::endl;
    // 1. ���ϻ���    
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == INVALID_SOCKET)
    {
        std::cout << "socket() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }
    std::cout << "WaitCallRequest2" << std::endl;
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
    std::cout << "WaitCallRequest3" << std::endl;
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
    std::cout << "WaitCallRequest4" << std::endl;
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
            std::cout << "WaitCallRequest7" << std::endl;
            hThread = CreateThread(NULL, 0, MakeThread, (void*)clientSocket, 0, NULL);
            CloseHandle(hThread);
            std::cout << "WaitCallRequest8" << std::endl;
        }

    }
    std::cout << "WaitCallRequest5" << std::endl;
    // 6-2. ���� ��������
    closesocket(listenSocket);

    return 0;
}

static DWORD WINAPI MakeThread(void* data)
{
    SOCKET socket = (SOCKET)data;
    // 5-1. ������ �б�
    char messageBuffer[MAX_BUFFER];
    int receiveBytes;
    while (receiveBytes = recv(socket, messageBuffer, MAX_BUFFER, 0))
    {
        if (receiveBytes > 0)
        {
            printf("Server TRACE - Receive message : %s (%d bytes)\n", messageBuffer, receiveBytes);
            // 5-2. ������ ����
            int sendBytes = send(socket, messageBuffer, receiveBytes, 0);
            if (sendBytes > 0)
            {
                printf("Server TRACE - Send message : %s (%d bytes)\n", messageBuffer, sendBytes);
            }
        }
        else
        {
            break;
        }
    }
    closesocket(socket);
    printf("End - makeThread\n");
    return 0;
}

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length)
{
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
        char * messageBuffer = (char *)message;
        unsigned int bufferLen = message_length;
        printf("Clinet message:%s, len:%u\n", message, message_length);

        // 3-1. ������ ����
        int sendBytes = send(listenSocket, messageBuffer, bufferLen, 0);
        if (sendBytes > 0)
        {
            printf("Client TRACE - Send message : %s (%d bytes)\n", messageBuffer, sendBytes);
            // 3-2. ������ �б�
            int receiveBytes = recv(listenSocket, messageBuffer, MAX_BUFFER, 0);
            if (receiveBytes > 0)
            {
                printf("Client TRACE - Receive message : %s (%d bytes)\n* Enter Message\n->", messageBuffer, receiveBytes);
            }
        }
    }

    // 4. ��������
    closesocket(listenSocket);

    return 0;
}