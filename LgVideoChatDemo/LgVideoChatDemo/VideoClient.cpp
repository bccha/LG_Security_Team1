#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include < cstdlib >
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "VideoClient.h"
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "Camera.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "Crypto.h"


enum InputMode { ImageSize, Image };
static  std::vector<uchar> sendbuff;//buffer for coding
static  std::vector<uchar> encryptedSendbuff;//buffer for Encryption
static  std::vector<uchar> decryptedRecvbuff;//buffer for Decryption
static HANDLE hClientEvent=INVALID_HANDLE_VALUE;
static HANDLE hEndVideoClientEvent=INVALID_HANDLE_VALUE;
static HANDLE hTimer = INVALID_HANDLE_VALUE;
static SOCKET Client = INVALID_SOCKET;
static cv::Mat ImageIn;
static DWORD ThreadVideoClientID;
static HANDLE hThreadVideoClient = INVALID_HANDLE_VALUE;

static DWORD WINAPI ThreadVideoClient(LPVOID ivalue);
static void VideoClientSetExitEvent(void);
static void VideoClientCleanup(void);

static void VideoClientSetExitEvent(void)
{
  if (hEndVideoClientEvent != INVALID_HANDLE_VALUE)
  SetEvent(hEndVideoClientEvent);
}
static void VideoClientCleanup(void)
{
    std::cout << "VideoClientCleanup" << std::endl;

    if (hClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hClientEvent);
        hClientEvent = INVALID_HANDLE_VALUE;
    }
    if (hEndVideoClientEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hEndVideoClientEvent);
        hEndVideoClientEvent = INVALID_HANDLE_VALUE;
    }
    if (hTimer!= INVALID_HANDLE_VALUE)
    {
        CloseHandle(hTimer);
        hTimer = INVALID_HANDLE_VALUE;
    }
    if (Client != INVALID_SOCKET)
    {
        closesocket(Client);
        Client = INVALID_SOCKET;
    }
}

bool ConnectToSever(const char* remotehostname, unsigned short remoteport)
{
    int iResult;
    struct addrinfo   hints;
    struct addrinfo* result = NULL;
    char remoteportno[128];

    sprintf_s(remoteportno,sizeof(remoteportno), "%d", remoteport);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
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
        std::cout << "video client socket() failed with error "<< WSAGetLastError() << std::endl;
        return false;
    }

    //----------------------
    // Connect to server.
    iResult = connect(Client, result->ai_addr, (int)result->ai_addrlen);
    freeaddrinfo(result);
    if (iResult == SOCKET_ERROR) {
        std::cout << "connect function failed with error : "<< WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error :"<< WSAGetLastError() << std::endl;
        return false;
    }
    return true;

}
bool StartVideoClient(void)
{
 hThreadVideoClient = CreateThread(NULL, 0, ThreadVideoClient, NULL, 0, &ThreadVideoClientID);
 return true;
}

bool StopVideoClient(void)
{
    VideoClientSetExitEvent();
    if (hThreadVideoClient != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadVideoClient, INFINITE);
        CloseHandle(hThreadVideoClient);
        hThreadVideoClient = INVALID_HANDLE_VALUE;
    }
;
    return true;
}
bool IsVideoClientRunning(void)
{
    if (hThreadVideoClient == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    else return true;
}

static DWORD WINAPI ThreadVideoClient(LPVOID ivalue)
{    
    HANDLE ghEvents[3];
    int NumEvents;
    int iResult;
    DWORD dwEvent;
    LARGE_INTEGER liDueTime;
    InputMode Mode = ImageSize;
    unsigned int InputBytesNeeded=sizeof(unsigned int);
    unsigned int SizeofImage;
    char* InputBuffer = NULL;
    char* InputBufferWithOffset = NULL;
    unsigned int CurrentInputBufferSize = 1024 * 10;
  
    InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
    InputBufferWithOffset = InputBuffer;

    if (InputBuffer == NULL)
    {
      std::cout << "InputBuffer Realloc failed" << std::endl;
      return 1;
    }
 
    liDueTime.QuadPart = 0LL;

    hTimer = CreateWaitableTimer(NULL, FALSE, NULL);

    if (NULL == hTimer)
    {
        std::cout << "CreateWaitableTimer failed "<< GetLastError() << std::endl;
        return 2;
    }

    if (!SetWaitableTimer(hTimer, &liDueTime, VIDEO_FRAME_DELAY, NULL, NULL, 0))
    {
        std::cout << "SetWaitableTimer failed  " << GetLastError() << std::endl;
        return 3;
    }
    hClientEvent = WSACreateEvent();
    hEndVideoClientEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (WSAEventSelect(Client, hClientEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)

    {
        std::cout << "WSAEventSelect() failed with error "<< WSAGetLastError() << std::endl;
        iResult = closesocket(Client);
        Client = INVALID_SOCKET;
        if (iResult == SOCKET_ERROR)
            std::cout << "closesocket function failed with error : " << WSAGetLastError() << std::endl;
        return 4;
    }
    ghEvents[0] = hEndVideoClientEvent;
    ghEvents[1] = hClientEvent;
    ghEvents[2] = hTimer;
    NumEvents = 3;

    while (1) {
     dwEvent = WaitForMultipleObjects(
         NumEvents,        // number of objects in array
         ghEvents,       // array of objects
         FALSE,           // wait for any object
         INFINITE);  // INFINITE) wait

     if (dwEvent == WAIT_OBJECT_0) break;
     else if (dwEvent == WAIT_OBJECT_0 + 1)
     {
         WSANETWORKEVENTS NetworkEvents;
         if (SOCKET_ERROR == WSAEnumNetworkEvents(Client, hClientEvent, &NetworkEvents))
         {
             std::cout << "WSAEnumNetworkEvent: "<< WSAGetLastError() << "dwEvent "<< dwEvent << " lNetworkEvent "<<std::hex<< NetworkEvents.lNetworkEvents<< std::endl;
             NetworkEvents.lNetworkEvents = 0;
         }
         else
         {
             if (NetworkEvents.lNetworkEvents & FD_READ)
             {
                 if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
                 {
                     std::cout << "FD_READ failed with error " << NetworkEvents.iErrorCode[FD_READ_BIT]<< std::endl;
                 }
                 else
                 {
                   int iResult;
                   iResult = ReadDataTcpNoBlock(Client, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
                   std::cout << "Client iResult:" << iResult << std::endl;
                   if (iResult != SOCKET_ERROR)
                   {
                       if (iResult == 0)
                       {
                           Mode = ImageSize;
                           InputBytesNeeded = sizeof(unsigned int);
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
                               if (Mode == ImageSize)
                               {
                                   Mode = Image;
                                   InputBufferWithOffset = InputBuffer;;
                                   memcpy(&SizeofImage, InputBuffer, sizeof(SizeofImage));
                                   SizeofImage = ntohl(SizeofImage);
                                   InputBytesNeeded = SizeofImage;
                                   if (InputBytesNeeded > CurrentInputBufferSize)
                                   {   
                                       CurrentInputBufferSize = InputBytesNeeded + (10 * 1024);
                                       InputBuffer = (char*)std::realloc(InputBuffer, CurrentInputBufferSize);
                                       if (InputBuffer == NULL)
                                       {
                                           std::cout << "std::realloc failed " << std::endl;
                                       }
                                   }
                                   InputBufferWithOffset = InputBuffer;;
                               }
                               else if (Mode == Image)
                               {
                                   size_t decrypted_size = 0;
                                   Mode = ImageSize;
                                   InputBytesNeeded = sizeof(unsigned int);
                                   InputBufferWithOffset = InputBuffer;
                                   if (!AesDecryptForRecieve((const unsigned char*)InputBuffer, SizeofImage,
                                       &decryptedRecvbuff, &decrypted_size)) {
                                       std::cout << "Client decryption failed";
                                   }
                                   std::cout << "Client Decrypted size:" << decrypted_size  << std::endl;
                                   cv::imdecode(cv::Mat(SizeofImage, 1, CV_8UC1, decryptedRecvbuff.data()), cv::IMREAD_COLOR, &ImageIn);
                                   DispayImage(ImageIn);
                                   decryptedRecvbuff.clear();
                               }
                           }

                       }
                   }
                  else std::cout << "ReadDataTcpNoBlock buff failed " << WSAGetLastError() << std::endl;

                 }

             }
             if (NetworkEvents.lNetworkEvents & FD_WRITE)
             {
                 if (NetworkEvents.iErrorCode[FD_WRITE_BIT] != 0)
                 {
                     std::cout << "FD_WRITE failed with error "<< NetworkEvents.iErrorCode[FD_WRITE_BIT] << std::endl;
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
                     std::cout << "FD_CLOSE failed with error "<< NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
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
     else if (dwEvent == WAIT_OBJECT_0 + 2)
      {
         unsigned int numbytes;
         size_t encyprted_size = 0;

         if (!GetCameraFrame(sendbuff))
         {
             std::cout << "Camera Frame Empty" << std::endl;
         }
         if (!AesEncryptForSend(sendbuff.data(), sendbuff.size(),
             &encryptedSendbuff, (size_t*)&encyprted_size))
         {
             std::cout << "Client encryption failed" << std::endl;
         }
         std::cout << "Client Encrypted_Size: " << encyprted_size <<" buffsize:"<< encryptedSendbuff.size() << std::endl;
         numbytes = htonl((unsigned long)encryptedSendbuff.size());
         if (WriteDataTcp(Client, (unsigned char*)&numbytes, sizeof(numbytes)) == sizeof(numbytes))
         {
             if (WriteDataTcp(Client, (unsigned char*)encryptedSendbuff.data(), (int)encryptedSendbuff.size()) != encryptedSendbuff.size())
             {
                 std::cout << "WriteDataTcp encryptedSendbuff.data() Failed " << WSAGetLastError() << std::endl;
                 PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
                 break;
             }
         }
         else
         {
             std::cout << "WriteDataTcp encryptedSendbuff.size() Failed " << WSAGetLastError() << std::endl;
             PostMessage(hWndMain, WM_CLIENT_LOST, 0, 0);
             break;
         }
         encryptedSendbuff.clear();
      }
     }
    if (InputBuffer)
    {
        std::free(InputBuffer);
        InputBuffer = nullptr;
    }
    VideoClientCleanup();
    std::cout << "Video Client Exiting" << std::endl;
    return 0;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------