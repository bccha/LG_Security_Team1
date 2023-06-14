#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include < iostream >
#include <new>
#include "VideoServer.h"
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "TcpSendRecv.h"
#include "DisplayImage.h"
#include "Camera.h"
#include "Crypto.h"

static  std::vector<uchar> sendbuff;//buffer for coding
static  std::vector<uchar> encryptedSendbuff;//buffer for Encryption
static  std::vector<uchar> decryptedRecvbuff;//buffer for Decryption
enum InputMode { ImageSize, Image };
static HANDLE hAcceptEvent=INVALID_HANDLE_VALUE;
static HANDLE hListenEvent = INVALID_HANDLE_VALUE;
static HANDLE hEndVideoServerEvent=INVALID_HANDLE_VALUE;
static HANDLE hTimer = INVALID_HANDLE_VALUE;
static SOCKET Listen = INVALID_SOCKET;
static SOCKET Accept = INVALID_SOCKET;
static cv::Mat ImageIn;
static DWORD ThreadVideoServerID;
static HANDLE hThreadVideoServer = INVALID_HANDLE_VALUE;
static int NumEvents;
static unsigned int InputBytesNeeded;
static char* InputBuffer = NULL;
static char* InputBufferWithOffset = NULL;
static InputMode Mode = ImageSize;
static bool RealConnectionActive = false;

static void VideoServerSetExitEvent(void);
static void VideoServerCleanup(void);
static DWORD WINAPI ThreadVideoServer(LPVOID ivalue);
static void CleanUpClosedConnection(void);

bool StartVideoServer(bool &Loopback)
{
  if (hThreadVideoServer == INVALID_HANDLE_VALUE)
    {
        hThreadVideoServer = CreateThread(NULL, 0, ThreadVideoServer, &Loopback, 0, &ThreadVideoServerID);
    }
  return true;
}
bool StopVideoServer(void)
{
    VideoServerSetExitEvent();
    if (hThreadVideoServer != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(hThreadVideoServer, INFINITE);
        hThreadVideoServer = INVALID_HANDLE_VALUE;
    }
    VideoServerCleanup();
    return true;
}
bool IsVideoServerRunning(void)
{
    if (hThreadVideoServer = INVALID_HANDLE_VALUE) return false;
    else return true;

}
static void VideoServerSetExitEvent(void)
{
 if (hEndVideoServerEvent != INVALID_HANDLE_VALUE)
  SetEvent(hEndVideoServerEvent);
}
static void VideoServerCleanup(void)
{
    if (hListenEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hListenEvent);
        hListenEvent = INVALID_HANDLE_VALUE;
    }
    if (hAcceptEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hAcceptEvent);
        hAcceptEvent = INVALID_HANDLE_VALUE;
    }
    if (hEndVideoServerEvent != INVALID_HANDLE_VALUE)
    {
      CloseHandle(hEndVideoServerEvent);
      hEndVideoServerEvent = INVALID_HANDLE_VALUE;
    }
    if (hTimer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hTimer);
        hTimer = INVALID_HANDLE_VALUE;
    }

    if (Listen != INVALID_SOCKET)
    {
        closesocket(Listen);
        Listen = INVALID_SOCKET;
    }
    if (Accept != INVALID_SOCKET)
    {
        closesocket(Accept);
        Accept = INVALID_SOCKET;
    } 
}

static DWORD WINAPI ThreadVideoServer(LPVOID ivalue)
{
    SOCKADDR_IN InternetAddr;
    HANDLE ghEvents[4];
    DWORD dwEvent;
    bool  Loopback = *((bool*)ivalue);
    bool  LoopbackOverRide = false;
    unsigned int SizeofImage;
    unsigned int CurrentInputBufferSize = 1024 * 10;

    std::cout << "Video Server Started Loopback " << (Loopback ? "True" : "False") << std::endl;
    
    RealConnectionActive = false;
    Mode = ImageSize;
    InputBytesNeeded = sizeof(unsigned int);
    InputBuffer = (char*)std::realloc(NULL, CurrentInputBufferSize);
    InputBufferWithOffset = InputBuffer;

    if (InputBuffer == NULL)
    { 
        std::cout << "InputBuffer Realloc failed" << std::endl;
        return 1;
    }

    if ((Listen = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        std::cout << "socket() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }

    hListenEvent = WSACreateEvent();
    
    hEndVideoServerEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (WSAEventSelect(Listen, hListenEvent, FD_ACCEPT | FD_CLOSE) == SOCKET_ERROR)

    { 
        std::cout << "WSAEventSelect() failed with error "<< WSAGetLastError() << std::endl;
        return 1;
    }
    InternetAddr.sin_family = AF_INET;
    InternetAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    InternetAddr.sin_port = htons(VIDEO_PORT);

    if (bind(Listen, (PSOCKADDR)&InternetAddr, sizeof(InternetAddr)) == SOCKET_ERROR)

    {
        std::cout << "bind() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }

    if (listen(Listen, 5))

    {
        std::cout << "listen() failed with error " << WSAGetLastError() << std::endl;
        return 1;
    }

    ghEvents[0] = hEndVideoServerEvent;
    ghEvents[1] = hListenEvent;
    NumEvents = 2;
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
         if (SOCKET_ERROR == WSAEnumNetworkEvents(Listen, hListenEvent, &NetworkEvents))
         {
             std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError()<<" dwEvent  " << dwEvent<<" lNetworkEvent "<< std::hex<< NetworkEvents.lNetworkEvents<< std::endl;
             NetworkEvents.lNetworkEvents = 0;
         }
         else
         {
             if (NetworkEvents.lNetworkEvents & FD_ACCEPT)

             {
                 if (NetworkEvents.iErrorCode[FD_ACCEPT_BIT] != 0)
                 {
                     std::cout << "FD_ACCEPT failed with error " << NetworkEvents.iErrorCode[FD_ACCEPT_BIT]<<std::endl;
                 }
                 else
                 {
                     if (Accept == INVALID_SOCKET)
                     {
                         struct sockaddr_storage sa;
                         socklen_t sa_len = sizeof(sa);
                         char RemoteIp[INET6_ADDRSTRLEN];

                         LARGE_INTEGER liDueTime;

                         // Accept a new connection, and add it to the socket and event lists
                         Accept = accept(Listen, (struct sockaddr*)&sa, &sa_len);
                         
                         int err = getnameinfo((struct sockaddr*)&sa, sa_len, RemoteIp, sizeof(RemoteIp), 0, 0, NI_NUMERICHOST);
                         if (err != 0) {
                             snprintf(RemoteIp, sizeof(RemoteIp), "invalid address");
                         }
                         else
                         {
                             std::cout << "Accepted Connection " << RemoteIp << std::endl;
                         }
                         if (!Loopback)
                         {
                             if ((strcmp(RemoteIp,LocalIpAddress) == 0) ||
                                 (strcmp(RemoteIp, "127.0.0.1") == 0) )
                             {
                                 LoopbackOverRide = true;
                                 std::cout << "Loopback Over Ride" << std::endl;
                             }
                             else LoopbackOverRide = false;
                         }

                         PostMessage(hWndMain, WM_REMOTE_CONNECT, 0, 0);
                         hAcceptEvent = WSACreateEvent();
                         WSAEventSelect(Accept, hAcceptEvent, FD_READ |FD_WRITE |FD_CLOSE);
                         ghEvents[2] = hAcceptEvent;
                         if ((Loopback) || (LoopbackOverRide))  NumEvents = 3;
                         else
                         {
                             liDueTime.QuadPart = 0LL;
                             if (!OpenCamera())
                             {
                                 std::cout << "OpenCamera() Failed" << std::endl;
                                 break;
                             }
                             VoipVoiceStart(RemoteIp, VOIP_LOCAL_PORT, VOIP_REMOTE_PORT, VoipAttr);
                             std::cout << "Voip Voice Started.." << std::endl;
                             RealConnectionActive = true;
                             hTimer = CreateWaitableTimer(NULL, FALSE, NULL);

                             if (NULL == hTimer)
                             {
                                 std::cout << "CreateWaitableTimer failed " << GetLastError() << std::endl;
                                 break;
                             }

                             if (!SetWaitableTimer(hTimer, &liDueTime, VIDEO_FRAME_DELAY, NULL, NULL, 0))
                             {
                                 std::cout << "SetWaitableTimer failed  " << GetLastError() << std::endl;
                                 break;
                             }
                             ghEvents[3] = hTimer;
                             NumEvents = 4;
                         }
                     }
                     else
                     {
                         SOCKET Temp = accept(Listen, NULL, NULL);
                         if (Temp != INVALID_SOCKET)
                         {
                             closesocket(Temp);
                             std::cout << "Refused-Already Connected" << std::endl;
                         }

                     }
                 }

             }
             if (NetworkEvents.lNetworkEvents & FD_CLOSE)
             {
                 if (NetworkEvents.iErrorCode[FD_CLOSE_BIT] != 0)

                 {
                     std::cout << "FD_CLOSE failed with error on Listen Socket" << NetworkEvents.iErrorCode[FD_CLOSE_BIT] <<std::endl;
                 }

                 closesocket(Listen);
                 Listen = INVALID_SOCKET;
             }
         }
     }
     else if (dwEvent == WAIT_OBJECT_0 + 2)
     {
         WSANETWORKEVENTS NetworkEvents;
         if (SOCKET_ERROR == WSAEnumNetworkEvents(Accept, hAcceptEvent, &NetworkEvents))
         {   
             std::cout << "WSAEnumNetworkEvent: " << WSAGetLastError() << " dwEvent  " << dwEvent << " lNetworkEvent " << std::hex << NetworkEvents.lNetworkEvents << std::endl;
             NetworkEvents.lNetworkEvents = 0;
         }
         else
         {
             if (NetworkEvents.lNetworkEvents & FD_READ)
             {
                 if (NetworkEvents.iErrorCode[FD_READ_BIT] != 0)
                 {
                     std::cout << "FD_READ failed with error "<< NetworkEvents.iErrorCode[FD_READ_BIT] << std::endl;
                 }
                 else if ((Loopback) || (LoopbackOverRide))
                 {
                     unsigned char *buffer;
                     u_long bytesAvailable;
                     int bytestosend;
                     int iResult;

                     ioctlsocket(Accept, FIONREAD, &bytesAvailable);
                     if (bytesAvailable >= 0)
                     {
                         buffer = new (std::nothrow) unsigned char[bytesAvailable];
                         //std::cout << "FD_READ "<< bytesAvailable << std::endl;
                         iResult = ReadDataTcpNoBlock(Accept, buffer, bytesAvailable);
                         std::cout << "Server iResult:" << iResult << std::endl;
                         if (iResult > 0)
                         {
                             bytestosend = iResult;
                             iResult = WriteDataTcp(Accept, buffer, bytestosend);
                             delete[] buffer;
                             if (iResult == SOCKET_ERROR)
                             {
                                 std::cout << "WriteDataTcp failed: " << WSAGetLastError() << std::endl;
                             }
                         }
                         else if (iResult == 0)
                         {
                             std::cout << "Connection closed on Recv" << std::endl;
                             CleanUpClosedConnection();
                         }
                         else
                         {
                             std::cout << "ReadDataTcpNoBlock failed:" << WSAGetLastError() <<std::endl;
                         }
                     }
                 }
                 else // No Loopback
                 {
                     int iResult;

                     iResult = ReadDataTcpNoBlock(Accept, (unsigned char*)InputBufferWithOffset, InputBytesNeeded);
                     if (iResult != SOCKET_ERROR)
                     {
                         if (iResult == 0)
                         {
                             CleanUpClosedConnection();
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
                                         std::cout << "Server decryption failed";
                                     }
                                     std::cout << "Server Decrypted size:" << decrypted_size << std::endl;
                                     cv::imdecode(cv::Mat(SizeofImage, 1, CV_8UC1, decryptedRecvbuff.data()), cv::IMREAD_COLOR, &ImageIn);
                                     DispayImage(ImageIn);
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
                     std::cout << "FD_CLOSE failed with error Connection "<< NetworkEvents.iErrorCode[FD_CLOSE_BIT] << std::endl;
                 }
                 else
                 {
                     std::cout << "FD_CLOSE" << std::endl;
                     
                 }
                 CleanUpClosedConnection();
             }
          }

       }
     else if (dwEvent == WAIT_OBJECT_0 + 3)
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
                 std::cout << "Server encryption failed" << std::endl;
             }
             std::cout << "Server Encrypted_Size: " << encyprted_size << " buffsize:" << encryptedSendbuff.size() << std::endl;
             numbytes = htonl((unsigned long)encryptedSendbuff.size());
             if (WriteDataTcp(Accept, (unsigned char*)&numbytes, sizeof(numbytes)) == sizeof(numbytes))
             {
                 if (WriteDataTcp(Accept, (unsigned char*)encryptedSendbuff.data(), (int)encryptedSendbuff.size()) != sendbuff.size())
                 {
                     std::cout << "WriteDataTcp encryptedSendbuff.data() Failed " << WSAGetLastError() << std::endl;
                     CleanUpClosedConnection();
                 }
             }
             else 
             {
                   std::cout << "WriteDataTcp encryptedSendbuff.size() Failed " << WSAGetLastError() << std::endl;
                   CleanUpClosedConnection();
             }
             encryptedSendbuff.clear();
       }
     

     }
    
    CleanUpClosedConnection();
    VideoServerCleanup();
    std::cout << "Video Server Stopped" << std::endl;
    return 0;
}
static void CleanUpClosedConnection(void)
{
    if (Accept != INVALID_SOCKET)
    {
        closesocket(Accept);
        Accept = INVALID_SOCKET;
        PostMessage(hWndMain, WM_REMOTE_LOST, 0, 0);
    }
    if (hAcceptEvent != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hAcceptEvent);
        hAcceptEvent = INVALID_HANDLE_VALUE;
    }
    if (hTimer != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hTimer);
        hTimer = INVALID_HANDLE_VALUE;
    }
    if (RealConnectionActive)
    {
        CloseCamera();
        VoipVoiceStop();
    }
    Mode = ImageSize;
    InputBytesNeeded = sizeof(unsigned int);
    InputBufferWithOffset = InputBuffer;
    NumEvents = 2;
    RealConnectionActive = false;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------