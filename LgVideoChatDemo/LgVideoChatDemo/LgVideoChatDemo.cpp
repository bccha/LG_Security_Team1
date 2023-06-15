// LgVideoChatDemo.cpp : Defines the entry point for the application.
//
#include "framework.h"
#include <Commctrl.h>
#include <atlstr.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <opencv2\highgui\highgui.hpp>
#include <opencv2\opencv.hpp>
#include "VoipVoice.h"
#include "LgVideoChatDemo.h"
#include "VideoServer.h"
#include "Camera.h"
#include "DisplayImage.h"
#include "VideoClient.h"
#include "litevad.h"
#include "RESTful.h"

#pragma comment(lib,"comctl32.lib")
#ifdef _DEBUG
#pragma comment(lib,"..\\..\\opencv\\build\\x64\\vc16\\lib\\opencv_world470d.lib")
#else
#pragma comment(lib,"..\\..\\opencv\\build\\x64\\vc16\\lib\\opencv_world470.lib")
#endif
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAX_LOADSTRING 100

#define IDC_LABEL_REMOTE       1010
#define IDC_EDIT_REMOTE        1011
#define IDC_CHECKBOX_LOOPBACK  1012 
#define IDC_EDIT               1013 
#define IDM_CONNECT            1014
#define IDM_DISCONNECT         1015
#define IDM_START_SERVER       1016
#define IDM_STOP_SERVER        1017
#define IDC_LABEL_VAD_STATE    1018
#define IDC_VAD_STATE_STATUS   1019
#define IDC_CHECKBOX_AEC       1020 
#define IDC_CHECKBOX_NS        1021
#define IDM_LOGIN              1022
// Global Variables:

HWND hWndMain;
GUID InstanceGuid;
char LocalIpAddress[512] = "127.0.0.1";
TVoipAttr VoipAttr = {true,false};

static HINSTANCE hInst;                                // current instance
static WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
static WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

static char RemoteAddress[512]="127.0.0.1";
static bool Loopback=false;

static FILE* pCout = NULL;
static HWND hWndMainToolbar;
static HWND hWndEdit;

// Forward declarations of functions included in this code module:
static ATOM                MyRegisterClass(HINSTANCE hInstance);
static BOOL                InitInstance(HINSTANCE, int);
static LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK    Login(HWND, UINT, WPARAM, LPARAM);


static LRESULT OnCreate(HWND, UINT, WPARAM, LPARAM);
static LRESULT OnSize(HWND, UINT, WPARAM, LPARAM);
static int OnConnect(HWND, UINT, WPARAM, LPARAM);
static int OnDisconnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static int OnStartServer(HWND, UINT, WPARAM, LPARAM);
static int OnStopServer(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static int PRINT(const TCHAR* fmt, ...);
static void SetHostAddr(void);
static void SetStdOutToNewConsole(void);
static void DisplayMessageOkBox(const char* Msg);
static bool OnlyOneInstance(void);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    WSADATA wsaData;
    HRESULT hr;

    SetStdOutToNewConsole();

    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        std::cout << "WSAStartup failed with error " << res << std::endl;
        return 1;
    }
    SetHostAddr();
    hr = CoCreateGuid(&InstanceGuid);
    if (hr != S_OK)
    {
        std::cout << "GUID Create Failure " << std::endl;
        return 1;
    }
    printf("Guid = {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}\n",
        InstanceGuid.Data1, InstanceGuid.Data2, InstanceGuid.Data3,
        InstanceGuid.Data4[0], InstanceGuid.Data4[1], InstanceGuid.Data4[2], InstanceGuid.Data4[3],
        InstanceGuid.Data4[4], InstanceGuid.Data4[5], InstanceGuid.Data4[6], InstanceGuid.Data4[7]);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_LGVIDEOCHATDEMO, szWindowClass, MAX_LOADSTRING);

    if (!OnlyOneInstance())
    {
        std::cout << "Another Instance Running " << std::endl;
        return 1;
    }

    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        WSACleanup();
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_LGVIDEOCHATDEMO));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
  
    if (pCout)
    {
      fclose(pCout);
      FreeConsole();
    }
    WSACleanup();
    return (int) msg.wParam;
}
static void SetStdOutToNewConsole(void)
{
    // Allocate a console for this app
    AllocConsole();
    //AttachConsole(ATTACH_PARENT_PROCESS);
    freopen_s(&pCout, "CONOUT$", "w", stdout);
}
static void SetHostAddr(void)
{
    // Get the local hostname
    struct addrinfo* _addrinfo;
    struct addrinfo* _res;
    char _address[INET6_ADDRSTRLEN];
    char szHostName[255];
    gethostname(szHostName, sizeof(szHostName));
    getaddrinfo(szHostName, NULL, 0, &_addrinfo);

    for (_res = _addrinfo; _res != NULL; _res = _res->ai_next)
    {
        if (_res->ai_family == AF_INET)
        {
            if (NULL == inet_ntop(AF_INET,
                &((struct sockaddr_in*)_res->ai_addr)->sin_addr,
                _address,
                sizeof(_address))
                )
            {
                perror("inet_ntop");
                return;
            }
            strcpy_s(RemoteAddress, sizeof(RemoteAddress), _address);
            strcpy_s(LocalIpAddress, sizeof(LocalIpAddress), _address);
        }
    }
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
static ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_LGVIDEOCHATDEMO));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_LGVIDEOCHATDEMO);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
static BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
             int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDC_EDIT_REMOTE:
            {
             HWND hEditWnd;
             hEditWnd = GetDlgItem(hWnd, IDC_EDIT_REMOTE);
             GetWindowTextA(hEditWnd, RemoteAddress,sizeof(RemoteAddress));
            }
            break;
            
            case IDC_CHECKBOX_LOOPBACK:
            {
                BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_LOOPBACK);
                if (checked) {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_LOOPBACK, BST_UNCHECKED);
                    Loopback = false;;
                }
                else {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_LOOPBACK, BST_CHECKED);
                    Loopback = true;
                }
            }
            break;

            case IDC_CHECKBOX_AEC:
            {
                BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_AEC);
                if (checked) {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_AEC, BST_UNCHECKED);
                    VoipAttr.AecOn = false;;
                }
                else {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_AEC, BST_CHECKED);
                    VoipAttr.AecOn = true;
                }
            }
            break;

            case IDC_CHECKBOX_NS:
            {
                BOOL checked = IsDlgButtonChecked(hWnd, IDC_CHECKBOX_NS);
                if (checked) {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_NS, BST_UNCHECKED);
                    VoipAttr.NoiseSuppressionOn = false;;
                }
                else {
                    CheckDlgButton(hWnd, IDC_CHECKBOX_NS, BST_CHECKED);
                    VoipAttr.NoiseSuppressionOn = true;
                }
            }
            break;

            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            case IDM_CONNECT:
                if (OnConnect(hWnd, message, wParam, lParam))
                {
                    SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
                        (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
                    SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_DISCONNECT,
                        (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
                }
                break;
            case IDM_DISCONNECT:
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
                    (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_DISCONNECT,
                    (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
                OnDisconnect(hWnd, message, wParam, lParam);
                break;
            case IDM_START_SERVER:
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_START_SERVER,
                    (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_STOP_SERVER,
                    (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
                EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LOOPBACK), false);
                //EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AEC), false);
                //EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_NS), false);
                OnStartServer(hWnd, message, wParam, lParam);
                break;
            case IDM_STOP_SERVER:
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_START_SERVER,
                    (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
                SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_STOP_SERVER,
                    (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
                EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_LOOPBACK), true);
                //EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_AEC), true);
                //EnableWindow(GetDlgItem(hWnd, IDC_CHECKBOX_NS), true);
                OnStopServer(hWnd, message, wParam, lParam);
                break;
            case IDM_LOGIN:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGINBOX), hWnd, Login);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_CREATE:
        OnCreate(hWnd, message, wParam, lParam);
        break;
    case WM_SIZE:
        OnSize(hWnd, message, wParam, lParam);
        break;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CLIENT_LOST:
        std::cout << "WM_CLIENT_LOST" << std::endl;
        SendMessage(hWndMain, WM_COMMAND, IDM_DISCONNECT, 0);
        break;
    case WM_REMOTE_CONNECT:
        SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
            (LPARAM)MAKELONG(TBSTATE_INDETERMINATE, 0));
        break;
    case WM_REMOTE_LOST:
        SendMessage(hWndMainToolbar, TB_SETSTATE, IDM_CONNECT,
            (LPARAM)MAKELONG(TBSTATE_ENABLED, 0));
        break;
    case WM_VAD_STATE:
        {
          HWND hTempWnd;
          litevad_result_t VadState;
          hTempWnd = GetDlgItem(hWnd, IDC_VAD_STATE_STATUS);
          VadState = (litevad_result_t)wParam;
          switch (VadState) 
          {
          case LITEVAD_RESULT_SPEECH_BEGIN:
              SetWindowTextA(hTempWnd, "Speech");
              break;
          case LITEVAD_RESULT_SPEECH_END:
              SetWindowTextA(hTempWnd, "Speech End");
              break;
          case LITEVAD_RESULT_SPEECH_BEGIN_AND_END:
              SetWindowTextA(hTempWnd, "Speech Begin & End");
              break;
          case LITEVAD_RESULT_FRAME_SILENCE:
              SetWindowTextA(hTempWnd, "Silence");
              break;
          case LITEVAD_RESULT_FRAME_ACTIVE:
              break;
          case LITEVAD_RESULT_ERROR:
              SetWindowTextA(hTempWnd, "VAD Error");
              break;
          default:
              SetWindowTextA(hTempWnd, "Unknown Error");
              break;
          }
        }
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
static INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for login box.
static INT_PTR CALLBACK Login(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            LoginFromApp(hDlg, LocalIpAddress);

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

HIMAGELIST g_hImageList = NULL;

HWND CreateSimpleToolbar(HWND hWndParent)
{
    // Declare and initialize local constants.
    const int ImageListID = 0;
    const int numButtons = 5;
    const int bitmapSize = 16;

    const DWORD buttonStyles = BTNS_AUTOSIZE;

    // Create the toolbar.
    HWND hWndToolbar = CreateWindowEx(0, TOOLBARCLASSNAME, NULL,
        WS_CHILD | TBSTYLE_WRAPABLE,
        0, 0, 0, 0,
        hWndParent, NULL, hInst, NULL);

    if (hWndToolbar == NULL)
        return NULL;

    // Create the image list.
    g_hImageList = ImageList_Create(bitmapSize, bitmapSize,   // Dimensions of individual bitmaps.
        ILC_COLOR16 | ILC_MASK,   // Ensures transparent background.
        numButtons, 0);

    // Set the image list.
    SendMessage(hWndToolbar, TB_SETIMAGELIST,
        (WPARAM)ImageListID,
        (LPARAM)g_hImageList);

    // Load the button images.
    SendMessage(hWndToolbar, TB_LOADIMAGES,
        (WPARAM)IDB_STD_SMALL_COLOR,
        (LPARAM)HINST_COMMCTRL);

    // Initialize button info.
    // IDM_NEW, IDM_OPEN, and IDM_SAVE are application-defined command constants.

    TBBUTTON tbButtons[numButtons] =
    {
        { MAKELONG(VIEW_NETCONNECT,    ImageListID), IDM_CONNECT,     TBSTATE_ENABLED,       buttonStyles, {0}, 0, (INT_PTR)L"Connect" },
        { MAKELONG(VIEW_NETDISCONNECT, ImageListID), IDM_DISCONNECT,  TBSTATE_INDETERMINATE, buttonStyles, {0}, 0, (INT_PTR)L"Disconnect"},
        { MAKELONG(VIEW_NETCONNECT,    ImageListID), IDM_START_SERVER,TBSTATE_ENABLED,       buttonStyles, {0}, 0, (INT_PTR)L"Start Server"},
        { MAKELONG(VIEW_NETDISCONNECT, ImageListID), IDM_STOP_SERVER, TBSTATE_INDETERMINATE, buttonStyles, {0}, 0, (INT_PTR)L"Stop Server"},
        { MAKELONG(VIEW_NETCONNECT,    ImageListID), IDM_LOGIN,       TBSTATE_ENABLED,       buttonStyles, {0}, 0, (INT_PTR)L"Login"}
    };

    // Add buttons.
    SendMessage(hWndToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
    SendMessage(hWndToolbar, TB_ADDBUTTONS, (WPARAM)numButtons, (LPARAM)&tbButtons);

    // Resize the toolbar, and then show it.
    SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0);
    ShowWindow(hWndToolbar, TRUE);

    return hWndToolbar;
}


static LRESULT OnCreate(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    UINT checked;
    InitCommonControls();

    CreateWindow(_T("STATIC"),
        _T("Remote Address:"),
        WS_VISIBLE | WS_CHILD,
        5, 50,120,20,
        hWnd,
        (HMENU)IDC_LABEL_REMOTE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);
   
    CreateWindow(_T("STATIC"),
        _T("VAD State:"),
        WS_VISIBLE | WS_CHILD,
        260, 50,70, 20,
        hWnd,
        (HMENU)IDC_LABEL_VAD_STATE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindow(_T("STATIC"),
        _T("Unknown"),
        WS_VISIBLE | WS_CHILD,
        335, 50, 120, 20,
        hWnd,
        (HMENU)IDC_VAD_STATE_STATUS,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    CreateWindowExA(WS_EX_CLIENTEDGE,
        "EDIT", RemoteAddress,
        WS_CHILD | WS_VISIBLE,
        130, 50, 120, 20,
        hWnd,
        (HMENU)IDC_EDIT_REMOTE,
        ((LPCREATESTRUCT)lParam)->hInstance, NULL);

    if (Loopback)  checked = BST_CHECKED;
    else checked = BST_UNCHECKED;

    CreateWindow(_T("button"), _T("Loopback"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        5, 75, 85, 20,
        hWnd, (HMENU)IDC_CHECKBOX_LOOPBACK, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_LOOPBACK, checked);

    if (VoipAttr.AecOn)  checked = BST_CHECKED;
    else checked = BST_UNCHECKED;

    CreateWindow(_T("button"), _T("AEC"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        95, 75, 50, 20,
        hWnd, (HMENU)IDC_CHECKBOX_AEC, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_AEC, checked);

    if (VoipAttr.NoiseSuppressionOn)  checked = BST_CHECKED;
    else checked = BST_UNCHECKED;

    CreateWindow(_T("button"), _T("Noise Suppression"),
        WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
        150, 75, 145, 20,
        hWnd, (HMENU)IDC_CHECKBOX_NS, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
    CheckDlgButton(hWnd, IDC_CHECKBOX_NS, checked);

    hWndEdit = CreateWindow(_T("edit"), NULL,
        WS_CHILD | WS_BORDER | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_READONLY,
        0, 0, 0, 0, hWnd, (HMENU)IDC_EDIT, hInst, NULL);

    hWndMainToolbar = CreateSimpleToolbar(hWnd);

    hWndMain = hWnd;
    InitializeImageDisplay(hWndMain);
    return 1;
}

LRESULT OnSize(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int cxClient, cyClient;

    cxClient = LOWORD(lParam);
    cyClient = HIWORD(lParam);

    MoveWindow(hWndEdit, 5, cyClient - 130, cxClient - 10, 120, TRUE);

    return DefWindowProc(hWnd, message, wParam, lParam);
}

static int OnConnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    CStringW cstring(RemoteAddress);

    PRINT(_T("Remote Address : %s Loopback %s\r\n"), cstring, Loopback ? _T("True"): _T("False"));
 
    if (!IsVideoClientRunning())
    {
        if (OpenCamera())
        {
            if (ConnectToSever(RemoteAddress, VIDEO_PORT))
            {
                std::cout << "Connected to Server" << std::endl;
                StartVideoClient();
                std::cout << "Video Client Started.." << std::endl;
                VoipVoiceStart(RemoteAddress, VOIP_LOCAL_PORT, VOIP_REMOTE_PORT, VoipAttr);
                std::cout << "Voip Voice Started.." << std::endl;
                return 1;
            }
            else
            {
                DisplayMessageOkBox("Connection Failed!");
                return 0;
            }
                
        }
        else 
          {
            std::cout << "Open Camera Failed" << std::endl;
            return 0;
          }
    }
    return 0;
}
static int OnDisconnect(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    VoipVoiceStop();
    if (IsVideoClientRunning())
    {
        StopVideoClient();
        CloseCamera();
        std::cout << "Video Client Stopped" << std::endl;
    }
    return 1;
}

static int PRINT(const TCHAR* fmt, ...)
{
    va_list argptr;
    TCHAR buffer[2048];
    int cnt;

    int iEditTextLength;
    HWND hWnd = hWndEdit;

    if (NULL == hWnd) return 0;

    va_start(argptr, fmt);

    cnt = wvsprintf(buffer, fmt, argptr);

    va_end(argptr);

    iEditTextLength = GetWindowTextLength(hWnd);
    if (iEditTextLength + cnt > 30000)       // edit text max length is 30000
    {
        SendMessage(hWnd, EM_SETSEL, 0, 10000);
        SendMessage(hWnd, WM_CLEAR, 0, 0);
        PostMessage(hWnd, EM_SETSEL, 0, 10000);
        iEditTextLength = iEditTextLength - 10000;
    }
    SendMessage(hWnd, EM_SETSEL, iEditTextLength, iEditTextLength);
    SendMessage(hWnd, EM_REPLACESEL, 0, (LPARAM)buffer);
    return(cnt);
}
static int OnStartServer(HWND, UINT, WPARAM, LPARAM)
{
    StartVideoServer(Loopback);
    
    return 0;
}
static int OnStopServer(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    StopVideoServer();
    return 0;
}
static void DisplayMessageOkBox(const char* Msg)
{
    int msgboxID = MessageBoxA(
        NULL,
        Msg,
        "Information",
        MB_OK
    );

    switch (msgboxID)
    {
    case IDCANCEL:
        // TODO: add code
        break;
    case IDTRYAGAIN:
        // TODO: add code
        break;
    case IDCONTINUE:
        // TODO: add code
        break;
    }

}

static bool OnlyOneInstance(void)
{
    HANDLE m_singleInstanceMutex = CreateMutex(NULL, TRUE, L"F2CBD5DE-2AEE-4BDA-8C56-D508CFD3F4DE");
    if (m_singleInstanceMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) 
    {
        HWND existingApp = FindWindow(0, szTitle);
        if (existingApp)
        {
            ShowWindow(existingApp, SW_NORMAL);
            SetForegroundWindow(existingApp);
        }
        return false; 
    }
    return true;
}
//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------
