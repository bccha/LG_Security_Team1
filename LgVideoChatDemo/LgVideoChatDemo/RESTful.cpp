#include <atlstr.h>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include "Resource.h"
#include "RESTful.h"

using namespace web;
using namespace web::http;
using namespace web::http::client;

static utility::string_t ServerUrl = U("https://192.168.0.136:8000");

int LoginFromApp(HWND hDlg, const char* ip)
{
    CStringW cstring(ip);
    HWND hEditWnd;
    WCHAR buffer[256];
    json::value data;

    hEditWnd = GetDlgItem(hDlg, IDC_EDIT_EMAIL);
    GetWindowTextW(hEditWnd, buffer, sizeof(buffer));
    data[U("email")] = json::value::string(buffer, false);

    hEditWnd = GetDlgItem(hDlg, IDC_EDIT_PASSWORD);
    GetWindowTextW(hEditWnd, buffer, sizeof(buffer));
    data[U("password")] = json::value::string(buffer, false);

    hEditWnd = GetDlgItem(hDlg, IDC_EDIT_TOKEN);
    GetWindowTextW(hEditWnd, buffer, sizeof(buffer));
    data[U("token")] = json::value::string(buffer, false);

    data[U("ip_address")] = json::value::string((const utility::char_t*)cstring, false);

    http_client_config config;
    config.set_validate_certificates(false);

    http_client client(ServerUrl, config);

    client.request(methods::POST, U("/login_from_app"), data.serialize(), U("application/json"))
        .then([](http_response response)
    {
        if (response.status_code() == status_codes::OK)
        {
            return response.extract_string();
        }
        else
        {
            throw std::runtime_error("HTTP request failed");
        }
    })
        .then([](utility::string_t responseBody)
    {
        std::wcout << responseBody << std::endl;
    })
        .wait();

    return 0;
}
