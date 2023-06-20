#pragma once

typedef struct
{
    std::wstring firstName;
    std::wstring lastName;
    std::wstring email;
    std::wstring key;
} PEER;

int CallRequest(const char* remotehostname, const char* message, unsigned int message_length);
void StartWaitCallThread(void);
void StopWaitCall(void);
void SetIsCalling(bool isCalling);
