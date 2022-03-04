#pragma once
#pragma warning(disable: 4390)
#pragma warning(disable: 4503)

#include "ntdll.h"
#include <Windows.h>
#include <Lmcons.h>
#include <strsafe.h>
#include <comdef.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <pathcch.h>
#include <psapi.h>
#include <iostream>
#include <wil/resource.h>
#include <bcrypt.h>

#pragma comment (lib, "bcrypt.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Pathcch.lib")

#define DUMP_MODE 0
#define KILL_MODE 1
#define SUSPEND_MODE 2
#define RESUME_MODE 3
#define LEAK_MODE 4

#define OPSEC
#ifndef OPSEC
#define AUTHOR L"@last0x00"
#define VERSION L"0.3"
#define PRINTDEBUG(...) PrintDebug(__VA_ARGS__)
#define PRINTVERBOSE(...) PrintVerbose(__VA_ARGS__)
#define PRINTLASTERROR(x) PrintLastError(x)
#define PRINTUSAGE() PrintUsage()
#define PRINTARGUMENTS() PrintArguments()
#define WPRINTF(...) wprintf(__VA_ARGS__)
#define PRINTF(...) printf(__VA_ARGS__)
#define ADVLOG 1
#else
#define AUTHOR L""
#define VERSION L""
#define PRINTDEBUG(...)
#define PRINTVERBOSE(...)
#define PRINTLASTERROR(x)
#define PRINTUSAGE()
#define PRINTARGUMENTS()
#define WPRINTF(...)
#endif

#define AESKEY {0}
#define IV {0}

#include "Log.h"
#include "MetaString.h"
#include "lazy_importer.hpp"

using namespace andrivet::ADVobfuscator;

extern BOOL g_bVerbose;
extern BOOL g_bDebug;
extern BOOL g_bForce;
extern DWORD g_dwProcessId;
extern LPWSTR g_pwszDumpFilePath;
extern LPWSTR g_pwszProcessName;
extern LPWSTR g_pwszExecutionMode;
extern int g_intExecutionMode;

BOOL ParseArguments(int argc, wchar_t* argv[]);
VOID PrintArguments();
VOID PrintUsage();

VOID PrintLastError(LPCWSTR pwszFunctionName);
VOID PrintVerbose(LPCWSTR pwszFormat, ...);
VOID PrintDebug(LPCWSTR pwszFormat, ...);

BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel);
BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel);
BOOL ProcessGetIntegrityLevel(DWORD dwProcessId, PDWORD pdwIntegrityLevel);
BOOL ProcessGetPIDFromName(LPWSTR pwszProcessName, PDWORD pdwProcessId);

HANDLE ObjectManagerCreateDirectory(LPCWSTR dirname);
HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname);

BOOL TokenGetSid(HANDLE hToken, PSID* ppSid);
BOOL TokenGetSidAsString(HANDLE hToken, LPWSTR* ppwszStringSid);
BOOL TokenCompareSids(PSID pSidA, PSID pSidB);
BOOL TokenGetUsername(HANDLE hToken, LPWSTR* ppwszUsername);
BOOL TokenCheckPrivilege(HANDLE hToken, LPCWSTR pwszPrivilege, BOOL bEnablePrivilege);
BOOL TokenIsNotRestricted(HANDLE hToken, PBOOL pbIsNotRestricted);
BOOL MiscSystemArchIsAmd64();
BOOL MiscGenerateGuidString(LPWSTR* ppwszGuid);
bool AESDecrypt(_Inout_ BYTE* payload, _In_ DWORD payload_len, _In_ BYTE* key, _In_ DWORD keylen, _In_ BYTE* iv, _In_ DWORD IVlength);
bool UnhookDll(_In_ LPCWSTR lpszDllName);