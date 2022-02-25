#pragma once

#include "ntdll.h"

#include <Windows.h>
#include <Lmcons.h>
#include <strsafe.h>
#include <comdef.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <pathcch.h>
#include <iostream>

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Pathcch.lib")

#define AUTHOR L"@last0x00"
#define VERSION L"0.1"
#define DUMP_MODE 0
#define KILL_MODE 1
#define SUSPEND_MODE 2
#define RESUME_MODE 3
#define LEAK_MODE 4

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
