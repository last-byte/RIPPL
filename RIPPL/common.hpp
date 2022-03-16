#pragma once
#pragma warning(disable: 4390)

#define DUMP_MODE 0 // -D
#define KILL_MODE 1 // -K
#define SUSPEND_MODE 2 // -S
#define RESUME_MODE 3 // -R
#define LEAK_MODE 4 // -L
#define JOB_SUPPRESS_MODE 5 // -X
#define JOB_KILL_MODE 6 // -W
#define SUICIDE_MODE 7 // -Z
#define TOKEN_DOWNGRADE_MODE 8 // -T
#define DRIVER_UNLOAD_MODE 9 // -U

//#define OPSEC // OPSEC enabling macro, if not defined the program will have verbose output

#include <Windows.h>
#include <Lmcons.h>
#include <strsafe.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <sddl.h>
#include <wil/resource.h>
#include <psapi.h>
#include <aclapi.h>
#include <iostream>
#include <vector>
#include <string>

#include "lazy_importer.hpp"
#include "ntdll.h"
#include "skCrypter.hpp"