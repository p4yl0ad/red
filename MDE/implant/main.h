#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <tlhelp32.h>

//VirtualAllocEx - kernel32.dll
LPVOID ( WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

//WriteProcessMemory - kernel32.dll
BOOL ( WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

//CreateRemoteThread - kernel32.dll
HANDLE ( WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

//VirtualAlloc - kernel32.dll
LPVOID ( WINAPI * pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

//RtlMoveMemory - Ntdll.dll
VOID ( WINAPI * RtlMoveMemory)(
  _Out_       VOID UNALIGNED *Destination,
  _In_  const VOID UNALIGNED *Source,
  _In_        SIZE_T         Length
);


//VirtualProtect - kernel32.dll 
BOOL ( WINAPI * VirtualProtect)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);


//OpenProcess - kernel32.dll 
HANDLE ( WINAPI * OpenProcess)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);


//CreateToolhelp32Snapshot - kernel32.dll 
HANDLE ( WINAPI * CreateToolhelp32Snapshot)(
  DWORD dwFlags,
  DWORD th32ProcessID
);
