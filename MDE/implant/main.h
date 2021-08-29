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


// pointer defs here
////inject 

//VirtualAllocEx
LPVOID ( WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

//WriteProcessMemory
BOOL ( WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

//CreateRemoteThread
HANDLE ( WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

//VirtualAlloc
LPVOID ( WINAPI * pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);



/*
RtlMoveMemory
VirtualProtect
OpenProcess
CreateToolhelp32Snapshot
*/
