#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
int main(void) {
    printf("before SymFromAddr\n"); fflush(stdout);
    char buf[sizeof(SYMBOL_INFO)+256]; PSYMBOL_INFO p=(PSYMBOL_INFO)buf;
    p->SizeOfStruct=sizeof(SYMBOL_INFO); p->MaxNameLen=255;
    DWORD64 d=0;
    BOOL ok = SymFromAddr(GetCurrentProcess(), (DWORD64)&printf, &d, p);
    printf("SymFromAddr returned %d err=%lu\n", ok, GetLastError());
    return 0;
}
