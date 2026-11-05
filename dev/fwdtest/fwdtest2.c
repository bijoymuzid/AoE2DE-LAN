#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
int main(void) {
    const char *m1 = "D:/fwmarker.txt";
    FILE*f=fopen(m1,"w");
    if(f){fprintf(f,"started\n");fclose(f);}
    char buf[sizeof(SYMBOL_INFO)+256]; PSYMBOL_INFO p=(PSYMBOL_INFO)buf;
    p->SizeOfStruct=sizeof(SYMBOL_INFO); p->MaxNameLen=255;
    DWORD64 d=0;
    BOOL ok = SymFromAddr(GetCurrentProcess(), (DWORD64)&printf, &d, p);
    f=fopen(m1,"a");
    if(f){fprintf(f,"SymFromAddr returned %d err=%lu\n", ok, GetLastError());fclose(f);}
    return 0;
}
