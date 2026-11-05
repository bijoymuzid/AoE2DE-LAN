#include <windows.h>
#include <stdio.h>
int main(void) {
    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char cmd[] = "fwdtest.exe";
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    printf("created=%d err=%lu pid=%lu\n", ok, ok?0:GetLastError(), ok?pi.dwProcessId:0);
    if (ok) {
        DWORD rc = WaitForSingleObject(pi.hProcess, 5000);
        DWORD code = 0xFFFFFFFF; GetExitCodeProcess(pi.hProcess, &code);
        printf("wait=%lu exit=%08lx\n", rc, code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    FILE*f=fopen("D:\fwmarker.txt","r");
    if(f){ char b[256]; size_t n=fread(b,1,255,f); b[n]=0; printf("marker: %s", b); fclose(f);} else printf("marker missing\n");
    return 0;
}
