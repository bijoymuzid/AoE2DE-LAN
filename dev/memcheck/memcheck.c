// memcheck.c — AoE2LAN M0.3 runtime-memory probe.
// Launches a PE suspended, reads memory at given RVAs, optionally resumes
// for N seconds, re-reads, then terminates. Validates whether on-disk
// "garbage" code regions are decrypted at runtime, without a debugger.
// Usage: memcheck.exe <exe-path> <wait-secs> <rva-hex...>
// Output: base + 64-byte hex dumps per RVA at T0 (suspended) and T1 (resumed).
// Static CRT, no dependencies beyond kernel32.
#include <windows.h>
#include <stdio.h>

static void dump(HANDLE hProc, DWORD64 base, DWORD64 rva) {
    BYTE buf[64];
    SIZE_T n = 0;
    DWORD64 va = base + rva;
    printf("  RVA %llx (VA %llx): ", rva, va);
    if (ReadProcessMemory(hProc, (LPCVOID)va, buf, sizeof(buf), &n) && n == sizeof(buf)) {
        for (int i = 0; i < 64; i++) printf("%02x", buf[i]);
        printf("\n");
    } else {
        printf("READ FAIL err=%lu\n", GetLastError());
    }
}

int main(int argc, char **argv) {
    if (argc < 4) { printf("usage: memcheck <exe> <wait-secs> <rva...>\n"); return 2; }
    const char *exe = argv[1];
    int wait_s = atoi(argv[2]);

    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    char cmd[1024]; snprintf(cmd, sizeof(cmd), "\"%s\"", exe);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess FAIL err=%lu\n", GetLastError());
        return 1;
    }
    // Primary thread starts with Rdx = PEB. ImageBase = PEB+0x10.
    CONTEXT cx; ZeroMemory(&cx, sizeof(cx)); cx.ContextFlags = CONTEXT_INTEGER;
    DWORD64 base = 0;
    if (GetThreadContext(pi.hThread, &cx)) {
        DWORD64 peb = cx.Rdx;
        SIZE_T n = 0;
        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(peb + 0x10), &base, 8, &n))
            printf("PEB read FAIL err=%lu\n", GetLastError());
    } else printf("GetThreadContext FAIL err=%lu\n", GetLastError());
    printf("imagebase=%llx\n", base);
    printf("T0 suspended:\n");
    for (int i = 3; i < argc; i++)
        dump(pi.hProcess, base, strtoull(argv[i], NULL, 16));
    if (wait_s > 0) {
        ResumeThread(pi.hThread);
        printf("-- resumed, waiting %ds --\n", wait_s);
        Sleep(wait_s * 1000);
        printf("T1 running:\n");
        for (int i = 3; i < argc; i++)
            dump(pi.hProcess, base, strtoull(argv[i], NULL, 16));
    }
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    printf("done\n");
    return 0;
}
