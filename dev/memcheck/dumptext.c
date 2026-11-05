// dumptext.c — dump AoE2DE_s.exe .text from a running process (post-decrypt)
// usage: dumptext.exe <pid> <out.bin>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: dumptext <pid> <out>\n"); return 2; }
    DWORD pid = (DWORD)strtoul(argv[1], 0, 10);
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { printf("open fail %lu\n", GetLastError()); return 1; }
    // find module base
    DWORD64 base = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32W me; me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) do {
        if (!lstrcmpiW(me.szModule, L"AoE2DE_s.exe")) base = (DWORD64)me.modBaseAddr;
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    if (!base) { printf("no module\n"); return 1; }
    printf("base %llx\n", base);
    FILE *o = fopen(argv[2], "wb");
    DWORD64 rva = 0x1000, end = 0x3196000;
    SIZE_T total = 0;
    while (rva < end) {
        BYTE buf[0x10000];
        SIZE_T n = 0;
        DWORD64 chunk = 0x10000; if (rva + chunk > end) chunk = end - rva;
        if (ReadProcessMemory(h, (LPCVOID)(base + rva), buf, (DWORD)chunk, &n) && n) {
            fwrite(buf, 1, n, o); total += n;
        } else {
            fwrite(buf, 1, 0, o); // hole: pad with nothing (we track rva separately)
            memset(buf, 0xCC, sizeof(buf));
            // write zeros to keep alignment
            fwrite(buf, 1, chunk, o); total += chunk;
        }
        rva += chunk;
    }
    fclose(o); CloseHandle(h);
    printf("dumped %llu bytes\n", (unsigned long long)total);
    return 0;
}
