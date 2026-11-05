// hooktest.c — standalone proof of the detour machinery before it goes anywhere
// near the game. Two synthetic 16-aligned RWX targets:
//   T6: `push rbx; sub rsp,0x20; ...`  — 6-byte first boundary (the EXACT shape
//       that v1's fixed-5-byte trampoline corrupted)
//   T5: `mov [rsp+0x10],rdx; ...`      — 5-byte boundary, leaf fn
// Both take SIX int args (5th/6th on the stack) and return the sum: proves the
// thunk preserves arg registers, stack args, rsp and the return value across
// stub -> thunk -> logger -> trampoline -> original body.
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdint.h>
#include <stdio.h>
#include "hookcore.h"
#include "iathook.h"

// Fake minimal PE image (in RW heap) exercising iathook_patch_module():
// a DOS header + NT headers + one import descriptor for a fake WINHTTP.dll
// with WinHttpOpen + WinHttpReadData + an unknown fn; verifies the two known
// slots get swapped (and only those), the unknown slot is untouched, and
// the saved originals point at the sentinel values.
static BYTE g_FakeImg[0x1000];
static const DWORD64 FAKE_REAL0 = 0x1111111111111111ULL;
static const DWORD64 FAKE_REAL1 = 0x2222222222222222ULL;
static const DWORD64 FAKE_REAL9 = 0x9999999999999999ULL;

static void build_fake_pe(void) {
    BYTE *b = g_FakeImg;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)b;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    DWORD64 *ilt, *iat;
    IMAGE_IMPORT_BY_NAME *ibn;
    char *names;
    dos->e_magic = 0x5A4D; dos->e_lfanew = 0x40;
    nt = (IMAGE_NT_HEADERS*)(b + 0x40);
    nt->Signature = 0x4550;
    nt->FileHeader.NumberOfSections = 0;
    nt->OptionalHeader.Magic = 0x20b;
    nt->OptionalHeader.DataDirectory[1].VirtualAddress = 0x200;
    nt->OptionalHeader.DataDirectory[1].Size = 40;
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(b + 0x200);
    imp[0].OriginalFirstThunk = 0x300;
    imp[0].FirstThunk = 0x340;
    imp[0].Name = 0x500;
    imp[1].Name = 0; // terminator
    ilt = (DWORD64*)(b + 0x300); iat = (DWORD64*)(b + 0x340);
    ibn = (IMAGE_IMPORT_BY_NAME*)(b + 0x400);
    ibn->Hint = 0;
    { const char *n = "WinHttpOpen"; char *d = (char*)ibn->Name;
      while (*n) *d++ = *n++; *d = 0; }
    ilt[0] = 0x400; iat[0] = FAKE_REAL0;
    // second entry, by the same hint/name VA style
    ibn = (IMAGE_IMPORT_BY_NAME*)(b + 0x430);
    ibn->Hint = 0;
    { const char *n = "WinHttpReadData"; char *d = (char*)ibn->Name;
      while (*n) *d++ = *n++; *d = 0; }
    ilt[1] = 0x430; iat[1] = FAKE_REAL1;
    // third: unknown fn must be skipped
    ibn = (IMAGE_IMPORT_BY_NAME*)(b + 0x460);
    ibn->Hint = 0;
    { const char *n = "WinHttpNotARealFn"; char *d = (char*)ibn->Name;
      while (*n) *d++ = *n++; *d = 0; }
    ilt[2] = 0x460; iat[2] = FAKE_REAL9;
    ilt[3] = 0; iat[3] = 0;
    names = (char*)(b + 0x500);
    { const char *n = "WINHTTP.dll"; char *d2 = names;
      while (*n) *d2++ = *n++; *d2 = 0; }
}

static int test_iat(void) {
    int n;
    DWORD64 *iat;
    build_fake_pe();
    extern void iathook_reset(void);
    iathook_reset();
    n = iathook_patch_module((HMODULE)g_FakeImg);
    iat = (DWORD64*)(g_FakeImg + 0x340);
    if (n != 2) { printf("FAIL: iat swapped=%d want 2\n", n); return 0; }
    if (iat[0] == FAKE_REAL0 || iat[1] == FAKE_REAL1) {
        printf("FAIL: iat slots not swapped\n"); return 0; }
    if (iat[2] != FAKE_REAL9) { printf("FAIL: unknown fn slot touched\n"); return 0; }
    if (iat[0] != (DWORD64)(uintptr_t)Hook_WinHttpOpen) {
        printf("FAIL: slot0 not Hook_WinHttpOpen\n"); return 0; }
    if (iat[1] != (DWORD64)(uintptr_t)Hook_WinHttpReadData) {
        printf("FAIL: slot1 not Hook_WinHttpReadData\n"); return 0; }
    printf("iat fake-pe ok (swapped 2, stubs live, unknown untouched)\n");
    return 1;
}

// --- session 12: WSAIoctl/ConnectEx through the *real* WS2_32 path ---
// Exercises exactly what the game will do: wrapper WSAIoctl hands us the
// ConnectEx fn pointer for WSAID_CONNECTEX (verifying our swap + our GUID
// bytes), then Hook_ConnectEx connects a bound client socket to a loopback
// listener. Also verifies the TLS ClientHello/SNI parser on canned bytes.

typedef BOOL (WINAPI *PFN_ConnectEx)(SOCKET, const struct sockaddr*, int,
    PVOID, DWORD, LPDWORD, LPOVERLAPPED);

static SOCKET g_Srv;
static volatile int g_Echoed = 0;

static DWORD WINAPI accept_worker(LPVOID p) {
    SOCKET srv = (SOCKET)(uintptr_t)p;
    SOCKET c = accept(srv, 0, 0);
    if (c != INVALID_SOCKET) {
        char b[256];
        int n = recv(c, b, sizeof(b), 0);
        if (n > 0) send(c, b, n, 0);   // echo the ClientHello-ish bytes back
        closesocket(c);
        g_Echoed = 1;
    }
    return 0;
}

// Load the REAL game exe as a data image and run the exact runtime IAT walk
// against it. Reproduces the swap count offline (names come from the ILT; the
// IAT slots hold file values, so this tests the parser, not resolution).
// Reconstruct the game's in-memory image layout (headers + sections at
// their RVAs) in a fresh allocation, then run the exact runtime IAT walk.
// This is byte-identical to what the game process looks like at boot (pre
// import resolution), so the parser result must match the game's count.
static BYTE *map_game_image(const wchar_t *path, DWORD *pSize) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE m; BYTE *raw, *img; DWORD hi = 0, size, imgSize;
    IMAGE_DOS_HEADER *dos; IMAGE_NT_HEADERS *nt; WORD nsec; IMAGE_SECTION_HEADER *sec;
    if (f == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(f, &hi); if (!size || hi) { CloseHandle(f); return 0; }
    m = CreateFileMappingW(f, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m) { CloseHandle(f); return 0; }
    raw = (BYTE*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
    if (!raw) { CloseHandle(m); CloseHandle(f); return 0; }
    dos = (IMAGE_DOS_HEADER*)raw;
    nt = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    imgSize = nt->OptionalHeader.SizeOfImage;
    img = (BYTE*)VirtualAlloc(NULL, imgSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!img) { UnmapViewOfFile(raw); CloseHandle(m); CloseHandle(f); return 0; }
    memcpy(img, raw, nt->OptionalHeader.SizeOfHeaders);
    nsec = nt->FileHeader.NumberOfSections;
    sec = (IMAGE_SECTION_HEADER*)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS));
    for (WORD s = 0; s < nsec; s++) {
        if (sec[s].SizeOfRawData)
            memcpy(img + sec[s].VirtualAddress, raw + sec[s].PointerToRawData, sec[s].SizeOfRawData);
    }
    UnmapViewOfFile(raw); CloseHandle(m); CloseHandle(f);
    *pSize = imgSize;
    return img;
}

static int test_gameimage(void) {
    DWORD sz = 0;
    BYTE *img = map_game_image(L"..\\..\\AoE2DE_s.exe", &sz);
    int n;
    if (!img) { printf("FAIL: map game image (err=%lu)\n", (unsigned long)GetLastError()); return 0; }
    iathook_reset();
    n = iathook_patch_module((HMODULE)img);
    printf("game-image iat walk: swapped %d of 68 (per-slot list in hooktest.log)\n", n);
    VirtualFree(img, 0, MEM_RELEASE);
    if (n != 68) { printf("FAIL: expected 68 swaps offline\n"); return 0; }
    return 1;
}

static const unsigned char CANNED_CH[] = {
    0x16,0x03,0x01,0x00,0x47, 0x01,0x00,0x00,0x3e, 0x03,0x03,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x00, 0x00,0x02,0x13,0x01, 0x01,0x00, 0x00,0x13,
    0x00,0x00, 0x00,0x0f, 0x00,0x0d, 0x00, 0x00,0x0a,
    't','e','s','t','.','l','o','c','a','l'
};

static int test_sni(void) {
    unsigned char junk[64];
    for (int i=0;i<64;i++) junk[i]=(unsigned char)(i+1);
    if (iathook_log_clienthello("sni-test", CANNED_CH, sizeof(CANNED_CH)) != 2) {
        printf("FAIL: SNI parser missed canned ClientHello rc=%d (want 2, SNI=test.local)\n",
               iathook_log_clienthello("dbg", CANNED_CH, sizeof(CANNED_CH))); return 0; }
    if (iathook_log_clienthello("sni-test", junk, 64) != 0) {
        printf("FAIL: SNI parser fired on garbage\n"); return 0; }
    printf("sni parser ok (test.local found, garbage rejected)\n");
    return 1;
}

static int test_wsa(void) {
    GUID guid = WSAID_CONNECTEX;
    void *ext = 0;
    DWORD ret = 0;
    WSADATA wsa;
    SOCKET cli = INVALID_SOCKET;
    struct sockaddr_in la, sa;
    int slen = sizeof(sa);
    HANDLE th;
    int r;
    if (WSAStartup(MAKEWORD(2,2), &wsa)) { printf("FAIL: WSAStartup\n"); return 0; }
    iathook_reset();
    extern int WINAPI WSAIoctl(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    iathook_set_real("WSAIoctl", (void*)WSAIoctl);
    iathook_set_real("WSASocketA", (void*)WSASocketA);
    iathook_set_real("socket", (void*)socket);
    iathook_set_real("connect", (void*)connect);
    iathook_set_real("send", (void*)send);
    iathook_set_real("recv", (void*)recv);
    iathook_set_real("closesocket", (void*)closesocket);
    iathook_set_real("GetQueuedCompletionStatus", (void*)GetQueuedCompletionStatus);
    g_Srv = socket(AF_INET, SOCK_STREAM, 0);
    la.sin_family = AF_INET; la.sin_addr.s_addr = htonl(0x7f000001); la.sin_port = 0;
    if (bind(g_Srv, (struct sockaddr*)&la, sizeof(la)) || listen(g_Srv, 1) ||
        getsockname(g_Srv, (struct sockaddr*)&sa, &slen)) {
        printf("FAIL: listener setup\n"); return 0;
    }
    th = CreateThread(NULL, 0, accept_worker, (LPVOID)(uintptr_t)g_Srv, 0, NULL);
    cli = (SOCKET)Hook_WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (cli == INVALID_SOCKET) { printf("FAIL: WSASocketA via hook\n"); return 0; }
    {
        struct sockaddr_in any;
        any.sin_family = AF_INET; any.sin_addr.s_addr = htonl(0x7f000001); any.sin_port = 0;
        if (bind(cli, (struct sockaddr*)&any, sizeof(any))) { printf("FAIL: bind\n"); return 0; }
    }
    r = Hook_WSAIoctl(cli, 0xC8000006u, &guid, sizeof(guid), &ext, sizeof(ext), &ret, 0, 0);
    if (r != 0 || !ext || ext != (void*)&Hook_ConnectEx || ret < 8) {
        printf("FAIL: WSAIoctl swap r=%d ext=%p ret=%lu\n", r, ext, (unsigned long)ret); return 0; }
    if (!g_RealConnectEx) { printf("FAIL: real ConnectEx not captured\n"); return 0; }
    printf("wsaioctl ok (out ptr = &Hook_ConnectEx, real captured)\n");
    {
        WSAOVERLAPPED ov; HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
        memset(&ov, 0, sizeof(ov)); ov.hEvent = ev;
        r = Hook_ConnectEx(cli, (const void*)&sa, sizeof(sa), NULL, 0, NULL, &ov);
        if (!r && WSAGetLastError() != ERROR_IO_PENDING) {
            printf("FAIL: ConnectEx err=%d\n", WSAGetLastError()); return 0; }
        if (WaitForSingleObject(ev, 3000) != WAIT_OBJECT_0) {
            printf("FAIL: ConnectEx did not complete\n"); return 0; }
        CloseHandle(ev);
    }
    printf("connectex ok (loopback connect through wrapper completed)\n");
    {
        char b[128];
        r = Hook_send(cli, (const char*)CANNED_CH, sizeof(CANNED_CH), 0);
        if (r != (int)sizeof(CANNED_CH)) { printf("FAIL: send via hook r=%d\n", r); return 0; }
        Sleep(200);
        {
            int n = Hook_recv(cli, b, sizeof(b), 0);
            if (n != (int)sizeof(CANNED_CH)) { printf("FAIL: echo recv n=%d\n", n); return 0; }
            for (unsigned k=0;k<sizeof(CANNED_CH);k++)
                if (b[k]!=(char)CANNED_CH[k]) { printf("FAIL: echo mismatch\n"); return 0; }
        }
        printf("send/recv ok (canned ClientHello echoed through hooks)\n");
    }
    WaitForSingleObject(th, 2000); CloseHandle(th);
    closesocket(cli); closesocket(g_Srv);
    printf("wsa end-to-end ok\n");
    return 1;
}

static const BYTE T6[] = {
    0x40,0x53,                    // push rbx
    0x48,0x83,0xEC,0x20,          // sub rsp, 0x20        (boundary at 6!)
    0x8B,0xD9,                    // mov ebx, ecx         (a)
    0x03,0xDA,                    // add ebx, edx         (b)
    0x41,0x03,0xD8,               // add ebx, r8d         (c)
    0x41,0x03,0xD9,               // add ebx, r9d         (d)
    0x03,0x5C,0x24,0x50,          // add ebx, [rsp+0x50]  (e)
    0x03,0x5C,0x24,0x58,          // add ebx, [rsp+0x58]  (f)
    0x8B,0xC3,                    // mov eax, ebx
    0x48,0x83,0xC4,0x20,          // add rsp, 0x20
    0x5B,                         // pop rbx
    0xC3,                         // ret
};
static const BYTE T5[] = {
    0x48,0x89,0x54,0x24,0x10,     // mov [rsp+0x10], rdx  (boundary at 5)
    0x48,0x89,0x4C,0x24,0x08,     // mov [rsp+0x08], rcx
    0x4C,0x89,0x44,0x24,0x18,     // mov [rsp+0x18], r8
    0x4C,0x89,0x4C,0x24,0x20,     // mov [rsp+0x20], r9
    0x48,0x8B,0x44,0x24,0x28,     // mov eax, [rsp+0x28]  (e)
    0x03,0x44,0x24,0x30,          // add eax, [rsp+0x30]  (f)
    0x03,0x44,0x24,0x10,          // add eax, [rsp+0x10]  (b)
    0x03,0x44,0x24,0x08,          // add eax, [rsp+0x08]  (a)
    0x03,0x44,0x24,0x18,          // add eax, [rsp+0x18]  (c)
    0x03,0x44,0x24,0x20,          // add eax, [rsp+0x20]  (d)
    0xC3,                         // ret
};

typedef int (*FN6)(int,int,int,int,int,int);

HOOKDEF g_Hooks[2] = {
    {"Test6", 0, T6, 0, 1, HK_RAW},
    {"Test5", 0, T5, 0, 1, HK_RAW},
};
const int g_NHooks = 2;

int main(void) {
    HANDLE hLog = CreateFileW(L"hooktest.log", GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hc_set_log(hLog, GetTickCount());
    log_line("hooktest: start");
    BYTE *page = (BYTE*)VirtualAlloc(NULL, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page) { printf("FAIL: VirtualAlloc\n"); return 1; }
    BYTE *p6 = page;            // 16-aligned
    BYTE *p5 = page + 0x100;    // 16-aligned
    for (int i=0;i<(int)sizeof(T6);i++) p6[i]=T6[i];
    for (int i=0;i<(int)sizeof(T5);i++) p5[i]=T5[i];
    FlushInstructionCache(GetCurrentProcess(), page, 0x1000);
    hc_alloc_near(p6);
    if (!hc_near_page()) { printf("FAIL: near page alloc\n"); return 1; }
    FN6 f6 = (FN6)p6, f5 = (FN6)p5;
    int r = f6(1,2,3,4,5,6);
    if (r != 21)  { printf("FAIL: pre-hook f6=%d\n", r); return 1; }
    r = f5(1,2,3,4,5,6);
    if (r != 21)  { printf("FAIL: pre-hook f5=%d\n", r); return 1; }
    printf("pre-hook ok (21, 21)\n");
    if (!hc_match_now(p6, g_Hooks[0].exp)) { printf("FAIL: T6 prologue\n"); return 1; }
    if (!hc_match_now(p5, g_Hooks[1].exp)) { printf("FAIL: T5 prologue\n"); return 1; }
    if (!hc_install_hook(p6, 0)) { printf("FAIL: install T6\n"); return 1; }
    if (!hc_install_hook(p5, 1)) { printf("FAIL: install T5\n"); return 1; }
    printf("installed both\n");
    { // debug: dump the patched target head and the near-page slot
      BYTE *slot6 = (BYTE*)g_TailTable[0];
      printf("p6 head : "); for (int i=0;i<8;i++)  printf("%02X ", p6[i]);    printf("\n");
      printf("slot6   : "); for (int i=0;i<40;i++) printf("%02X ", slot6[i]); printf("\n");
      printf("p6      : %p  slot: %p  delta=0x%llX\n", p6, slot6, (unsigned long long)(p6 - slot6));
      printf("thunk   : %p tail0 : %p\n", (void*)&lanhook_thunk, (void*)g_TailTable[0]);
    }
    __try {
        r = f6(1,2,3,4,5,6);
    } __except (printf("EXC in f6: code=0x%lX\n", GetExceptionCode())) { return 1; }
    if (r != 21)   { printf("FAIL: post-hook f6=%d\n", r); return 1; }
    r = f5(10,20,30,40,50,60);
    if (r != 210)  { printf("FAIL: post-hook f5=%d\n", r); return 1; }
    r = f6(100,200,300,400,500,600);
    if (r != 2100) { printf("FAIL: post-hook f6b=%d\n", r); return 1; }
    r = f5(1,1,1,1,1,1);
    if (r != 6)    { printf("FAIL: post-hook f5b=%d\n", r); return 1; }
    printf("post-hook ok (21, 210, 2100, 6) — thunk/trampoline verified\n");
    if (!test_iat()) return 1;
    if (!test_sni()) return 1;
    if (!test_wsa()) return 1;
    if (!test_gameimage()) return 1;
    log_line("hooktest: PASS");
    CloseHandle(hLog);
    return 0;
}
