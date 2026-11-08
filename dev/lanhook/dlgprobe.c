// dlgprobe.c - MEASURE the crypt32 root-store consent dialog, then auto-click it.
//
// Why: RootRegThread calls CertAddCertificateContextToStore on the user Root
// store at BOOT (t=0.125 s, measured in logs/lanhook-12816.log). That call pops
// a consent dialog and BLOCKS until a human answers. Nobody answers during an
// automated run, so the run dies. This probe reproduces the exact call offline
// (no game) and reports what the dialog actually is, so the auto-click can be
// written against measured facts instead of guesses.
//
// Build: mkdlg.cmd   Run: dlgprobe.exe [--noclick] [--cert cert.der]
//   --noclick  only measure, leave the dialog up for a human
// Writes: adds our own self-signed root to HKCU Root (same as srvtest already
// does), and removes it again at the end so repeated runs stay dialog-producing.

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define IDYES_BTN 6   // IDYES
#define IDNO_BTN  7   // IDNO

static volatile LONG g_stop;
static volatile LONG g_clicked;
static int g_noclick;
static DWORD g_selfPid;

static PCCERT_CONTEXT g_cert;

static void get_text(HWND h, char *out, int n) {
    wchar_t w[256];
    int len = GetWindowTextW(h, w, 250);
    out[0] = 0;
    if (len <= 0) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, "?", NULL);
}

static void get_class(HWND h, char *out, int n) {
    wchar_t w[128];
    GetClassNameW(h, w, 120);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, n, "?", NULL);
}

// Windows already reported (keeps the 100 ms poll readable).
#define SEEN_MAX 256
static HWND g_seen[SEEN_MAX];
static int  g_seenN;
static int seen(HWND h) {
    int i;
    for (i = 0; i < g_seenN; i++) if (g_seen[i] == h) return 1;
    if (g_seenN < SEEN_MAX) g_seen[g_seenN++] = h;
    return 0;
}

// Yes/No dialogs whose children we already dumped.
#define HANDLED_MAX 32
static HWND g_handled[HANDLED_MAX];
static int  g_handledN;
static int handled(HWND h) {
    int i;
    for (i = 0; i < g_handledN; i++) if (g_handled[i] == h) return 1;
    if (g_handledN < HANDLED_MAX) g_handled[g_handledN++] = h;
    return 0;
}

static BOOL CALLBACK childProc(HWND h, LPARAM lp) {
    char cls[128], txt[256];
    int id = GetDlgCtrlID(h);
    (void)lp;
    get_class(h, cls, sizeof cls);
    get_text(h, txt, sizeof txt);
    printf("      child hwnd=%p id=%d class=%-16s vis=%d text=\"%s\"\n",
           (void*)h, id, cls, IsWindowVisible(h) ? 1 : 0, txt);
    return TRUE;
}

static void try_click(HWND dlg) {
    HWND yes = GetDlgItem(dlg, IDYES_BTN);
    HWND no  = GetDlgItem(dlg, IDNO_BTN);
    printf("    click: IDYES(6)=%p IDNO(7)=%p\n", (void*)yes, (void*)no);
    if (!yes) { printf("    click: no control id 6, not clicking\n"); return; }
    if (g_noclick) { printf("    click: --noclick, leaving it up\n"); return; }

    // Rung 1: post BM_CLICK to the button (cross-thread safe, never blocks us).
    PostMessageW(yes, BM_CLICK, 0, 0);
    printf("    click: posted BM_CLICK to %p\n", (void*)yes);
    Sleep(400);
    if (!IsWindow(dlg)) { printf("    click: RUNG1 post BM_CLICK worked\n"); InterlockedIncrement(&g_clicked); return; }

    // Rung 2: WM_COMMAND straight at the dialog, as if the button notified it.
    PostMessageW(dlg, WM_COMMAND, MAKEWPARAM(IDYES_BTN, BN_CLICKED), (LPARAM)yes);
    printf("    click: posted WM_COMMAND IDYES to dialog\n");
    Sleep(400);
    if (!IsWindow(dlg)) { printf("    click: RUNG2 WM_COMMAND worked\n"); InterlockedIncrement(&g_clicked); return; }

    // Rung 3: blocking send. Last resort; can stall this thread, not the game's.
    SendMessageW(yes, BM_CLICK, 0, 0);
    Sleep(400);
    if (!IsWindow(dlg)) { printf("    click: RUNG3 send BM_CLICK worked\n"); InterlockedIncrement(&g_clicked); return; }

    printf("    click: all three rungs failed, dialog still up\n");
    (void)no;
}

static BOOL CALLBACK enumProc(HWND h, LPARAM lp) {
    char cls[128], txt[256];
    DWORD pid = 0;
    int fresh;
    (void)lp;
    GetWindowThreadProcessId(h, &pid);
    get_class(h, cls, sizeof cls);
    get_text(h, txt, sizeof txt);
    fresh = !seen(h);
    if (fresh)
        printf("  win hwnd=%p pid=%lu%s class=%-20s vis=%d title=\"%s\"\n",
               (void*)h, pid, pid == g_selfPid ? "(SELF)" : "", cls,
               IsWindowVisible(h) ? 1 : 0, txt);

    // Candidate: a visible Yes/No dialog. Ours, or a broker's - the measurement
    // prints the pid either way.
    if (IsWindowVisible(h) && GetDlgItem(h, IDYES_BTN) && GetDlgItem(h, IDNO_BTN)) {
        int firstTime = !handled(h);
        printf("    ^^ Yes/No dialog candidate (pid=%lu)\n", pid);
        if (firstTime) EnumChildWindows(h, childProc, 0);
        if (!g_clicked) try_click(h);
    }
    return TRUE;
}

static DWORD WINAPI watcher(void *p) {
    int polls = 0;
    (void)p;
    // Ends when the add call returns (g_stop) or a click landed. The dialog can
    // take a second to appear, so never stop early on a poll count.
    while (!g_stop && !g_clicked && polls < 400) {   // 400 * 100 ms = 40 s ceiling
        Sleep(100);
        polls++;
        if (polls <= 3 || polls % 10 == 0) printf("--- poll %d (t=%d ms) ---\n", polls, polls * 100);
        EnumWindows(enumProc, 0);
    }
    printf("--- watcher out after %d polls, clicked=%ld ---\n", polls, (long)g_clicked);
    return 0;
}

static int root_has_cert(void) {
    HCERTSTORE st = CertOpenSystemStoreW(0, L"Root");
    PCCERT_CONTEXT pc = NULL;
    int found = 0;
    if (!st) return -1;
    while ((pc = CertEnumCertificatesInStore(st, pc)) != NULL) {
        if (pc->cbCertEncoded == g_cert->cbCertEncoded &&
            !memcmp(pc->pbCertEncoded, g_cert->pbCertEncoded, pc->cbCertEncoded)) { found = 1; break; }
    }
    if (pc) CertFreeCertificateContext(pc);
    CertCloseStore(st, 0);
    return found;
}

int main(int argc, char **argv) {
    const char *certPath = "cert.der";
    HANDLE hThread;
    HCERTSTORE hRoot;
    BOOL addOk;
    DWORD gle;
    int i, before, after;
    BYTE *der;
    DWORD derLen = 0;
    FILE *f;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--noclick")) g_noclick = 1;
        else if (!strcmp(argv[i], "--cert") && i + 1 < argc) certPath = argv[++i];
    }
    g_selfPid = GetCurrentProcessId();
    SetConsoleOutputCP(CP_UTF8);

    f = fopen(certPath, "rb");
    if (!f) { printf("FAIL: cannot open %s\n", certPath); return 2; }
    fseek(f, 0, SEEK_END); derLen = (DWORD)ftell(f); fseek(f, 0, SEEK_SET);
    der = (BYTE*)malloc(derLen);
    if (!der || fread(der, 1, derLen, f) != derLen) { printf("FAIL: read %s\n", certPath); return 2; }
    fclose(f);
    g_cert = CertCreateCertificateContext(X509_ASN_ENCODING, der, derLen);
    if (!g_cert) { printf("FAIL: CertCreateCertificateContext gle=%lu\n", GetLastError()); return 2; }
    printf("cert: %s loaded der=%lu bytes\n", certPath, derLen);

    // The dialog only appears when the cert is NOT already trusted, so start clean.
    before = root_has_cert();
    printf("root: cert present before = %d\n", before);
    if (before == 1) {
        HCERTSTORE st = CertOpenSystemStoreW(0, L"Root");
        PCCERT_CONTEXT pc = NULL;
        while ((pc = CertEnumCertificatesInStore(st, pc)) != NULL) {
            if (pc->cbCertEncoded == g_cert->cbCertEncoded &&
                !memcmp(pc->pbCertEncoded, g_cert->pbCertEncoded, pc->cbCertEncoded)) {
                PCCERT_CONTEXT dup = CertDuplicateCertificateContext(pc);
                CertDeleteCertificateFromStore(dup);   // delete frees the dup
                CertFreeCertificateContext(pc);
                pc = NULL;
                printf("root: deleted the pre-existing copy so the dialog will fire\n");
                break;
            }
        }
        if (pc) CertFreeCertificateContext(pc);
        CertCloseStore(st, 0);
        before = root_has_cert();
        printf("root: cert present after delete = %d\n", before);
    }

    hRoot = CertOpenSystemStoreW(0, L"Root");
    if (!hRoot) { printf("FAIL: cannot open Root store gle=%lu\n", GetLastError()); return 2; }

    hThread = CreateThread(NULL, 0, watcher, NULL, 0, NULL);
    printf("=== calling CertAddCertificateContextToStore (this is what pops the dialog) ===\n");
    addOk = CertAddCertificateContextToStore(hRoot, g_cert, CERT_STORE_ADD_NEW, NULL);
    gle = GetLastError();
    InterlockedIncrement(&g_stop);
    if (hThread) { WaitForSingleObject(hThread, 3000); CloseHandle(hThread); }

    printf("=== add returned %d gle=%lu (0x%08lx) ===\n", addOk ? 1 : 0, gle, gle);
    after = root_has_cert();
    printf("root: cert present after add = %d\n", after);
    printf("click: dialog was auto-clicked = %ld time(s)\n", (long)g_clicked);
    printf(after == 1 ? "RESULT: PASS - root trusted, no human needed\n"
                      : "RESULT: FAIL - root not trusted\n");

    // leave the machine as we found it: drop our root so the next run prompts too
    if (after == 1) {
        HCERTSTORE st = CertOpenSystemStoreW(0, L"Root");
        PCCERT_CONTEXT pc = NULL;
        while ((pc = CertEnumCertificatesInStore(st, pc)) != NULL) {
            if (pc->cbCertEncoded == g_cert->cbCertEncoded &&
                !memcmp(pc->pbCertEncoded, g_cert->pbCertEncoded, pc->cbCertEncoded)) {
                PCCERT_CONTEXT dup = CertDuplicateCertificateContext(pc);
                CertDeleteCertificateFromStore(dup);
                CertFreeCertificateContext(pc);
                break;
            }
        }
        if (pc) CertFreeCertificateContext(pc);
        CertCloseStore(st, 0);
        printf("cleanup: our root removed again (present now = %d)\n", root_has_cert());
    }
    CertCloseStore(hRoot, 0);
    return after == 1 ? 0 : 1;
}
