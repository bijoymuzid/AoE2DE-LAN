// srvtest.c — offline validation of the H1 login server (session 12).
// Starts loginsrv (TLS on 127.0.0.1:443) and idles so a Python ssl client
// can exercise handshake + HTTP + JSON. Checks:
//   C:/Python314/python.exe -X utf8 srvclient.py
// Never touches the game.
#include <windows.h>
#include <stdio.h>
#include "hookcore.h"
#include "loginsrv.h"

// hookcore references the hook table; srvtest never installs detours
HOOKDEF g_Hooks[1] = { {"dummy", 0, 0, 0, 0, 0} };
const int g_NHooks = 0;

int main(int argc, char **argv) {
    int secs = 60;
    HANDLE hLog = CreateFileW(L"srvtest.log", GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hc_set_log(hLog, GetTickCount());
    log_line("srvtest: start");
    if (argc > 1) secs = atoi(argv[1]);
    if (!loginsrv_start()) {
        printf("FAIL: loginsrv_start\n");
        return 1;
    }
    printf("login server live on https://127.0.0.1:443/ — idling %ds\n", secs);
    for (int i = 0; i < secs; i++) {
        Sleep(1000);
        // s45: offline there is no hook 13, so nothing would ever increment
        // g_ParseFail and the shim's payload ladder would grade variant 0 as
        // "parsed" and stop after one push. Simulate the failure the game's WS
        // notification parser reports, so srvclient can watch the ladder escalate
        // through all three variants and then terminate.
        InterlockedIncrement(&g_ParseFail);
    }
    printf("srvtest done\n");
    log_line("srvtest: done");
    CloseHandle(hLog);
    return 0;
}
