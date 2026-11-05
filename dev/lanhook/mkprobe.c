// mkprobe.c — time the CU Root store add in isolation (unbuffered).
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("t0 start\n");
    HCRYPTPROV pv = 0; HCRYPTKEY ky = 0;
    char cont[48]; sprintf_s(cont, sizeof cont, "probe-%lu", GetTickCount());
    CryptAcquireContextA(&pv, cont, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT);
    CryptGenKey(pv, AT_SIGNATURE, 2048 << 16 | CRYPT_EXPORTABLE, &ky);
    CERT_NAME_BLOB sb = {0}; DWORD dn = 512;
    sb.pbData = (BYTE*)LocalAlloc(0, 512);
    LPCWSTR pe = NULL;
    CertStrToNameW(X509_ASN_ENCODING, L"CN=probe-x, O=t", CERT_X500_NAME_STR, NULL, sb.pbData, &dn, &pe);
    sb.cbData = dn;
    WCHAR wc[48]; size_t wl = 0; while (cont[wl]) { wc[wl] = (WCHAR)cont[wl]; wl++; } wc[wl] = 0;
    CRYPT_KEY_PROV_INFO kpi; ZeroMemory(&kpi, sizeof kpi);
    kpi.pwszContainerName = wc; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_SIGNATURE;
    SYSTEMTIME et; GetSystemTime(&et); et.wYear += 1;
    PCCERT_CONTEXT cx = CertCreateSelfSignCertificate((ULONG_PTR)pv, &sb, 0, &kpi, NULL, NULL, &et, NULL);
    printf("t1 cssc ctx=%p gle=%lu\n", (void*)cx, cx ? 0 : GetLastError());
    HCERTSTORE h = CertOpenSystemStoreW(0, L"Root");
    printf("t2 open store=%p gle=%lu\n", (void*)h, h ? 0 : GetLastError());
    DWORD t0 = GetTickCount();
    BOOL a = CertAddCertificateContextToStore(h, cx, CERT_STORE_ADD_NEW, NULL);
    printf("t3 add=%d after %lums gle=%lu\n", a, GetTickCount()-t0, a ? 0 : GetLastError());
    CertCloseStore(h, 0);
    CertFreeCertificateContext(cx);
    printf("t4 done\n");
    return 0;
}
