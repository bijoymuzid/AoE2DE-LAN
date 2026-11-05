// certext.c — empirical ground truth for CertCreateSelfSignCertificate's
// pExtensions contract + a dump helper (rebuilt session 14 after a bad
// scripted edit truncated it; the F case = full ageLANServer cert shape).
// Build: mkce.cmd (cl + crypt32.lib advapi32.lib)
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")

static const WCHAR HOSTW[] = L"pb-live-release6-api.worldsedgelink.com";
static const char  HOSTA[] =  "pb-live-release6-api.worldsedgelink.com";

static void dump(PCCERT_CONTEXT ctx, const char *tag) {
    char fn[64]; sprintf_s(fn, sizeof fn, "certext-%s.der", tag);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(ctx->pbCertEncoded, ctx->cbCertEncoded, 1, f); fclose(f); }
    printf("%s: ctx=%p der=%lu -> %s\n", tag, (void*)ctx, ctx->cbCertEncoded, fn);
    printf("  exts=%lu", ctx->pCertInfo->cExtension);
    for (DWORD i = 0; i < ctx->pCertInfo->cExtension; i++)
        printf(" [%s]", ctx->pCertInfo->rgExtension[i].pszObjId);
    printf("\n");
    PCERT_EXTENSION e = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
        ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (e) {
        CERT_ALT_NAME_INFO *ai = NULL; DWORD sz = 0;
        if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
            e->Value.pbData, e->Value.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &ai, &sz)) {
            for (DWORD j = 0; j < ai->cAltEntry; j++)
                if (ai->rgAltEntry[j].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME)
                    printf("  SAN dNSName: %ls\n", ai->rgAltEntry[j].pwszDNSName);
            LocalFree(ai);
        } else printf("  SAN decode failed gle=%lu\n", GetLastError());
    } else printf("  (no SAN)\n");
}

static void run(const char *tag, CERT_EXTENSIONS *exts) {
    HCRYPTPROV prov = 0; HCRYPTKEY key = 0;
    char cont[48]; sprintf_s(cont, sizeof cont, "certext-%s-%lu", tag, GetTickCount());
    if (!CryptAcquireContextA(&prov, cont, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT))
        printf("%s: CAC failed gle=%lu\n", tag, GetLastError());
    if (!CryptGenKey(prov, AT_SIGNATURE, 2048 << 16 | CRYPT_EXPORTABLE, &key))
        printf("%s: GenKey failed gle=%lu\n", tag, GetLastError());
    CERT_NAME_BLOB subj = {0};
    DWORD dn = 512;
    LPCWSTR perr = NULL;
    subj.pbData = (BYTE*)LocalAlloc(0, 512);
    CertStrToNameW(X509_ASN_ENCODING,
        L"CN=pb-live-release6-api.worldsedgelink.com, O=AoE2LAN",
        CERT_X500_NAME_STR, NULL, subj.pbData, &dn, &perr);
    subj.cbData = dn;
    WCHAR wc[48]; size_t wl = 0; while (cont[wl]) { wc[wl] = (WCHAR)cont[wl]; wl++; } wc[wl] = 0;
    CRYPT_KEY_PROV_INFO kpi; ZeroMemory(&kpi, sizeof kpi);
    kpi.pwszContainerName = wc; kpi.dwProvType = PROV_RSA_AES; kpi.dwKeySpec = AT_SIGNATURE;
    SYSTEMTIME et; GetSystemTime(&et); et.wYear += 1;   // ageLANServer uses 1y
    CRYPT_ALGORITHM_IDENTIFIER sigAlg; ZeroMemory(&sigAlg, sizeof sigAlg);
    sigAlg.pszObjId = szOID_RSA_SHA256RSA;
    __try {
        PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate((ULONG_PTR)prov, &subj, 0, &kpi, &sigAlg, NULL, &et, exts);
        if (!ctx) printf("%s: CSSC FAILED gle=0x%lX\n", tag, GetLastError());
        else { dump(ctx, tag); CertFreeCertificateContext(ctx); }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("%s: CSSC AV (code 0x%lX)\n", tag, GetExceptionCode());
    }
    LocalFree(subj.pbData);
    CryptReleaseContext(prov, 0);
}

void dump_san_der(void) {
    CERT_ALT_NAME_ENTRY ent; ZeroMemory(&ent, sizeof ent);
    ent.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; ent.pwszDNSName = (LPWSTR)HOSTW;
    CERT_ALT_NAME_INFO ai; ai.cAltEntry = 1; ai.rgAltEntry = &ent;
    CRYPT_DATA_BLOB der = {0};
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &ai,
        CRYPT_ENCODE_ALLOC_FLAG, NULL, &der.pbData, &der.cbData)) {
        printf("SAN inner DER (%luB): ", der.cbData);
        for (DWORD i = 0; i < der.cbData; i++) printf("%02X", der.pbData[i]);
        printf("\n");
        LocalFree(der.pbData);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'd') { dump_san_der(); return 0; }

    // case C: pre-encoded SAN via CryptEncodeObjectEx (the pattern that works)
    CERT_ALT_NAME_ENTRY ent; ZeroMemory(&ent, sizeof ent);
    ent.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; ent.pwszDNSName = (LPWSTR)HOSTW;
    CERT_ALT_NAME_INFO ai; ai.cAltEntry = 1; ai.rgAltEntry = &ent;
    CRYPT_DATA_BLOB der = {0};
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &ai,
        CRYPT_ENCODE_ALLOC_FLAG, NULL, &der.pbData, &der.cbData)) {
        CERT_EXTENSION eC; ZeroMemory(&eC, sizeof eC);
        eC.pszObjId = szOID_SUBJECT_ALT_NAME2; eC.fCritical = FALSE;
        eC.Value = der;
        CERT_EXTENSIONS xC = { 1, &eC };
        run("C-encoded", &xC);
        LocalFree(der.pbData);
    } else printf("encode failed gle=%lu\n", GetLastError());

    printf("== F: full ageLANServer shape (KU crit DS+KE+KC, EKU srv+cli, BC crit CA pathlen:0, SAN 3 entries) ==\n");
    {
        CRYPT_DATA_BLOB sanDer3 = {0, 0};
        CERT_ALT_NAME_ENTRY sanE[3];
        static const WCHAR W1[] = L"pb-live-release6-api.worldsedgelink.com";
        static const WCHAR W2[] = L"*.worldsedgelink.com";
        static const WCHAR W3[] = L"aoe-api.reliclink.com";
        ZeroMemory(sanE, sizeof sanE);
        sanE[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; sanE[0].pwszDNSName = (LPWSTR)W1;
        sanE[1].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; sanE[1].pwszDNSName = (LPWSTR)W2;
        sanE[2].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME; sanE[2].pwszDNSName = (LPWSTR)W3;
        CERT_ALT_NAME_INFO ai3; ai3.cAltEntry = 3; ai3.rgAltEntry = sanE;
        if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &ai3,
            CRYPT_ENCODE_ALLOC_FLAG, NULL, &sanDer3.pbData, &sanDer3.cbData)) {
            static const BYTE KU_DER[] = {0x03,0x02,0x02,0xA4};
            static const BYTE EKU_DER[] = {0x30,0x14,
                0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01,
                0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02};
            static const BYTE BC_DER[] = {0x30,0x06,0x01,0x01,0xFF,0x02,0x01,0x00};
            CERT_EXTENSION extF[4];
            ZeroMemory(extF, sizeof extF);
            extF[0].pszObjId = szOID_KEY_USAGE;          extF[0].fCritical = TRUE;
            extF[0].Value.cbData = sizeof KU_DER;  extF[0].Value.pbData = (BYTE*)KU_DER;
            extF[1].pszObjId = szOID_ENHANCED_KEY_USAGE; extF[1].fCritical = FALSE;
            extF[1].Value.cbData = sizeof EKU_DER; extF[1].Value.pbData = (BYTE*)EKU_DER;
            extF[2].pszObjId = szOID_BASIC_CONSTRAINTS2; extF[2].fCritical = TRUE;
            extF[2].Value.cbData = sizeof BC_DER;  extF[2].Value.pbData = (BYTE*)BC_DER;
            extF[3].pszObjId = szOID_SUBJECT_ALT_NAME2;  extF[3].fCritical = FALSE;
            extF[3].Value = sanDer3;
            CERT_EXTENSIONS xF = { 4, extF };
            run("F-fullshape", &xF);
            LocalFree(sanDer3.pbData);
        }
    }
    return 0;
}
