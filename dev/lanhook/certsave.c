// certsave.c — offline probe (host tool, never loaded by the game).
//
// Question: can we produce the byte format the CURRENT USER Root store persists at
// HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\<THUMBPRINT>\Blob
// without calling CertAddCertificateContextToStore (which pops the Windows consent
// dialog)? A real Blob starts 5C 00 00 00 01 00 00 00 04 00 00 00 ... and holds
// {propId,flags,size,data} records ending with the raw DER cert, so it is crypt32's
// serialized-context format, not PKCS#7. This prints what CertSaveStore yields for
// every plausible encoding combo, plus what the real Root store yields, so the
// formats can be compared directly. Writes nothing.
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "crypt32.lib")

static void hex(const unsigned char *p, unsigned n) {
    for (unsigned i = 0; i < n; i++) printf("%02X", p[i]);
}

static void try_save(const char *tag, HCERTSTORE st, DWORD enc) {
    CRYPT_DATA_BLOB b;
    BOOL r;
    memset(&b, 0, sizeof b);
    r = CertSaveStore(st, enc, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    printf("%-22s enc=%08X sizing r=%d gle=%lu cb=%lu\n", tag, enc, r,
           GetLastError(), b.cbData);
    if (!b.cbData) return;
    b.pbData = (unsigned char *)malloc(b.cbData);
    if (!b.pbData) return;
    r = CertSaveStore(st, enc, CERT_STORE_SAVE_TO_MEMORY, &b, 0);
    printf("%-22s   fill r=%d gle=%lu cb=%lu first32=", tag, r, GetLastError(),
           b.cbData);
    hex(b.pbData, b.cbData < 32 ? b.cbData : 32);
    printf("\n");
    free(b.pbData);
}

int main(int argc, char **argv) {
    const char *derPath = argc > 1 ? argv[1] : "cert.der";
    FILE *f = fopen(derPath, "rb");
    unsigned char *der;
    long n;
    PCCERT_CONTEXT c;
    HCERTSTORE mem;
    DWORD combos[] = { X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                       X509_ASN_ENCODING,
                       PKCS_7_ASN_ENCODING,
                       CRYPT_ASN_ENCODING | PKCS_7_ASN_ENCODING };
    if (!f) { printf("FAIL: cannot open %s\n", derPath); return 1; }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    der = (unsigned char *)malloc((size_t)n);
    if (!der || fread(der, 1, (size_t)n, f) != (size_t)n) { printf("FAIL: read\n"); return 1; }
    fclose(f);
    printf("cert %s: %ld bytes, sha1-prop below\n", derPath, n);

    c = CertCreateCertificateContext(X509_ASN_ENCODING, der, (DWORD)n);
    if (!c) { printf("FAIL: CertCreateCertificateContext gle=%lu\n", GetLastError()); return 1; }
    { unsigned char th[24]; DWORD tl = sizeof th;
      if (CertGetCertificateContextProperty(c, CERT_SHA1_HASH_PROP_ID, th, &tl)) {
          printf("thumbprint(%lu)=", tl); hex(th, tl); printf("\n"); }
      else printf("thumbprint FAILED gle=%lu\n", GetLastError()); }

    for (int i = 0; i < 4; i++) {
        mem = CertOpenStore(CERT_STORE_PROV_MEMORY, combos[i], 0, 0, NULL);
        if (!mem) { printf("mem store open failed enc=%08X gle=%lu\n", combos[i], GetLastError()); continue; }
        if (!CertAddCertificateContextToStore(mem, c, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
            printf("  add-to-memory failed gle=%lu\n", GetLastError());
        try_save("memory-store", mem, combos[i]);
        // also try saving with the fixed X509|PKCS7 encoding regardless of the
        // store's own encoding type
        if (combos[i] != (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING))
            try_save("memory-store fixed", mem, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
        CertCloseStore(mem, 0);
    }

    { // the real CURRENT USER Root store: what does saving IT look like?
      HCERTSTORE root = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                      CERT_SYSTEM_STORE_CURRENT_USER, L"Root");
      if (!root) printf("root open failed gle=%lu\n", GetLastError());
      else {
          try_save("real-user-Root", root, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING);
          CertCloseStore(root, 0);
      } }
    CertFreeCertificateContext(c);
    free(der);
    return 0;
}
