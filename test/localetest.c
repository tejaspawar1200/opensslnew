
#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include "testutil.h"
#include "testutil/output.h"

#include <stdlib.h>
#include <locale.h>
#ifdef OPENSSL_SYS_WINDOWS
# define strcasecmp _stricmp
#else
# include <strings.h>
#endif

int setup_tests(void)
{
  const unsigned char der_bytes[] = {
  0x30, 0x82, 0x03, 0x09, 0x30, 0x82, 0x01, 0xf1, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x08, 0xe0, 0x8c, 0xd3, 0xf3, 0xbf, 0x2c, 0xf2, 0x0d,
  0x0a, 0x75, 0xd1, 0xe8, 0xea, 0xbe, 0x70, 0x61, 0xd9, 0x67, 0xf9, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
  0x05, 0x00, 0x30, 0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
  0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
  0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x34, 0x31, 0x31, 0x31, 0x34,
  0x31, 0x39, 0x35, 0x37, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x35, 0x31,
  0x31, 0x31, 0x34, 0x31, 0x39, 0x35, 0x37, 0x5a, 0x30, 0x14, 0x31, 0x12,
  0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x6c, 0x6f, 0x63,
  0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
  0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
  0x01, 0x01, 0x00, 0xc3, 0x1f, 0x5c, 0x56, 0x46, 0x8d, 0x69, 0xb6, 0x48,
  0x3c, 0xbf, 0xe2, 0x0f, 0xa7, 0x4a, 0x44, 0x72, 0x74, 0x36, 0xfe, 0xe8,
  0x2f, 0x10, 0x4a, 0xe9, 0x46, 0x45, 0x72, 0x5e, 0x48, 0xdd, 0x75, 0xab,
  0xd9, 0x63, 0x91, 0x37, 0x93, 0x46, 0x28, 0x7e, 0x45, 0x94, 0x4b, 0x8a,
  0xd5, 0x05, 0x2b, 0x9a, 0x01, 0x96, 0x30, 0xde, 0xcc, 0x14, 0x2d, 0x06,
  0x09, 0x1b, 0x7d, 0x50, 0x14, 0x99, 0x36, 0x6b, 0x97, 0x6e, 0xc9, 0xb1,
  0x69, 0x70, 0xcd, 0x9b, 0x74, 0x24, 0x9a, 0xe2, 0xd4, 0xc0, 0x1e, 0xbc,
  0xec, 0xf6, 0x7a, 0xbb, 0xa0, 0x53, 0x93, 0xf8, 0x68, 0x9a, 0x18, 0xa1,
  0xa1, 0x5c, 0x47, 0x93, 0xd1, 0x4c, 0x36, 0x8c, 0x00, 0xb3, 0x66, 0xda,
  0xf1, 0x05, 0xb2, 0x3a, 0xad, 0x7e, 0x4b, 0xf3, 0xd3, 0x93, 0xfa, 0x59,
  0x09, 0x9c, 0x60, 0x37, 0x69, 0x61, 0xe8, 0x5a, 0x33, 0xc6, 0xb2, 0x1a,
  0xba, 0x36, 0xe2, 0xb3, 0x58, 0xe9, 0x73, 0x01, 0x2d, 0x36, 0x48, 0x36,
  0x94, 0xe4, 0xb2, 0xa4, 0x5b, 0xdf, 0x3d, 0x5f, 0x62, 0x9f, 0xd9, 0xf3,
  0x24, 0x0c, 0xf0, 0x2f, 0x71, 0x44, 0x79, 0x13, 0x70, 0x95, 0xa7, 0xbe,
  0xea, 0x0a, 0x08, 0x0a, 0xa6, 0x4b, 0xe9, 0x58, 0x6b, 0xa4, 0xc2, 0xed,
  0x74, 0x1e, 0xb0, 0x3b, 0x59, 0xd5, 0xe6, 0xdb, 0x8f, 0x58, 0x6a, 0xa3,
  0x7d, 0x52, 0x40, 0xec, 0x72, 0xb7, 0xba, 0x7e, 0x30, 0x9d, 0x12, 0x57,
  0xf2, 0x48, 0xae, 0x80, 0x0d, 0x0a, 0xf4, 0xfd, 0x24, 0xed, 0xd8, 0x05,
  0xb2, 0x96, 0x44, 0x02, 0x3e, 0x6e, 0x25, 0xb0, 0xc4, 0x93, 0xda, 0xfe,
  0x78, 0xd9, 0xbb, 0xd2, 0x71, 0x69, 0x70, 0x7f, 0xba, 0xf7, 0xb0, 0x4f,
  0x14, 0xf7, 0x98, 0x71, 0x01, 0x6c, 0xec, 0x6f, 0x76, 0x03, 0x59, 0xff,
  0xe2, 0xba, 0x8d, 0xd9, 0x21, 0x08, 0xb3, 0x02, 0x03, 0x01, 0x00, 0x01,
  0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
  0x16, 0x04, 0x14, 0x59, 0xb8, 0x6e, 0x1a, 0x72, 0xe9, 0x27, 0x1e, 0xbf,
  0x80, 0x87, 0x0f, 0xa9, 0xd0, 0x06, 0x6a, 0x11, 0x30, 0x77, 0x8e, 0x30,
  0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
  0x59, 0xb8, 0x6e, 0x1a, 0x72, 0xe9, 0x27, 0x1e, 0xbf, 0x80, 0x87, 0x0f,
  0xa9, 0xd0, 0x06, 0x6a, 0x11, 0x30, 0x77, 0x8e, 0x30, 0x0f, 0x06, 0x03,
  0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
  0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
  0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x98, 0x76, 0x9e,
  0x3c, 0xfc, 0x3f, 0x58, 0xe8, 0xf2, 0x1f, 0x2e, 0x11, 0xa2, 0x59, 0xfa,
  0x27, 0xb5, 0xec, 0x9d, 0x97, 0x05, 0x06, 0x2c, 0x95, 0xa5, 0x28, 0x88,
  0x86, 0xeb, 0x4e, 0x8a, 0x62, 0xe9, 0x87, 0x78, 0xd8, 0x18, 0x22, 0x4e,
  0xb1, 0x8d, 0x46, 0x4a, 0x4c, 0x6e, 0x7c, 0x53, 0x62, 0x2c, 0xf2, 0x7a,
  0x95, 0xa0, 0x1a, 0x30, 0x18, 0x6a, 0x31, 0x6f, 0x3f, 0x55, 0x25, 0x9f,
  0x67, 0x60, 0x68, 0x99, 0x0f, 0x41, 0x09, 0xc8, 0xe2, 0x04, 0x33, 0x22,
  0x1a, 0xe9, 0xf3, 0xae, 0xce, 0xb6, 0x83, 0x64, 0x78, 0x66, 0x14, 0xc9,
  0x54, 0xc8, 0x34, 0x70, 0x96, 0xaf, 0x16, 0xcd, 0xb8, 0xdf, 0x81, 0x7e,
  0xf0, 0xa6, 0x7d, 0xc1, 0x13, 0xb2, 0x76, 0x3a, 0xd5, 0x7e, 0x68, 0x8c,
  0xd5, 0x00, 0x70, 0x82, 0x23, 0x7e, 0x5e, 0xc9, 0x31, 0x2f, 0x33, 0x54,
  0xaa, 0xaf, 0xcd, 0xe9, 0x38, 0x9a, 0x23, 0x53, 0xad, 0x4e, 0x72, 0xa7,
  0x6f, 0x47, 0x60, 0xc9, 0xd3, 0x06, 0x9b, 0x7a, 0x21, 0xc6, 0xe9, 0xdb,
  0x3c, 0xaa, 0xc0, 0x21, 0x29, 0x5f, 0x44, 0x6a, 0x45, 0x90, 0x73, 0x5e,
  0x6d, 0x78, 0x82, 0xcb, 0x42, 0xe6, 0xba, 0x67, 0xb2, 0xe6, 0xa2, 0x15,
  0x04, 0xea, 0x69, 0xae, 0x3e, 0xc0, 0x0c, 0x10, 0x99, 0xec, 0xa9, 0xb0,
  0x7e, 0xe8, 0x94, 0xe2, 0xf3, 0xaf, 0xf7, 0x9f, 0x65, 0xe7, 0xd7, 0xe2,
  0x49, 0xfa, 0x52, 0x7d, 0xb5, 0xfd, 0xa0, 0xa5, 0xe0, 0x49, 0xa7, 0x3d,
  0x94, 0x20, 0x2d, 0xec, 0x8c, 0x22, 0xa5, 0xa4, 0x43, 0xfa, 0x7e, 0xd0,
  0x50, 0x21, 0xb8, 0x67, 0x18, 0x44, 0x69, 0x8f, 0xdd, 0x47, 0x41, 0xc6,
  0x35, 0xe0, 0xe9, 0x2e, 0x41, 0xa9, 0x6f, 0x41, 0xee, 0xb9, 0xbd, 0x45,
  0xf3, 0x88, 0xc1, 0x23, 0x35, 0x96, 0xba, 0xf8, 0xcd, 0x4b, 0x83, 0x73,
  0x5f
};

    char str1[] = "SubjectPublicKeyInfo", str2[] = "subjectpublickeyinfo";
    int res;
    X509 *cert = NULL;
    X509_PUBKEY *cert_pubkey = NULL;
    const unsigned char *p = der_bytes;

    TEST_ptr(setlocale(LC_ALL, ""));

    res = strcasecmp(str1, str2);
    TEST_note("Case-insensitive comparison via strcasecmp in current locale %s\n", res ? "failed" : "succeeded");

    TEST_false(OPENSSL_strcasecmp(str1, str2));

    cert = d2i_X509(NULL, &p, sizeof(der_bytes));
    if (!TEST_ptr(cert))
        return 0;

    cert_pubkey = X509_get_X509_PUBKEY(cert);
    if (!TEST_ptr(cert_pubkey)) {
        X509_free(cert);
        return 0;
    }

    if (!TEST_ptr(X509_PUBKEY_get0(cert_pubkey))) {
        X509_free(cert);
        return 0;
    }

    X509_free(cert);
    return 1;
}

void cleanup_tests(void)
{
}
