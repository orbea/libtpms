/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

int main(void)
{
    TPM_RESULT res;
    char *profile;
    int ret = 1;

    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (res) {
        fprintf(stderr, "TPMLIB_ChooseTPMVersion() failed: 0x%02x\n", res);
        goto exit;
    }

    res = TPMLIB_SetProfile(NULL);
    if (res) {
        fprintf(stderr, "TPMLIB_SetProfile() failed: 0x%02x\n", res);
        goto exit;
    }

    res = TPMLIB_MainInit();
    if (res) {
        fprintf(stderr, "TPMLIB_MainInit() failed: 0x%02x\n", res);
        goto exit;
    }

    /*
     * The stateFormatLevel will have to be adapted when the default profile
     * implements a later version of the state format.
     */
    const char *exp_profile =
        "{\"ActiveProfile\":{"
          "\"name\":\"default\","
          "\"stateFormatLevel\":1,"
          "\"commands\":\"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,"
                         "0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,"
                         "0x17a-0x193,0x197\","
          "\"algorithms\":\"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,"
                           "sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
                           "xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,"
                           "oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
                           "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,"
                           "symcipher,camellia,camellia-min-size=128,"
                           "cmac,ctr,ofb,cbc,cfb,ecb\""
        "}}";
    profile = TPMLIB_GetInfo(TPMLIB_INFO_ACTIVE_PROFILE);
    if (strcmp(profile, exp_profile)) {
        fprintf(stderr,
                "Active Profile is different than expected one.\n"
                "actual   : %s\n"
                "expected : %s\n",
                profile, exp_profile);
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}
