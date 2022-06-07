/********************************************************************************/
/*										*/
/*			 Algorithm Runtime Disablement 				*/
/*			     Written by Stefan Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2022					*/
/*										*/
/********************************************************************************/

#define _GNU_SOURCE
#include <assert.h>
#include <string.h>

#include "Tpm.h"
#include "NVMarshal.h"
#include "GpMacros.h"
#include "tpm_library_intern.h"

#define ALGO_SEPARATOR_C ','
#define ALGO_SEPARATOR_STR ","

struct KeySizes {
    BOOL enabled;
    UINT16 size;
};

static const struct KeySizes s_KeySizesAES[] = {
    { .enabled = AES_128, .size = 128 },
    { .enabled = AES_192, .size = 192 },
    { .enabled = AES_256, .size = 256 },
    { .enabled = false  , .size = 0 },
};
static const struct KeySizes s_KeySizesSM4[] = {
    { .enabled = SM4_128, .size = 128 },
    { .enabled = false  , .size = 0 },
};
static const struct KeySizes s_KeySizesCamellia[] = {
    { .enabled = CAMELLIA_128, .size = 128 },
    { .enabled = CAMELLIA_192, .size = 192 },
    { .enabled = CAMELLIA_256, .size = 256 },
    { .enabled = false       , .size = 0 },
};
static const struct KeySizes s_KeySizesTDES[] = {
    { .enabled = TDES_128, .size = 128 },
    { .enabled = TDES_192, .size = 192 },
    { .enabled = false   , .size = 0 },
};
static const struct KeySizes s_KeySizesRSA[] = {
    { .enabled = RSA_1024, .size = 1024 },
    { .enabled = RSA_2048, .size = 2048 },
    { .enabled = RSA_3072, .size = 3072 },
    { .enabled = RSA_4096, .size = 4096 },
    { .enabled = false   , .size = 0 },
};
static const struct KeySizes s_KeySizesECC[] = {
    { .enabled = ECC_NIST_P192, .size = 192 },
    { .enabled = ECC_NIST_P224, .size = 224 },
    { .enabled = ECC_NIST_P256, .size = 256 },
    { .enabled = ECC_BN_P256  , .size = 256 },
    { .enabled = ECC_SM2_P256 , .size = 256 },
    { .enabled = ECC_NIST_P384, .size = 384 },
    { .enabled = ECC_NIST_P521, .size = 521 },
    { .enabled = ECC_BN_P638  , .size = 638 },
    { .enabled = false        , .size = 0 },
};

static const struct {
    const char   *name;
    union {
	const struct KeySizes *keySizes;
    } u;
    BOOL          canBeDisabled;
} s_AlgorithmProperties[NUM_ENTRIES_ALGORITHM_PROPERTIES] = {
#define SYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE }
#define ASYMMETRIC(ENABLED, NAME, KEYSIZES, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .u.keySizes = KEYSIZES, .canBeDisabled = CANDISABLE }
#define HASH(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define SIGNING(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define ENCRYPTING(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }
#define OTHER(ENABLED, NAME, CANDISABLE) \
    { .name = ENABLED ? NAME : NULL, .canBeDisabled = CANDISABLE }

    [TPM_ALG_RSA] = ASYMMETRIC(ALG_RSA, "rsa", s_KeySizesRSA, false),
    [TPM_ALG_TDES] = SYMMETRIC(ALG_TDES, "tdes", s_KeySizesTDES, true),
    [TPM_ALG_SHA1] = HASH(ALG_SHA1, "sha1", true),
    [TPM_ALG_HMAC] = SIGNING(ALG_HMAC, "hmac", false),
    [TPM_ALG_AES] = SYMMETRIC(ALG_AES, "aes", s_KeySizesAES, false), // never disable: context encryption
    [TPM_ALG_MGF1] = HASH(ALG_MGF1, "mgf1", false),
    [TPM_ALG_KEYEDHASH] = HASH(ALG_KEYEDHASH, "keyedhash", false),
    [TPM_ALG_XOR] = OTHER(ALG_XOR, "xor", false),
    [TPM_ALG_SHA256] = HASH(ALG_SHA256, "sha256", false),
    [TPM_ALG_SHA384] = HASH(ALG_SHA384, "sha384", false),
    [TPM_ALG_SHA512] = HASH(ALG_SHA512, "sha512", true),
    [TPM_ALG_NULL] = OTHER(true, "null", false),
    [TPM_ALG_SM4] = SYMMETRIC(ALG_SM4, "sm4", s_KeySizesSM4, true),
    [TPM_ALG_RSASSA] = SIGNING(ALG_RSASSA, "rsassa", true),
    [TPM_ALG_RSAES] = ENCRYPTING(ALG_RSAES, "rsaes", true),
    [TPM_ALG_RSAPSS] = SIGNING(ALG_RSAPSS, "rsapss", true),
    [TPM_ALG_OAEP] = ENCRYPTING(ALG_OAEP, "oaep", false), // never disable: CryptSecretEncrypt/Decrypt needs it
    [TPM_ALG_ECDSA] = SIGNING(ALG_ECDSA, "ecdsa", false),
    [TPM_ALG_ECDH] = OTHER(ALG_ECDH, "ecdh", false),
    [TPM_ALG_ECDAA] = OTHER(ALG_ECDAA, "ecdaa", false),
    [TPM_ALG_SM2] = SIGNING(ALG_SM2, "sm2", false),
    [TPM_ALG_ECSCHNORR] = SIGNING(ALG_ECSCHNORR, "ecschnorr", false),
    [TPM_ALG_ECMQV] = OTHER(ALG_ECMQV, "ecmqv", true),
    [TPM_ALG_KDF1_SP800_56A] = HASH(ALG_KDF1_SP800_56A, "kdf1-sp800-56a", false),
    [TPM_ALG_KDF2] = HASH(ALG_KDF2, "kdf2", false),
    [TPM_ALG_KDF1_SP800_108] = HASH(ALG_KDF1_SP800_108, "kdf1-sp800-108", false),
    [TPM_ALG_ECC] = ASYMMETRIC(ALG_ECC, "ecc", s_KeySizesECC, false),
    [TPM_ALG_SYMCIPHER] = OTHER(ALG_SYMCIPHER, "symcipher", false),
    [TPM_ALG_CAMELLIA] = SYMMETRIC(ALG_CAMELLIA, "camellia", s_KeySizesCamellia, true),
    [TPM_ALG_SHA3_256] = HASH(ALG_SHA3_256, "sha3-256", false),
    [TPM_ALG_SHA3_384] = HASH(ALG_SHA3_384, "sha3-384", false),
    [TPM_ALG_SHA3_512] = HASH(ALG_SHA3_512, "sha3-256", false),
    [TPM_ALG_CMAC] = SIGNING(ALG_CMAC, "cmac", true),
    [TPM_ALG_CTR] = ENCRYPTING(ALG_CTR, "ctr", true),
    [TPM_ALG_OFB] = ENCRYPTING(ALG_OFB, "ofb", true),
    [TPM_ALG_CBC] = ENCRYPTING(ALG_CBC, "cbc", true),
    [TPM_ALG_CFB] = ENCRYPTING(ALG_CFB, "cfb", false), // never disable: context entryption
    [TPM_ALG_ECB] = ENCRYPTING(ALG_ECB, "ecb", true),
};

static const TPM_ALG_ID algsWithKeySizes[] = {
    TPM_ALG_RSA,
    TPM_ALG_TDES,
    TPM_ALG_AES,
    TPM_ALG_SM4,
    TPM_ALG_CAMELLIA,
};

static unsigned int
KeySizesGetMinimum(const struct KeySizes *ks)
{
    size_t i = 0;

    while (ks[i].size) {
	if (ks[i].enabled)
	    return ks[i].size;
	i++;
    }
    return 0;
}

static void
RuntimeAlgorithmEnableAllAlgorithms(
				    struct RuntimeAlgorithm *RuntimeAlgorithm
				    )
{
    TPM_ALG_ID algId;

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0 , sizeof(RuntimeAlgorithm->enabledAlgorithms));

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
    }
}

LIB_EXPORT void
RuntimeAlgorithmInit(
		     struct RuntimeAlgorithm *RuntimeAlgorithm
		     )
{
    TPM_ALG_ID algId;
    size_t i;

    MemorySet(RuntimeAlgorithm->algosMinimumKeySizes, 0 , sizeof(RuntimeAlgorithm->algosMinimumKeySizes));

    for (i = 0; i < ARRAY_SIZE(algsWithKeySizes); i++) {
	algId = algsWithKeySizes[i];
	assert(algId < ARRAY_SIZE(RuntimeAlgorithm->algosMinimumKeySizes));
	assert(s_AlgorithmProperties[algId].u.keySizes != NULL);
	RuntimeAlgorithm->algosMinimumKeySizes[algId] = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
    }
}

/* Set the default profile with all algorithms and all keysizes enabled */
static void
RuntimeAlgorithmSetDefault(
			   struct RuntimeAlgorithm *RuntimeAlgorithm
			   )
{
    free(RuntimeAlgorithm->algorithmProfile);
    RuntimeAlgorithm->algorithmProfile = NULL;
    RuntimeAlgorithmInit(RuntimeAlgorithm);
    RuntimeAlgorithmEnableAllAlgorithms(RuntimeAlgorithm);
}

/* Set the given profile and runtime-enable the given algorithms. A NULL pointer
 * for the profile parameter sets the default profile which enables all algorithms
 * and all key sizes without any restrictions.
 */
LIB_EXPORT TPM_RC
RuntimeAlgorithmSetProfile(
			   struct RuntimeAlgorithm  *RuntimeAlgorithm,
			   const char		    *newProfile  // IN: colon-separated list of algorithm names
			   )
{
    TPM_RC retVal = TPM_RC_SUCCESS;
    unsigned long minKeySize;
    const char *token, *comma;
    size_t toklen, cmplen;
    TPM_ALG_ID algId;
    char *endptr;
    bool found;

    /* NULL pointer for profile enables all */
    if (!newProfile) {
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);
	return TPM_RC_SUCCESS;
    }

    MemorySet(RuntimeAlgorithm->enabledAlgorithms, 0, sizeof(RuntimeAlgorithm->enabledAlgorithms));

    token = newProfile;
    while (1) {
	comma = strchr(token, ALGO_SEPARATOR_C);
	if (comma)
	    toklen = (size_t)(comma - token);
	else
	    toklen = strlen(token);

	found = false;
	for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	    /* skip over unsupported algorithms */
	    if (!s_AlgorithmProperties[algId].name)
		continue;
	    cmplen = MAX(strlen(s_AlgorithmProperties[algId].name), toklen);
	    if (!strncmp(token, s_AlgorithmProperties[algId].name, cmplen)) {
		TPMLIB_LogPrintf("Enabling %s: 0x%x\n", s_AlgorithmProperties[algId].name, algId);
		SET_BIT(algId, RuntimeAlgorithm->enabledAlgorithms);
		found = true;
		break;
	    } else if (s_AlgorithmProperties[algId].u.keySizes) {
		size_t algnamelen = strlen(s_AlgorithmProperties[algId].name);
		if (strncmp(token, s_AlgorithmProperties[algId].name, algnamelen) ||
		    strncmp(&token[algnamelen], "-min-size=", 10))
		    continue;
		minKeySize = strtoul(&token[algnamelen + 10], &endptr, 10);
		if ((*endptr != ALGO_SEPARATOR_C && *endptr != '\0') ||  minKeySize > 4096) {
		    retVal = TPM_RC_KEY_SIZE;
		    goto exit;
		}
		RuntimeAlgorithm->algosMinimumKeySizes[algId] = (UINT16)minKeySize;
		found = true;
		TPMLIB_LogPrintf("Set minimum key size for %s: %u\n", s_AlgorithmProperties[algId].name, RuntimeAlgorithm->algosMinimumKeySizes[algId]);
		break;
	    }
	}
	if (!found) {
	    TPMLIB_LogTPM2Error("Requested algorithm specifier %.*s is not supported.\n",
				(int)toklen, token);
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}

	if (!comma)
	    break;
	token = &comma[1];
    }

    /* reconcile with what can be disabled per code instrumentation */
    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	/* skip over unsupported algorithms */
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	if (!s_AlgorithmProperties[algId].canBeDisabled && !TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms)) {
	    retVal = TPM_RC_FAILURE;
	    goto exit;
	}
    }

    /* some consistency checks */
    /* Do not allow aes-min-size > 128 while RSA=2048 otherwise standard EK certs cannot be created anymore */
    if (RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_AES] > 128 &&
	RuntimeAlgorithm->algosMinimumKeySizes[TPM_ALG_RSA] == 2048) {
	retVal = TPM_RC_KEY_SIZE;
	goto exit;
    }

    RuntimeAlgorithm->algorithmProfile = strdup(newProfile);
    if (!RuntimeAlgorithm->algorithmProfile)
	retVal = TPM_RC_MEMORY;

exit:
    if (retVal != TPM_RC_SUCCESS)
	RuntimeAlgorithmSetDefault(RuntimeAlgorithm);

    return retVal;
}

LIB_EXPORT TPM_RC
RuntimeAlgorithmSwitchProfile(
			      struct RuntimeAlgorithm  *RuntimeAlgorithm,
			      const char               *newProfile,
			      char                    **oldProfile
			      )
{
    TPM_RC retVal;

    *oldProfile = RuntimeAlgorithm->algorithmProfile;
    RuntimeAlgorithm->algorithmProfile = NULL;

    retVal = RuntimeAlgorithmSetProfile(RuntimeAlgorithm, newProfile);
    if (retVal != TPM_RC_SUCCESS) {
	RuntimeAlgorithmSetProfile(RuntimeAlgorithm, *oldProfile);
	*oldProfile = NULL;
    }
    return retVal;
}

/* Check whether the given algorithm is runtime-disabled */
LIB_EXPORT BOOL
RuntimeAlgorithmCheckEnabled(
			     struct RuntimeAlgorithm *RuntimeAlgorithm,
			     TPM_ALG_ID	              algId      // IN: the algorithm to check
			     )
{
    TPMLIB_LogPrintf("IsEnEnabled(0x%x = '%s'): %d\n",
                     algId, s_AlgorithmProperties[algId].name, TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms));
    if (!TEST_BIT(algId, RuntimeAlgorithm->enabledAlgorithms))
	return FALSE;
    return TRUE;
}

/* Check whether the given symmetric or asymmetric crypto algorithm is enabled
 * for the given keysize */
LIB_EXPORT BOOL
RuntimeAlgorithmKeySizeCheckEnabled(
				    struct RuntimeAlgorithm *RuntimeAlgorithm,
				    TPM_ALG_ID               algId,		// IN: the algorithm to check
				    UINT16                   keySizeInBits	// IN: size of the key in bits
				    )
{
    UINT16 minKeySize;

    TPMLIB_LogPrintf("Check: %s-%d\n", s_AlgorithmProperties[algId].name, keySizeInBits);

    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
	return FALSE;

    minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];

    TPMLIB_LogPrintf("  MinKeySize: %u  current key's Size: %u\n", minKeySize, keySizeInBits);
    if (minKeySize > keySizeInBits)
	return FALSE;

    return TRUE;
}

LIB_EXPORT char *
RuntimeAlgorithmGet(
		    struct RuntimeAlgorithm   *RuntimeAlgorithm,
		    enum RuntimeAlgorithmType rat
		    )
{
    char *buffer, *nbuffer = NULL;
    unsigned int minKeySize;
    TPM_ALG_ID algId;
    int n;
    BOOL first = true;

    buffer = strdup("\"");
    if (!buffer)
	return NULL;

    for (algId = 0; algId < ARRAY_SIZE(s_AlgorithmProperties); algId++) {
	// skip over unsupported algorithms
	if (!s_AlgorithmProperties[algId].name)
	    continue;
	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    // no filter
	    break;
	case RUNTIME_ALGO_CAN_BE_DISABLED:
	    if (!s_AlgorithmProperties[algId].canBeDisabled)
		 continue;
	    break;
	case RUNTIME_ALGO_ENABLED:
	    // skip over disabled ones
	    if (!RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		continue;
	    break;
	case RUNTIME_ALGO_DISABLED:
	    // skip over enabled ones
	    if (RuntimeAlgorithmCheckEnabled(RuntimeAlgorithm, algId))
		continue;
	    break;
	default:
	    continue;
	}
	n = asprintf(&nbuffer, "%s%s%s",
		     buffer ? buffer : "",
		     first ? "" : ALGO_SEPARATOR_STR,
		     s_AlgorithmProperties[algId].name);
	free(buffer);
	if (n < 0)
	     return NULL;

	buffer = nbuffer;
	first = false;

	minKeySize = 0;

	switch (rat) {
	case RUNTIME_ALGO_IMPLEMENTED:
	    if (s_AlgorithmProperties[algId].u.keySizes) {
		minKeySize = KeySizesGetMinimum(s_AlgorithmProperties[algId].u.keySizes);
	    }
	    break;
	case RUNTIME_ALGO_ENABLED:
	    if (s_AlgorithmProperties[algId].u.keySizes) {
		minKeySize = RuntimeAlgorithm->algosMinimumKeySizes[algId];
	    }
	    break;
	default:
	}
	if (minKeySize > 0) {
	    n = asprintf(&nbuffer, "%s%s%s-min-size=%u",
			 buffer,
			 ALGO_SEPARATOR_STR,
			 s_AlgorithmProperties[algId].name,
			 minKeySize);
	    free(buffer);
	    if (n < 0)
		return NULL;

	    buffer = nbuffer;
	}
    }

    n = asprintf(&nbuffer, "%s\"", buffer);
    free(buffer);

    return nbuffer;
}

LIB_EXPORT void
RuntimeAlgorithmsFilterPCRSelection(
				    TPML_PCR_SELECTION *pcrSelection // IN/OUT: PCRSelection to filter
				    )
{
    UINT32 i = 0;

    while (i < pcrSelection->count) {
	if (!RuntimeAlgorithmCheckEnabled(&g_RuntimeProfile.RuntimeAlgorithm,
					  pcrSelection->pcrSelections[i].hash)) {
	    pcrSelection->count--;
	    if (pcrSelection->count - 1 > i) {
		MemoryCopy(&pcrSelection->pcrSelections[i],
			   &pcrSelection->pcrSelections[i + 1],
			   sizeof(pcrSelection->pcrSelections[0]) * (pcrSelection->count - i));
	    }
	} else {
	    i++;
	}
    }
}
