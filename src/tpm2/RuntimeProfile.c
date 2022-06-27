/********************************************************************************/
/*										*/
/*			       Runtime Profile 					*/
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
#include <errno.h>
#include <stdio.h>
#include <regex.h>

#include "Tpm.h"
#include "tpm_library_intern.h"

struct RuntimeProfile g_RuntimeProfile;

static const struct RuntimeProfileDesc {
    const char *name;
    const char *commandProfile;
    const char *algorithmsProfile;
    /* StateFormatLevel drives the format the TPM's state is written in and
     * how it is read.
     * Once a version of libtpms is released this field must never change afterwards
     * so that backwards compatibility for reading the state can be maintained.
     * This basically locks the name of the profile to the stateFormatLevel.
     */
    unsigned int stateFormatLevel;
#define STATE_FORMAT_LEVEL_CURRENT 1
#define STATE_FORMAT_LEVEL_UNKNOWN 0 /* JSON didn't provide StateFormatLevel; this is only
                                        allowed for the 'default' profile or when user
                                        passed JSON via SetProfile() */
} RuntimeProfileDescs[] = {
    {
        /* When no profile is given, the 'default' profile is applied which locks the
         * TPM 2 into a set of commands and algorithms that are enabled.
         */
	.name = "default",
	.commandProfile    = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
			     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.algorithmsProfile = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,"
			     "aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,"
			     "null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,"
			     "kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,symcipher,"
			     "camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb",
	.stateFormatLevel  = 1, /* do NOT change */
    }, {
	.name = "fips-2022",
	.commandProfile    = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"
	                     "0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
        /*
         * removed: rsa-1024, sha1, rsapss (not available CentOS FIPS mode),
         *          camellia (CentOS), tdes (CentOS)
         * Note: Test suites will fail!
         */
	.algorithmsProfile = "rsa,rsa-min-size=2048,hmac,aes,aes-min-size=128,mgf1,keyedhash,"
	                     "xor,sha256,sha384,sha512,null,rsassa,rsaes,oaep,ecdsa,ecdh,ecdaa,"
	                     "sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,"
	                     "symcipher,cmac,ctr,ofb,cbc,cfb,ecb,ecc-min-size=256",
	.stateFormatLevel  = 1,
    }, {
        // FIXME: test profile
	.name = "1",
	.commandProfile = "0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197",
	.stateFormatLevel = 1,
    }
};

/* Current state format level this version of libtpms implements.
 * This is to be bumped up every time new parts of the state need to be written.
 */
static const unsigned int s_currentStateFormatLevel = STATE_FORMAT_LEVEL_CURRENT;

LIB_EXPORT TPM_RC
RuntimeProfileInit(
		   struct RuntimeProfile           *RuntimeProfile
		   )
{
    RuntimeAlgorithmInit(&RuntimeProfile->RuntimeAlgorithm);
    RuntimeCommandsInit(&RuntimeProfile->RuntimeCommands);

    RuntimeProfile->profileName = NULL;
    RuntimeProfile->runtimeProfileJSON = NULL;
    RuntimeProfile->stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
    RuntimeProfile->wasNullProfile = FALSE;

    return TPM_RC_SUCCESS;
}

static TPM_RC
RuntimeProfileSetRuntimeProfile(
				struct RuntimeProfile           *RuntimeProfile,
				const struct RuntimeProfileDesc *rp,
				const char                      *algorithmsProfile
				)
{
    TPM_RC retVal;

    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    return RuntimeCommandsSetProfile(&RuntimeProfile->RuntimeCommands, rp->commandProfile);
}

static TPM_RC
RuntimeProfileGetFromJSON(
			  const char  *json,
			  const char  *regex,
			  char       **value
			  )
{
    regmatch_t match[2];
    TPM_RC retVal;
    regex_t r;

    if (regcomp(&r, regex, REG_EXTENDED) != 0)
	return TPM_RC_FAILURE;

    if (regexec(&r, json, 2, match, 0) == REG_NOMATCH) {
	retVal = TPM_RC_NO_RESULT;
	goto exit;
    }

    if (match[1].rm_eo - match[1].rm_so == 0) {
	retVal = TPM_RC_SIZE;
	goto exit;
    }

    *value = strndup(&json[match[1].rm_so], match[1].rm_eo - match[1].rm_so);
    if (*value == NULL) {
	retVal= TPM_RC_MEMORY;
	goto exit;
    }
    retVal = TPM_RC_SUCCESS;

exit:
    regfree(&r);

    return retVal;
}

static TPM_RC
RuntimeProfileGetNameFromJSON(
			      const char  *json,
			      char       **name
			      )
{
    const char *regex = "^\\{.*[[:space:]]*\"name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";

    return RuntimeProfileGetFromJSON(json, regex, name);
}

static TPM_RC
GetStateFormatLevelFromJSON(
			    const char    *json,
			    unsigned int  *stateFormatLevel
			    )
{
    const char *regex = "^\\{.*,[[:space:]]*\"stateFormatLevel\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    char *str = NULL;
    unsigned long v;
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, &str);
    if (retVal == TPM_RC_NO_RESULT) {
	*stateFormatLevel = STATE_FORMAT_LEVEL_UNKNOWN;
	return TPM_RC_SUCCESS;
    }
    if (retVal)
	return retVal;

    errno = 0;
    v = strtoul(str, NULL, 10);
    if (v > UINT_MAX || errno)
	retVal = TPM_RC_FAILURE;
    else
	*stateFormatLevel = v;

    free(str);

    return retVal;
}

static TPM_RC
GetAlgorithmsProfileFromJSON(
			     const char  *json,
			     char       **algorithmsProfile
			     )
{
    const char *regex = "^\\{.*[[:space:]]*\"algorithms\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*\\}$";
    TPM_RC retVal;

    retVal = RuntimeProfileGetFromJSON(json, regex, algorithmsProfile);
    if (retVal == TPM_RC_NO_RESULT) {
	*algorithmsProfile = NULL;
	retVal = 0;
    }
    return retVal;
}

static TPM_RC
GetParametersFromJSON(
		      const char    *json,
		      char         **profileName,
		      unsigned int  *stateLevelFormat,
		      char         **algorithmsProfile
		      )
{
    TPM_RC retVal;

    if (!json) {
	*profileName = strdup("default");
	if (*profileName == NULL)
	    return TPM_RC_MEMORY;
        *stateLevelFormat = STATE_FORMAT_LEVEL_CURRENT;
	return TPM_RC_SUCCESS;
    }

    retVal = RuntimeProfileGetNameFromJSON(json, profileName);
    if (retVal != TPM_RC_SUCCESS)
        return retVal;

    retVal = GetStateFormatLevelFromJSON(json, stateLevelFormat);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_profilename;

    retVal = GetAlgorithmsProfileFromJSON(json, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto err_free_profilename;

    return TPM_RC_SUCCESS;

err_free_profilename:
    free(*profileName);

    return retVal;
}

static TPM_RC
RuntimeProfileFormat(char **json, const char *profileName, const char *algorithmsProfile)
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *ret, *nret;
    size_t i;
    int n;

    if (!profileName)
	return TPM_RC_SUCCESS;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];
	    break;
	}
    }
    if (!rp)
	return TPM_RC_FAILURE;

    n = asprintf(&ret,
                 "{\"name\":\"%s\","
                  "\"stateFormatLevel\":%d",
                  profileName, rp->stateFormatLevel);
    if (n < 0)
	return TPM_RC_MEMORY;
    if (rp->commandProfile) {
	n = asprintf(&nret, "%s,\"commands\":\"%s\"", ret, rp->commandProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    if (algorithmsProfile) {
	n = asprintf(&nret, "%s,\"algorithms\":\"%s\"", ret, algorithmsProfile);
	free(ret);
	if (n < 0)
	    return TPM_RC_MEMORY;

	ret = nret;
    }
    n = asprintf(&nret, "%s}", ret);
    free(ret);
    if (n < 0)
       return TPM_RC_MEMORY;

    *json = nret;

    return TPM_RC_SUCCESS;
}

LIB_EXPORT TPM_RC
RuntimeProfileFormatJSON(
			 struct RuntimeProfile *RuntimeProfile
			 )
{
    char *runtimeProfileJSON = NULL;
    TPM_RC retVal;

    if (!RuntimeProfile->profileName)
	return TPM_RC_FAILURE;

    retVal = RuntimeProfileFormat(&runtimeProfileJSON,
				  RuntimeProfile->profileName,
				  RuntimeProfile->RuntimeAlgorithm.algorithmProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    return TPM_RC_SUCCESS;
}

static TPM_RC
CheckStateFormatLevel(
		      const struct RuntimeProfileDesc *rpd,
		      unsigned int                    *stateFormatLevel,
		      bool                             jsonFromUser
		      )
{
    TPM_RC retVal = TPM_RC_SUCCESS;

    if (strcmp(rpd->name, "default") == 0) {
        /* the stateFormatLevel must never be larger than the one implemented */
	if (*stateFormatLevel > s_currentStateFormatLevel) {
	    retVal = TPM_RC_FAILURE;
	} else {
	    if (jsonFromUser) {
		/* If the default profile is chosen due to the user providing it
		 * choose the latest StateFormatLevel.
		 */
		*stateFormatLevel = s_currentStateFormatLevel;
	    } else {
		/* If the default profile is chose due to not finding a profile
		 * in the TPM 2's state then set the StateFormatLevel to '1'.
		 */
		*stateFormatLevel = 1;
	    }
	}
    } else {
	/* If user passed JSON and it didn't contain a stateFormatLevel take
	 * it from the profile description.
	 * Otherwise the stateFormatLevel read from the state must match the
	 * one in the profile description.
	 */
	if (*stateFormatLevel == STATE_FORMAT_LEVEL_UNKNOWN)
	    *stateFormatLevel = rpd->stateFormatLevel;
	else if (*stateFormatLevel != rpd->stateFormatLevel)
	    retVal = TPM_RC_FAILURE;
    }
    return retVal;
}

/*
 * Set the given RuntimeProfile to the policy in JSON format.
 * If jsonProlicyIsFromUser is 'true' then the the default policy
 * will get the latest StateFormatLevel version number, otherwise
 * it will get the StateFormatLevel '1' if not stateFormatLevel
 * field is found in the JSON policy.
 */
LIB_EXPORT TPM_RC
RuntimeProfileSet(
		  struct RuntimeProfile *RuntimeProfile,
		  const char	        *jsonPolicy,
		  bool                   jsonPolicyIsFromUser
		  )
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *runtimeProfileJSON = NULL;
    char *algorithmsProfile = NULL;
    unsigned int stateFormatLevel;
    char *profileName = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(jsonPolicy, &profileName, &stateFormatLevel,
				   &algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	return retVal;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];

	    retVal = CheckStateFormatLevel(rp, &stateFormatLevel, jsonPolicyIsFromUser);
	    if (retVal != TPM_RC_SUCCESS)
		goto error;

            /* if user did not provide algo profile use the default one */
	    if (!algorithmsProfile && rp->algorithmsProfile) {
		algorithmsProfile = strdup(rp->algorithmsProfile);
		if (!algorithmsProfile) {
		    retVal = TPM_RC_MEMORY;
		    goto error;
		}
	    }

	    retVal = RuntimeProfileSetRuntimeProfile(RuntimeProfile, rp,
						     algorithmsProfile);
	    if (retVal != TPM_RC_SUCCESS)
		return retVal;
	    break;
	}
    }
    if (!rp) {
	retVal = TPM_RC_FAILURE;
	goto error;
    }

    retVal = RuntimeProfileFormat(&runtimeProfileJSON, profileName, algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	goto error;

    TPMLIB_LogPrintf("%s @ %u: runtimeProfile: %s\n", __func__, __LINE__, runtimeProfileJSON);

    free(RuntimeProfile->runtimeProfileJSON);
    RuntimeProfile->runtimeProfileJSON = runtimeProfileJSON;

    free(RuntimeProfile->RuntimeAlgorithm.algorithmProfile); // FIXME: use a function
    RuntimeProfile->RuntimeAlgorithm.algorithmProfile = algorithmsProfile;

    free(RuntimeProfile->profileName);
    RuntimeProfile->profileName = profileName;

    /* Indicate whether the profile was mapped to the default profile due to
     * a NULL pointer read from the state.
     */
    RuntimeProfile->wasNullProfile = (jsonPolicy == NULL) && (jsonPolicyIsFromUser == FALSE);

    return TPM_RC_SUCCESS;

error:
    free(algorithmsProfile);
    free(profileName);
    return retVal;
}

LIB_EXPORT const char *
RuntimeProfileGetJSON(
		      struct RuntimeProfile *RuntimeProfile
		      )
{
    return RuntimeProfile->runtimeProfileJSON;
}

LIB_EXPORT TPM_RC
RuntimeProfileTest(
		   struct RuntimeProfile *RuntimeProfile,
		   const char	         *jsonProfile,
		   bool                   jsonProfileFromUser
		   )
{
    const struct RuntimeProfileDesc *rp = NULL;
    char *algorithmsProfile = NULL;
    unsigned int stateFormatLevel;
    char *profileName = NULL;
    char *oldProfile = NULL;
    TPM_RC retVal;
    size_t i;

    retVal = GetParametersFromJSON(jsonProfile, &profileName, &stateFormatLevel,
				   &algorithmsProfile);
    if (retVal != TPM_RC_SUCCESS)
	 return retVal;

    for (i = 0; i < ARRAY_SIZE(RuntimeProfileDescs); i++) {
	if (!strcmp(RuntimeProfileDescs[i].name, profileName)) {
	    rp = &RuntimeProfileDescs[i];

	    retVal = CheckStateFormatLevel(rp, &stateFormatLevel, jsonProfileFromUser);
	    if (retVal != TPM_RC_SUCCESS)
		goto error;

	    break;
	}
    }
    if (!rp) {
	retVal = TPM_RC_FAILURE;
	goto error;
    }

    if (algorithmsProfile) {
	/* Test the algorithms profile if one was given;
	 * The CommandProfile will be taken from the profile description above
	 * and is assumed to be correct.
	 */
	retVal = RuntimeAlgorithmSwitchProfile(&RuntimeProfile->RuntimeAlgorithm,
					       algorithmsProfile, &oldProfile);
	if (retVal == TPM_RC_SUCCESS)
	    retVal = RuntimeAlgorithmSetProfile(&RuntimeProfile->RuntimeAlgorithm, oldProfile);
    }

error:
    free(algorithmsProfile);
    free(profileName);

    return retVal;
}

LIB_EXPORT BOOL
RuntimeProfileWasNullProfile(
			     struct RuntimeProfile *RuntimeProfile
			     )
{
    return RuntimeProfile->wasNullProfile;
}
