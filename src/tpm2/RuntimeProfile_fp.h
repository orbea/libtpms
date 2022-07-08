/********************************************************************************/
/*										*/
/*			        Runtime Profile 				*/
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

#ifndef RUNTIME_PROFILE_H
#define RUNTIME_PROFILE_H

#include "RuntimeAlgorithm_fp.h"
#include "RuntimeCommands_fp.h"

struct RuntimeProfile {
    struct RuntimeAlgorithm RuntimeAlgorithm;
    struct RuntimeCommands  RuntimeCommands;
    char *profileName;		    /* name of profile */
    char *runtimeProfileJSON;	    /* JSON description */
    unsigned int stateFormatLevel;  /* how the state is to be written */
    BOOL wasNullProfile;            /* whether this profile was originally due to a NULL profile */
};

extern struct RuntimeProfile g_RuntimeProfile;

LIB_EXPORT TPM_RC
RuntimeProfileInit(
		   struct RuntimeProfile           *RuntimeProfile
		   );

TPM_RC
RuntimeProfileSet(
		  struct RuntimeProfile *RuntimeProfile,
		  const char            *jsonProfile,
		  bool                   jsonProfileFromUser
		  );

LIB_EXPORT TPM_RC
RuntimeProfileTest(
		   struct RuntimeProfile *RuntimeProfile,
		   const char            *jsonProfile,
		   bool                   jsonProfileFromUser
		   );

LIB_EXPORT BOOL
RuntimeProfileWasNullProfile(
			     struct RuntimeProfile *RuntimeProfile
			     );

LIB_EXPORT TPM_RC
RuntimeProfileFormatJSON(
			 struct RuntimeProfile *RuntimeProfile
			 );

LIB_EXPORT const char *
RuntimeProfileGetJSON(
		      struct RuntimeProfile *RuntimeProfile
		      );

LIB_EXPORT TPM_RC
RuntimeProfileGetByIndex(
			 size_t  idx,
			 char    **runtimeProfileJSON
			 );

#endif /* RUNTIME_PROFILE_H */
