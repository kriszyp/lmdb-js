/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Adapted for inclusion into OpenLDAP by Kurt D. Zeilenga */
/*---
 * Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT
 * THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 *---*/
/* Note: A verbatim copy of version 2.0.1 of the OpenLDAP Public License
 * can be found in the file "build/LICENSE-2.0.1" in this distribution
 * of OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

#define PPOLICY_WARNING 0xa0L
#define PPOLICY_ERROR 0xa1L

#define PPOLICY_EXPIRE 0xa0L
#define PPOLICY_GRACE  0xa1L

/*---
   ldap_create_passwordpolicy_control
   
   Create and encode the Password Policy Request

   ld        (IN)  An LDAP session handle, as obtained from a call to
				   ldap_init().
   
   ctrlp     (OUT) A result parameter that will be assigned the address
				   of an LDAPControl structure that contains the 
				   passwordPolicyRequest control created by this function.
				   The memory occupied by the LDAPControl structure
				   SHOULD be freed when it is no longer in use by
				   calling ldap_control_free().
					  
   
   There is no control value for a password policy request
 ---*/

int
ldap_create_passwordpolicy_control( LDAP *ld,
                                    LDAPControl **ctrlp )
{
	BerElement *ber;

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( ctrlp != NULL );

	if ((ber = ldap_alloc_ber_with_options(ld)) == NULL) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return(LDAP_NO_MEMORY);
	}

	ld->ld_errno = ldap_create_control( LDAP_CONTROL_PASSWORDPOLICYREQUEST,
		ber, 0, ctrlp);

	ber_free(ber, 1);
	return(ld->ld_errno);

exit:
	ber_free(ber, 1);
	ld->ld_errno = LDAP_ENCODING_ERROR;
	return(ld->ld_errno);
}


/*---
   ldap_parse_passwordpolicy_control
   
   Decode the passwordPolicyResponse control and return information.

   ld           (IN)   An LDAP session handle.
   
   ctrls        (IN)   The address of a NULL-terminated array of 
					   LDAPControl structures, typically obtained 
					   by a call to ldap_parse_result().

   exptimep     (OUT)  This result parameter is filled in with the number of seconds before
                                           the password will expire, if expiration is imminent
                                           (imminency defined by the password policy). If expiration
                                           is not imminent, the value is set to -1.

   gracep       (OUT)  This result parameter is filled in with the number of grace logins after
                                           the password has expired, before no further login attempts
                                           will be allowed.

   errorcodep   (OUT)  This result parameter is filled in with the error code of the password operation
                                           If no error was detected, this error is set to PP_noError.
   
   Ber encoding
   
   PasswordPolicyResponseValue ::= SEQUENCE {
       warning [0] CHOICE {
           timeBeforeExpiration [0] INTEGER (0 .. maxInt),
           graceLoginsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL
       error [1] ENUMERATED {
           passwordExpired        (0),
           accountLocked          (1),
           changeAfterReset       (2),
           passwordModNotAllowed  (3),
           mustSupplyOldPassword  (4),
           invalidPasswordSyntax  (5),
           passwordTooShort       (6),
           passwordTooYoung       (7),
           passwordInHistory      (8) } OPTIONAL }
           
---*/

int
ldap_parse_passwordpolicy_control(
	LDAP           *ld,
	LDAPControl    **ctrls,
        int            *expirep,
        int            *gracep,
        LDAPPasswordPolicyError *errorp )
{
	BerElement  *ber;
	LDAPControl *pControl;
	int i, exp = -1, grace = -1;
	ber_tag_t tag;
	ber_len_t berLen;
        char *last;
        LDAPPasswordPolicyError err = PP_noError;
        
	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if (ctrls == NULL) {
		ld->ld_errno = LDAP_CONTROL_NOT_FOUND;
		return(ld->ld_errno);
	}

	/* Search the list of control responses for a VLV control. */
	for (i=0; ctrls[i]; i++) {
		pControl = ctrls[i];
		if (!strcmp(LDAP_CONTROL_PASSWORDPOLICYRESPONSE, pControl->ldctl_oid))
                       goto foundPPControl;
	}

	/* No sort control was found. */
	ld->ld_errno = LDAP_CONTROL_NOT_FOUND;
	return(ld->ld_errno);

foundPPControl:
	/* Create a BerElement from the berval returned in the control. */
	ber = ber_init(&pControl->ldctl_value);

	if (ber == NULL) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return(ld->ld_errno);
	}

        tag = ber_peek_tag( ber, &berLen );
        if (tag != LBER_SEQUENCE) goto exit;

        for( tag = ber_first_element( ber, &berLen, &last );
             tag != LBER_DEFAULT;
             tag = ber_next_element( ber, &berLen, last ) ) {
            switch (tag) {
                case PPOLICY_WARNING:
                    ber_skip_tag(ber, &berLen );
                    tag = ber_peek_tag( ber, &berLen );
                    switch( tag ) {
                        case PPOLICY_EXPIRE:
                            if (ber_get_int( ber, &exp ) == LBER_DEFAULT) goto exit;
                            break;
                        case PPOLICY_GRACE:
                            if (ber_get_int( ber, &grace ) == LBER_DEFAULT) goto exit;
                            break;
                        default:
                            goto exit;

                    }
                    
                    break;
                case PPOLICY_ERROR:
                    if (ber_get_enum( ber, (int *)&err ) == LBER_DEFAULT) goto exit;
                    break;
                default:
                    goto exit;
            }
        }
        
	ber_free(ber, 1);

	/* Return data to the caller for items that were requested. */
        if (expirep) *expirep = exp;
        if (gracep) *gracep = grace;
        if (errorp) *errorp = err;
        
	ld->ld_errno = LDAP_SUCCESS;
	return(ld->ld_errno);

  exit:
        ber_free(ber, 1);
        ld->ld_errno = LDAP_DECODING_ERROR;
        return(ld->ld_errno);
}
