/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* This notice applies to changes, created by or for Novell, Inc.,
 * to preexisting works for which notices appear elsewhere in this file.
 *
 * Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
 * USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT TO VERSION
 * 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS AVAILABLE AT
 * HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE" IN THE
 * TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION OF THIS
 * WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP PUBLIC
 * LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT THE
 * PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY. 
 *---
 * Note: A verbatim copy of version 2.0.1 of the OpenLDAP Public License
 * can be found in the file "build/LICENSE-2.0.1" in this distribution
 * of OpenLDAP Software.
 */
/* Portions Copyright (C) The Internet Society (1997)
 * ASN.1 fragments are from RFC 2251; see RFC for full legal notices.
 */

/* LDAPv3 Controls (RFC2251)
 *
 *	Controls ::= SEQUENCE OF Control  
 *
 *	Control ::= SEQUENCE { 
 *		controlType		LDAPOID,
 *		criticality		BOOLEAN DEFAULT FALSE,
 *		controlValue	OCTET STRING OPTIONAL
 *	}
 */

#include "portable.h"

#include <ac/stdlib.h>

#include <ac/time.h>
#include <ac/string.h>

#include "ldap-int.h"


/*
 * ldap_int_put_controls
 */

int
ldap_int_put_controls(
	LDAP *ld,
	LDAPControl *const *ctrls,
	BerElement *ber )
{
	LDAPControl *const *c;

	assert( ld != NULL );
	assert( LDAP_VALID(ld) );
	assert( ber != NULL );

	if( ctrls == NULL ) {
		/* use default server controls */
		ctrls = ld->ld_sctrls;
	}

	if( ctrls == NULL || *ctrls == NULL ) {
		return LDAP_SUCCESS;
	}

	if ( ld->ld_version < LDAP_VERSION3 ) {
		/* LDAPv2 doesn't support controls,
		 * error if any control is critical
		 */
		for( c = ctrls ; *c != NULL; c++ ) {
			if( (*c)->ldctl_iscritical ) {
				ld->ld_errno = LDAP_NOT_SUPPORTED;
				return ld->ld_errno;
			}
		}

		return LDAP_SUCCESS;
	}

	/* Controls are encoded as a sequence of sequences */
	if( ber_printf( ber, "t{"/*}*/, LDAP_TAG_CONTROLS ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return ld->ld_errno;
	}

	for( c = ctrls ; *c != NULL; c++ ) {
		if ( ber_printf( ber, "{s" /*}*/,
			(*c)->ldctl_oid ) == -1 )
		{
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return ld->ld_errno;
		}

		if( (*c)->ldctl_iscritical /* only if true */
			&&  ( ber_printf( ber, "b",
				(ber_int_t) (*c)->ldctl_iscritical ) == -1 ) )
		{
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return ld->ld_errno;
		}

		if( (*c)->ldctl_value.bv_val != NULL /* only if we have a value */
			&&  ( ber_printf( ber, "O",
				&((*c)->ldctl_value) ) == -1 ) )
		{
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return ld->ld_errno;
		}


		if( ber_printf( ber, /*{*/"N}" ) == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return ld->ld_errno;
		}
	}


	if( ber_printf( ber, /*{*/ "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return ld->ld_errno;
	}

	return LDAP_SUCCESS;
}

int ldap_pvt_get_controls(
	BerElement *ber,
	LDAPControl ***ctrls )
{
	int nctrls;
	ber_tag_t tag;
	ber_len_t len;
	char *opaque;

	assert( ber != NULL );

	if( ctrls == NULL ) {
		return LDAP_SUCCESS;
	}
	*ctrls = NULL;

	len = ber_pvt_ber_remaining( ber );

	if( len == 0) {
		/* no controls */
		return LDAP_SUCCESS;
	}

	if(( tag = ber_peek_tag( ber, &len )) != LDAP_TAG_CONTROLS ) {
		if( tag == LBER_ERROR ) {
			/* decoding error */
			return LDAP_DECODING_ERROR;
		}

		/* ignore unexpected input */
		return LDAP_SUCCESS;
	}

	/* set through each element */
	nctrls = 0;
	*ctrls = LDAP_MALLOC( 1 * sizeof(LDAPControl *) );

	if( *ctrls == NULL ) {
		return LDAP_NO_MEMORY;
	}

	*ctrls[nctrls] = NULL;

	for( tag = ber_first_element( ber, &len, &opaque );
		tag != LBER_ERROR;
		tag = ber_next_element( ber, &len, opaque ) )
	{
		LDAPControl *tctrl;
		LDAPControl **tctrls;

		tctrl = LDAP_CALLOC( 1, sizeof(LDAPControl) );

		/* allocate pointer space for current controls (nctrls)
		 * + this control + extra NULL
		 */
		tctrls = (tctrl == NULL) ? NULL :
			LDAP_REALLOC(*ctrls, (nctrls+2) * sizeof(LDAPControl *));

		if( tctrls == NULL ) {
			/* one of the above allocation failed */

			if( tctrl != NULL ) {
				LDAP_FREE( tctrl );
			}

			ldap_controls_free(*ctrls);
			*ctrls = NULL;

			return LDAP_NO_MEMORY;
		}


		tctrls[nctrls++] = tctrl;
		tctrls[nctrls] = NULL;

		tag = ber_scanf( ber, "{a" /*}*/, &tctrl->ldctl_oid );

		if( tag == LBER_ERROR ) {
			*ctrls = NULL;
			ldap_controls_free( tctrls );
			return LDAP_DECODING_ERROR;
		}

		tag = ber_peek_tag( ber, &len );

		if( tag == LBER_BOOLEAN ) {
			ber_int_t crit;
			tag = ber_scanf( ber, "b", &crit );
			tctrl->ldctl_iscritical = crit ? (char) 0 : (char) ~0;
			tag = ber_peek_tag( ber, &len );
		}

		if( tag == LBER_OCTETSTRING ) {
			tag = ber_scanf( ber, "o", &tctrl->ldctl_value );
		} else {
			tctrl->ldctl_value.bv_val = NULL;
		}

		*ctrls = tctrls;
	}
		
	return LDAP_SUCCESS;
}

/*
 * Free a LDAPControl
 */
void
ldap_control_free( LDAPControl *c )
{
#ifdef LDAP_MEMORY_DEBUG
	assert( c != NULL );
#endif

	if ( c != NULL ) {
		if( c->ldctl_oid != NULL) {
			LDAP_FREE( c->ldctl_oid );
		}

		if( c->ldctl_value.bv_val != NULL ) {
			LDAP_FREE( c->ldctl_value.bv_val );
		}

		LDAP_FREE( c );
	}
}

/*
 * Free an array of LDAPControl's
 */
void
ldap_controls_free( LDAPControl **controls )
{
#ifdef LDAP_MEMORY_DEBUG
	assert( controls != NULL );
#endif

	if ( controls != NULL ) {
		int i;

		for( i=0; controls[i] != NULL; i++) {
			ldap_control_free( controls[i] );
		}

		LDAP_FREE( controls );
	}
}

/*
 * Duplicate an array of LDAPControl
 */
LDAPControl **
ldap_controls_dup( LDAPControl *const *controls )
{
	LDAPControl **new;
	int i;

	if ( controls == NULL ) {
		return NULL;
	}

	/* count the controls */
	for(i=0; controls[i] != NULL; i++) /* empty */ ;

	if( i < 1 ) {
		/* no controls to duplicate */
		return NULL;
	}

	new = (LDAPControl **) LDAP_MALLOC( (i+1) * sizeof(LDAPControl *) );

	if( new == NULL ) {
		/* memory allocation failure */
		return NULL;
	}

	/* duplicate the controls */
	for(i=0; controls[i] != NULL; i++) {
		new[i] = ldap_control_dup( controls[i] );

		if( new[i] == NULL ) {
			ldap_controls_free( new );
			return NULL;
		}
	}

	new[i] = NULL;

	return new;
}

/*
 * Duplicate a LDAPControl
 */
LDAPControl *
ldap_control_dup( const LDAPControl *c )
{
	LDAPControl *new;

	if ( c == NULL ) {
		return NULL;
	}

	new = (LDAPControl *) LDAP_MALLOC( sizeof(LDAPControl) );

	if( new == NULL ) {
		return NULL;
	}

	if( c->ldctl_oid != NULL ) {
		new->ldctl_oid = LDAP_STRDUP( c->ldctl_oid );

		if(new->ldctl_oid == NULL) {
			LDAP_FREE( new );
			return NULL;
		}

	} else {
		new->ldctl_oid = NULL;
	}

	if( c->ldctl_value.bv_val != NULL ) {
		new->ldctl_value.bv_val =
			(char *) LDAP_MALLOC( c->ldctl_value.bv_len + 1 );

		if(new->ldctl_value.bv_val == NULL) {
			if(new->ldctl_oid != NULL) {
				LDAP_FREE( new->ldctl_oid );
			}
			LDAP_FREE( new );
			return NULL;
		}
		
		new->ldctl_value.bv_len = c->ldctl_value.bv_len;

		AC_MEMCPY( new->ldctl_value.bv_val, c->ldctl_value.bv_val, 
			c->ldctl_value.bv_len );

		new->ldctl_value.bv_val[new->ldctl_value.bv_len] = '\0';

	} else {
		new->ldctl_value.bv_len = 0;
		new->ldctl_value.bv_val = NULL;
	}

	new->ldctl_iscritical = c->ldctl_iscritical;
	return new;
}


LDAPControl *
ldap_find_control(
	LDAP_CONST char *oid,
	LDAPControl **ctrls )
{
	if( ctrls == NULL || *ctrls == NULL ) {
		return NULL;
	}

	for( ; *ctrls != NULL; ctrls++ ) {
		if( strcmp( (*ctrls)->ldctl_oid, oid ) == 0 ) {
			return *ctrls;
		}
	}

	return NULL;
}

/*
   ldap_create_control
   
   Internal function to create an LDAP control from the encoded BerElement.

   requestOID  (IN) The OID to use in creating the control.
   
   ber         (IN) The encoded BerElement to use in creating the control.
   
   iscritical  (IN) 0 - Indicates the control is not critical to the operation.
					non-zero - The control is critical to the operation.
				  
   ctrlp      (OUT) Returns a pointer to the LDAPControl created.  This control
					SHOULD be freed by calling ldap_control_free() when done.
---*/

int
ldap_create_control(
	LDAP_CONST char *requestOID,
	BerElement *ber,
	int iscritical,
	LDAPControl **ctrlp )
{
	LDAPControl *ctrl;

	assert( requestOID != NULL );
	assert( ber != NULL );
	assert( ctrlp != NULL );

	ctrl = (LDAPControl *) LDAP_MALLOC( sizeof(LDAPControl) );
	if ( ctrl == NULL ) {
		return LDAP_NO_MEMORY;
	}

	BER_BVZERO( &ctrl->ldctl_value );
	if ( ber != NULL && ber_flatten2( ber, &ctrl->ldctl_value, 1 ) == -1 ) {
		LDAP_FREE( ctrl );
		return LDAP_NO_MEMORY;
	}

	ctrl->ldctl_oid = LDAP_STRDUP( requestOID );
	ctrl->ldctl_iscritical = iscritical;

	if ( requestOID != NULL && ctrl->ldctl_oid == NULL ) {
		ldap_control_free( ctrl );
		return LDAP_NO_MEMORY;
	}

	*ctrlp = ctrl;
	return LDAP_SUCCESS;
}

/*
 * check for critical client controls and bitch if present
 * if we ever support critical controls, we'll have to
 * find a means for maintaining per API call control
 * information.
 */
int ldap_int_client_controls( LDAP *ld, LDAPControl **ctrls )
{
	LDAPControl *const *c;

	assert( ld != NULL );
	assert( LDAP_VALID(ld) );

	if( ctrls == NULL ) {
		/* use default server controls */
		ctrls = ld->ld_cctrls;
	}

	if( ctrls == NULL || *ctrls == NULL ) {
		return LDAP_SUCCESS;
	}

	for( c = ctrls ; *c != NULL; c++ ) {
		if( (*c)->ldctl_iscritical ) {
			ld->ld_errno = LDAP_NOT_SUPPORTED;
			return ld->ld_errno;
		}
	}

	return LDAP_SUCCESS;
}
