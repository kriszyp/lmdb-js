/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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


		if( ber_printf( ber, /*{*/"}" ) == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			return ld->ld_errno;
		}
	}


	if( ber_printf( ber, /*{*/"}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return ld->ld_errno;
	}

	return LDAP_SUCCESS;
}

int ldap_int_get_controls(
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

	len = ber_pvt_ber_remaining(ber);

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

		if( tag != LBER_ERROR ) {
			tag = ber_peek_tag( ber, &len );
		}

		if( tag == LBER_BOOLEAN ) {
			ber_int_t crit;
			tag = ber_scanf( ber, "b", &crit );
			tctrl->ldctl_iscritical = crit ? (char) 0 : (char) ~0;
		}

		if( tag != LBER_ERROR ) {
			tag = ber_peek_tag( ber, &len );
		}

		if( tag == LBER_OCTETSTRING ) {
			tag = ber_scanf( ber, "o", &tctrl->ldctl_value );

		} else {
			tctrl->ldctl_value.bv_val = NULL;
		}

		if( tag == LBER_ERROR ) {
			*ctrls = NULL;
			ldap_controls_free( tctrls );
			return LDAP_DECODING_ERROR;
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
	assert( c != NULL );

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
	assert( controls != NULL );

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

	new = (LDAPControl **) LDAP_MALLOC( i * sizeof(LDAPControl *) );

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

	if( c->ldctl_value.bv_len > 0 ) {
		new->ldctl_value.bv_val = (char *) LDAP_MALLOC( c->ldctl_value.bv_len );

		if(new->ldctl_value.bv_val == NULL) {
			if(new->ldctl_oid != NULL) {
				LDAP_FREE( new->ldctl_oid );
			}
			LDAP_FREE( new );
			return NULL;
		}
		
		SAFEMEMCPY( new->ldctl_value.bv_val, c->ldctl_value.bv_val, 
			c->ldctl_value.bv_len );

		new->ldctl_value.bv_len = c->ldctl_value.bv_len;

	} else {
		new->ldctl_value.bv_len = 0;
		new->ldctl_value.bv_val = NULL;
	}

	new->ldctl_iscritical = c->ldctl_iscritical;
	return new;
}
