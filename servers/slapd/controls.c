/* 
 * Copyright 1999 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"

#include "../../libraries/liblber/lber-int.h"

char *supportedControls[] = {
	LDAP_CONTROL_MANAGEDSAIT,
	NULL
};

int get_ctrls(
	Connection *conn,
	Operation *op,
	int sendres )
{
	int nctrls;
	ber_tag_t tag;
	ber_len_t len;
	char *opaque;
	BerElement *ber = op->o_ber;
	LDAPControl ***ctrls = &op->o_ctrls;
	int rc = LDAP_SUCCESS;
	char *errmsg = NULL;

	len = ber_pvt_ber_remaining(ber);

	if( len == 0) {
		/* no controls */
		rc = LDAP_SUCCESS;
		goto return_results;
	}

	if(( tag = ber_peek_tag( ber, &len )) != LDAP_TAG_CONTROLS ) {
		if( tag == LBER_ERROR ) {
			rc = -1;
			errmsg = "unexpected data in PDU";
		}

		goto return_results;
	}

	if( op->o_protocol < LDAP_VERSION3 ) {
		rc = -1;
		errmsg = "controls require LDAPv3";
		goto return_results;
	}

	/* set through each element */
	nctrls = 0;
	*ctrls = ch_malloc( 1 * sizeof(LDAPControl *) );

#if 0
	if( *ctrls == NULL ) {
		rc = LDAP_NO_MEMORY;
		errmsg = "no memory";
		goto return_results;
	}
#endif

	ctrls[nctrls] = NULL;

	for( tag = ber_first_element( ber, &len, &opaque );
		tag != LBER_ERROR;
		tag = ber_next_element( ber, &len, opaque ) )
	{
		LDAPControl *tctrl;
		LDAPControl **tctrls;

		tctrl = ch_calloc( 1, sizeof(LDAPControl) );

		/* allocate pointer space for current controls (nctrls)
		 * + this control + extra NULL
		 */
		tctrls = (tctrl == NULL) ? NULL :
			ch_realloc(*ctrls, (nctrls+2) * sizeof(LDAPControl *));

#if 0
		if( tctrls == NULL ) {
			/* one of the above allocation failed */

			if( tctrl != NULL ) {
				ch_free( tctrl );
			}

			ldap_controls_free(*ctrls);
			*ctrls = NULL;

			rc = LDAP_NO_MEMORY;
			errmsg = "no memory";
			goto return_results;
		}
#endif


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
			rc = -1;
			errmsg = "decoding controls error";
			goto return_results;
		}

		if( tctrl->ldctl_iscritical &&
			!charray_inlist( supportedControls, tctrl->ldctl_oid ) )
		{
			rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
			errmsg = "critical extension is unavailable ";
			goto return_results;
		}

		*ctrls = tctrls;
	}

return_results:
	if( sendres && rc != LDAP_SUCCESS ) {
		if( rc == -1 ) {
			send_ldap_disconnect( conn, op, rc, errmsg );
		} else {
			send_ldap_result( conn, op, rc,
				NULL, errmsg, NULL, NULL );
		}
	}

	return rc;
}


int get_manageDSAit( Operation *op )
{
	int i;
	if( op == NULL || op->o_ctrls == NULL ) {
		return 0;
	}

	for( i=0; op->o_ctrls[i] != NULL; i++ ) {
		if( strcmp( LDAP_CONTROL_MANAGEDSAIT, op->o_ctrls[i]->ldctl_oid )
			== 0 )
		{
			return 1;
		}
	}

	return 0;
}