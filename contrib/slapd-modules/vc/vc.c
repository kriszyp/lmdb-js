/* vc.c - LDAP Verify Credentials extop (no spec yet) */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2010 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

/*
 * LDAP Verify Credentials: suggested by Kurt Zeilenga
 * no spec yet
 */

#include "portable.h"

#include "slap.h"
#include "ac/string.h"

static const struct berval vc_exop_oid_bv = BER_BVC(LDAP_EXOP_VERIFY_CREDENTIALS);

static int
vc_exop(
	Operation	*op,
	SlapReply	*rs )
{
	int rc = LDAP_SUCCESS;
	ber_tag_t tag;
	ber_len_t len = -1;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	struct berval reqdata = BER_BVNULL;

	if ( op->ore_reqdata == NULL || op->ore_reqdata->bv_len == 0 ) {
		rs->sr_text = "empty request data field in VerifyCredentials exop";
		return LDAP_PROTOCOL_ERROR;
	}

	ber_dupbv_x( &reqdata, op->ore_reqdata, op->o_tmpmemctx );

	/* ber_init2 uses reqdata directly, doesn't allocate new buffers */
	ber_init2( ber, &reqdata, 0 );

	tag = ber_scanf( ber, "{" /*}*/ );
	if ( tag != LBER_SEQUENCE ) {
		rs->sr_err = LDAP_PROTOCOL_ERROR;
		goto done;
	}

	tag = ber_peek_tag( ber, &len );
	if ( tag == LBER_INTEGER ) {
		ber_int_t version;
		struct berval bdn;
		ber_tag_t authtag;
		struct berval cred;
		struct berval ndn;
		Attribute a = { 0 };

		/* simple */

		/* version */
		tag = ber_scanf( ber, "i", &version );
		if ( tag == LBER_ERROR || version != 3 ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			goto done;
		}

		/* DN, authtag, cred */
		tag = ber_scanf( ber, "mtm", &bdn, &authtag, &cred );
		if ( tag == LBER_ERROR || authtag != LDAP_AUTH_SIMPLE ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			goto done;
		}

		rc = dnNormalize( 0, NULL, NULL, &bdn, &ndn, op->o_tmpmemctx );
		if ( rc != LDAP_SUCCESS ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			goto done;
		}

		a.a_desc = slap_schema.si_ad_userPassword;
		rc = backend_attribute( op, NULL, &ndn, a.a_desc, &a.a_vals, ACL_AUTH );
		if ( rc != LDAP_SUCCESS || a.a_vals == NULL ) {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;

		} else {
			a.a_nvals = a.a_vals;
			for ( a.a_numvals = 0; !BER_BVISNULL( &a.a_nvals[a.a_numvals] ); a.a_numvals++ )
				;

			rc = slap_passwd_check( op, NULL, &a, &cred, &rs->sr_text );
			if ( rc != 0 ) {
				rs->sr_err = LDAP_INVALID_CREDENTIALS;

			} else {
				rs->sr_err = LDAP_SUCCESS;
				rs->sr_rspoid = NULL;
				rs->sr_rspdata = NULL;
			}
		}

		op->o_tmpfree( ndn.bv_val, op->o_tmpmemctx );
		op->o_tmpfree( a.a_vals, op->o_tmpmemctx );

	} else {
		/* SASL */
		if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE ) {
		} else {
		}
	}

	tag = ber_skip_tag( ber, &len );
	if ( len || tag != LBER_DEFAULT ) {
		rs->sr_err = LDAP_PROTOCOL_ERROR;
		goto done;
	}

done:;
	op->o_tmpfree( reqdata.bv_val, op->o_tmpmemctx );

        return rs->sr_err;
}

static int
vc_initialize( void )
{
	int rc;

	rc = load_extop2( (struct berval *)&vc_exop_oid_bv,
		SLAP_EXOP_HIDE, vc_exop, 0 );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"vc_initialize: unable to register VerifyCredentials exop: %d.\n",
			rc, 0, 0 );
	}

	return rc;
}

int
init_module( int argc, char *argv[] )
{
	return vc_initialize();
}

