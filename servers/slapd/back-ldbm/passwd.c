/* extended.c - ldbm backend extended routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_exop_passwd(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
	char		*oid,
    struct berval	*reqdata,
    struct berval	**rspdata,
	char**	text
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	int rc = LDAP_OPERATIONS_ERROR;
	Entry *e;
	struct berval *cred = NULL;

	assert( oid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, oid ) == 0 );

	Debug( LDAP_DEBUG_ARGS, "==> ldbm_back_exop_passwd: dn: %s\n",
		op->o_dn, 0, 0 );


	cred = slap_passwd_generate( reqdata );
	if( cred == NULL || cred->bv_len == 0 ) {
		*text = ch_strdup("password generation failed");
		return LDAP_OPERATIONS_ERROR;
	}

	Debug( LDAP_DEBUG_TRACE, "passwd: %s\n", cred->bv_val, 0, 0 );

	e = dn2entry_w( be, op->o_ndn, NULL );

	if( e == NULL ) {
		*text = ch_strdup("could not locate authorization entry");
		return LDAP_OPERATIONS_ERROR;
	}

	if( ! access_allowed( be, conn, op, e, "entry", NULL, ACL_WRITE ) ) {
		*text = ch_strdup("access to authorization entry denied");
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto done;
	}

	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		*text = ch_strdup("authorization entry is alias");
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		*text = ch_strdup("authorization entry is referral");
		goto done;
	}

	{
		LDAPModList ml;
		struct berval *vals[2];

		vals[0] = cred;
		vals[1] = NULL;

		ml.ml_type = ch_strdup("userPassword");
		ml.ml_bvalues = vals;
		ml.ml_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
		ml.ml_next = NULL;

		rc = ldbm_modify_internal( be,
			conn, op, op->o_ndn, &ml, e );

		ch_free(ml.ml_type);
	}

	if( rc == LDAP_SUCCESS ) {
		/* change the entry itself */
		if( id2entry_add( be, e ) != 0 ) {
			rc = LDAP_OPERATIONS_ERROR;
		}
	}
	
done:
	cache_return_entry_w( &li->li_cache, e );

	if( cred != NULL ) {
		ber_bvfree( cred );
	}

	return rc;
}
