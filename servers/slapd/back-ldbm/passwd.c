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
	LDAPControl *** rspctrls,
	char**	text
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	int rc;
	Entry *e = NULL;
	struct berval *hash = NULL;

	struct berval *id = NULL;
	struct berval *new = NULL;

	char *dn;

	assert( oid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, oid ) == 0 );

	rc = slap_passwd_parse( reqdata,
		&id, NULL, &new, text );

	Debug( LDAP_DEBUG_ARGS, "==> ldbm_back_exop_passwd: \"%s\"\n",
		id ? id->bv_val : "", 0, 0 );

	if( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if( new == NULL || new->bv_len == 0 ) {
		new = slap_passwd_generate();

		if( new == NULL || new->bv_len == 0 ) {
			*text = ch_strdup("password generation failed.");
			rc = LDAP_OPERATIONS_ERROR;
			goto done;
		}
		
		*rspdata = slap_passwd_return( new );
	}

	hash = slap_passwd_hash( new );

	if( hash == NULL || hash->bv_len == 0 ) {
		*text = ch_strdup("password hash failed");
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	dn = id ? id->bv_val : op->o_dn;

	Debug( LDAP_DEBUG_TRACE, "passwd: \"%s\"%s\n",
		dn, id ? " (proxy)" : "", 0 );

	if( dn == NULL || dn[0] == NULL ) {
		*text = ch_strdup("No password is associated with the Root DSE");
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	e = dn2entry_w( be, dn, NULL );

	if( e == NULL ) {
		*text = ch_strdup("could not locate authorization entry");
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
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

	rc = LDAP_OPERATIONS_ERROR;

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		*text = ch_strdup("authorization entry is referral");
		goto done;
	}

	{
		LDAPModList ml;
		struct berval *vals[2];

		vals[0] = hash;
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
	if( e != NULL ) {
		cache_return_entry_w( &li->li_cache, e );
	}

	if( id != NULL ) {
		ber_bvfree( id );
	}

	if( new != NULL ) {
		ber_bvfree( new );
	}

	if( hash != NULL ) {
		ber_bvfree( hash );
	}

	return rc;
}
