/* passwd.c - bdb backend password routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_exop_passwd(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
	const char		*reqoid,
    struct berval	*reqdata,
	char			**rspoid,
    struct berval	**rspdata,
	LDAPControl		*** rspctrls,
	const char		**text,
    struct berval	*** refs
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	Entry *e = NULL;
	struct berval *hash = NULL;
	DB_TXN *ltid;

	struct berval *id = NULL;
	struct berval *new = NULL;

	char *dn;

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, reqoid ) == 0 );

	rc = slap_passwd_parse( reqdata,
		&id, NULL, &new, text );

	Debug( LDAP_DEBUG_ARGS, "==> bdb_exop_passwd: \"%s\"\n",
		id ? id->bv_val : "", 0, 0 );

	if( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if( new == NULL || new->bv_len == 0 ) {
		new = slap_passwd_generate();

		if( new == NULL || new->bv_len == 0 ) {
			*text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		*rspdata = slap_passwd_return( new );
	}

	hash = slap_passwd_hash( new );

	if( hash == NULL || hash->bv_len == 0 ) {
		*text = "password hash failed";
		rc = LDAP_OTHER;
		goto done;
	}

	dn = id ? id->bv_val : op->o_dn;

	Debug( LDAP_DEBUG_TRACE, "passwd: \"%s\"%s\n",
		dn, id ? " (proxy)" : "", 0 );

	if( dn == NULL || dn[0] == '\0' ) {
		*text = "No password is associated with the Root DSE";
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	/* fetch entry */
	rc = dn2entry_w( be, NULL, dn, &e, NULL );

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
		    NULL, "internal error", NULL, NULL );
		return rc;
	}

	if( e == NULL ) {
		*text = "could not locate authorization entry";
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		*text = "authorization entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}

	rc = LDAP_OPERATIONS_ERROR;

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		*text = "authorization entry is referral";
		goto done;
	}

	{
		Modifications ml;
		struct berval *vals[2];

		vals[0] = hash;
		vals[1] = NULL;

		ml.sml_desc = slap_schema.si_ad_userPassword;
		ml.sml_bvalues = vals;
		ml.sml_op = LDAP_MOD_REPLACE;
		ml.sml_next = NULL;

		rc = bdb_modify_internal( be,
			conn, op, op->o_ndn, &ml, e, text );

	}

	if( rc == LDAP_SUCCESS ) {
		/* change the entry itself */
		if( bdb_id2entry_add( be, ltid, e ) != 0 ) {
			*text = "entry update failed";
			rc = LDAP_OTHER;
		}
	}
	
done:
	if( e != NULL ) {
		bdb_entry_return( be, e );
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
