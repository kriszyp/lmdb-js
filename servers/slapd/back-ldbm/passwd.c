/* passwd.c - ldbm backend password routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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
	const char		*reqoid,
    struct berval	*reqdata,
	char			**rspoid,
    struct berval	**rspdata,
	LDAPControl		*** rspctrls,
	const char		**text,
    BerVarray *refs
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	int rc;
	Entry *e = NULL;
	struct berval hash = { 0, NULL };

	struct berval id = { 0, NULL };
	struct berval new = { 0, NULL };

	struct berval dn;
	struct berval ndn;

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_MODIFY_PASSWD, reqoid ) == 0 );

	rc = slap_passwd_parse( reqdata,
		&id, NULL, &new, text );

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY,
		   "ldbm_back_exop_passwd: \"%s\"\n", id.bv_val ? id.bv_val : "", 0,0 );
#else
	Debug( LDAP_DEBUG_ARGS, "==> ldbm_back_exop_passwd: \"%s\"\n",
		id.bv_val ? id.bv_val : "", 0, 0 );
#endif


	if( rc != LDAP_SUCCESS ) {
		goto done;
	}

	if( new.bv_len == 0 ) {
		slap_passwd_generate(&new);

		if( new.bv_len == 0 ) {
			*text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		*rspdata = slap_passwd_return( &new );
	}

	slap_passwd_hash( &new, &hash );

	if( hash.bv_len == 0 ) {
		*text = "password hash failed";
		rc = LDAP_OTHER;
		goto done;
	}

	if( id.bv_len ) {
		dn = id;
	} else {
		dn = op->o_dn;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1,
		"ldbm_back_exop_passwd: \"%s\"%s\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "passwd: \"%s\"%s\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#endif

	if( dn.bv_len == 0 ) {
		*text = "No password is associated with the Root DSE";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto done;
	}

	rc = dnNormalize2( NULL, &dn, &ndn );
	if( rc != LDAP_SUCCESS ) {
		*text = "Invalid DN";
		goto done;
	}

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	e = dn2entry_w( be, &ndn, NULL );
	if( e == NULL ) {
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
		*text = "could not locate authorization entry";
		rc = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		*text = "authorization entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}

	rc = LDAP_OTHER;

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		*text = "authorization entry is referral";
		goto done;
	}

	{
		Modifications ml;
		struct berval vals[2];
		char textbuf[SLAP_TEXT_BUFLEN]; /* non-returnable */

		vals[0] = hash;
		vals[1].bv_val = NULL;

		ml.sml_desc = slap_schema.si_ad_userPassword;
		ml.sml_bvalues = vals;
		ml.sml_op = LDAP_MOD_REPLACE;
		ml.sml_next = NULL;

		rc = ldbm_modify_internal( be,
			conn, op, op->o_ndn.bv_val, &ml, e, text, textbuf, 
			sizeof( textbuf ) );

		/* FIXME: ldbm_modify_internal may set *text = textbuf,
		 * which is BAD */
		if ( *text == textbuf ) {
			*text = NULL;
		}

		if( rc ) {
			/* cannot return textbuf */
			*text = "entry modify failed";
			goto done;
		}

		/* change the entry itself */
		if( id2entry_add( be, e ) != 0 ) {
			*text = "entry update failed";
			rc = LDAP_OTHER;
		}

		if( rc == LDAP_SUCCESS ) {
			replog( be, op, &e->e_name, &e->e_nname, &ml );
		}
	}

done:
	if( e != NULL ) {
		cache_return_entry_w( &li->li_cache, e );
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	}

	if( hash.bv_val != NULL ) {
		free( hash.bv_val );
	}

	if( ndn.bv_val != NULL ) {
		free( ndn.bv_val );
	}

	return rc;
}
