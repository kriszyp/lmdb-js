/* passwd.c - ldbm backend password routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"
#include "lber_pvt.h"

int
ldbm_back_exop_passwd(
	Operation	*op,
	SlapReply	*rs )
{
	struct ldbminfo *li = (struct ldbminfo *) op->o_bd->be_private;
	int rc;
	Entry *e = NULL;
	struct berval hash = { 0, NULL };

	struct berval id = { 0, NULL };
	struct berval new = { 0, NULL };

	struct berval dn = { 0, NULL };
	struct berval ndn = { 0, NULL };

	assert( ber_bvcmp( &slap_EXOP_MODIFY_PASSWD, &op->oq_extended.rs_reqoid ) == 0 );

	rc = slap_passwd_parse( op->oq_extended.rs_reqdata,
		&id, NULL, &new, &rs->sr_text );

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
			rs->sr_text = "password generation failed.";
			rc = LDAP_OTHER;
			goto done;
		}
		
		rs->sr_rspdata = slap_passwd_return( &new );
	}

	slap_passwd_hash( &new, &hash, &rs->sr_text );

	if( hash.bv_len == 0 ) {
		if( !rs->sr_text ) rs->sr_text = "password hash failed";
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
		rs->sr_text = "No password is associated with the Root DSE";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto done;
	}

	rc = dnNormalize( 0, NULL, NULL, &dn, &ndn, op->o_tmpmemctx );
	if( rc != LDAP_SUCCESS ) {
		rs->sr_text = "Invalid DN";
		goto done;
	}

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	e = dn2entry_w( op->o_bd, &ndn, NULL );

	if ( e == NULL || is_entry_glue( e )) {
		/* FIXME : dn2entry() should return non-glue entry */
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
		rs->sr_text = "could not locate authorization entry";
		rc = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

#ifdef LDBM_SUBENTRIES
	if( is_entry_subentry( e ) ) {
		/* entry is a subentry, don't allow operation */
		rs->sr_text = "authorization entry is subentry";
		rc = LDAP_OTHER;
		goto done;
	}
#endif

	if( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow operation */
		rs->sr_text = "authorization entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
		goto done;
	}

	rc = LDAP_OTHER;

	if( is_entry_referral( e ) ) {
		/* entry is an referral, don't allow operation */
		rs->sr_text = "authorization entry is referral";
		goto done;
	}

	{
		Modifications ml;
		struct berval vals[2];
		char textbuf[SLAP_TEXT_BUFLEN]; /* non-returnable */

		vals[0] = hash;
		vals[1].bv_val = NULL;

		ml.sml_desc = slap_schema.si_ad_userPassword;
		ml.sml_values = vals;
		ml.sml_nvalues = vals;
		ml.sml_op = LDAP_MOD_REPLACE;
		ml.sml_next = NULL;

		rc = ldbm_modify_internal( op,
			&ml, e, &rs->sr_text, textbuf, 
			sizeof( textbuf ) );

		/* FIXME: ldbm_modify_internal may set *text = textbuf,
		 * which is BAD */
		if ( rs->sr_text == textbuf ) {
			rs->sr_text = NULL;
		}

		if( rc ) {
			/* cannot return textbuf */
			rs->sr_text = "entry modify failed";
			goto done;
		}

		/* change the entry itself */
		if( id2entry_add( op->o_bd, e ) != 0 ) {
			rs->sr_text = "entry update failed";
			rc = LDAP_OTHER;
		}

		if( rc == LDAP_SUCCESS ) {
			replog( op );
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
		op->o_tmpfree( ndn.bv_val, op->o_tmpmemctx );
	}

	return rc;
}
