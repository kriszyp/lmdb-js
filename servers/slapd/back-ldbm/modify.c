/* modify.c - ldbm backend modify routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

/* We need this function because of LDAP modrdn. If we do not 
 * add this there would be a bunch of code replication here 
 * and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 */ 
int ldbm_modify_internal(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    Modifications	*modlist,
    Entry	*e,
	const char **text,
	char *textbuf,
	size_t textlen
)
{
	int rc = LDAP_SUCCESS;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;
	Attribute 	*ap;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY,  "ldbm_modify_internal: %s\n", dn, 0, 0 );
#else
	Debug(LDAP_DEBUG_TRACE, "ldbm_modify_internal: %s\n", dn, 0, 0);
#endif


	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_modify_internal: add\n", 0, 0, 0);
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: add\n", 0, 0, 0);
#endif

			rc = modify_add_values( e, mod, text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO, 
					"ldbm_modify_internal: failed %d (%s)\n", rc, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_DELETE:
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_modify_internal: delete\n", 0,0,0);
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: delete\n", 0, 0, 0);
#endif

			rc = modify_delete_values( e, mod, text, textbuf, textlen );
			assert( rc != LDAP_TYPE_OR_VALUE_EXISTS );
			if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO, 
					"ldbm_modify_internal: failed %d (%s)\n", rc, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_REPLACE:
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_modify_internal:  replace\n",0,0,0);
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: replace\n", 0, 0, 0);
#endif

			rc = modify_replace_values( e, mod, text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO, 
					"ldbm_modify_internal: failed %d (%s)\n", rc, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
#endif
			}
			break;

		case SLAP_MOD_SOFTADD:
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1, 
				"ldbm_modify_internal: softadd\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: softadd\n", 0, 0, 0);
#endif

			/* Avoid problems in index_add_mods()
			 * We need to add index if necessary.
			 */
			mod->sm_op = LDAP_MOD_ADD;

			rc = modify_add_values( e, mod, text, textbuf, textlen );
			if ( rc == LDAP_TYPE_OR_VALUE_EXISTS ) {
				rc = LDAP_SUCCESS;
			}

			if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO, 
					   "ldbm_modify_internal: failed %d (%s)\n", rc, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
#endif
			}
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_modify_internal: invalid op %d\n", mod->sm_op, 0, 0 );
#else
			Debug(LDAP_DEBUG_ANY, "ldbm_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
#endif

			rc = LDAP_OTHER;
			*text = "Invalid modify operation";
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_modify_internal: %d (%s)\n", rc, *text, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
				rc, *text, 0);
#endif
		}

		if ( rc != LDAP_SUCCESS ) {
			goto exit;
		}

		/* If objectClass was modified, reset the flags */
		if ( mod->sm_desc == slap_schema.si_ad_objectClass ) {
			e->e_ocflags = 0;
		}

		/* check if modified attribute was indexed */
		rc = index_is_indexed( be, mod->sm_desc );
		if ( rc == LDAP_SUCCESS ) {
			ap = attr_find( save_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXDEL;

			ap = attr_find( e->e_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXADD;
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( be, e, save_attrs, text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_modify_internal: entry failed schema check: %s\n", 
			*text, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "entry failed schema check: %s\n",
			*text, 0, 0 );
#endif

		goto exit;
	}

	/* check for abandon */
	if ( op->o_abandon ) {
		rc = SLAPD_ABANDON;
		goto exit;
	}

	/* update the indices of the modified attributes */

	/* start with deleting the old index entries */
	for ( ap = save_attrs; ap != NULL; ap = ap->a_next ) {
		if ( ap->a_flags & SLAP_ATTR_IXDEL ) {
			rc = index_values( be, ap->a_desc, ap->a_vals, e->e_id,
				  	   SLAP_INDEX_DELETE_OP );
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR,
					"ldbm_modify_internal: Attribute index delete failure\n",
					0, 0, 0	);
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index delete failure",
			               0, 0, 0 );
#endif
				goto exit;
			}
			ap->a_flags &= ~SLAP_ATTR_IXDEL;
		}
	}

	/* add the new index entries */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
		if ( ap->a_flags & SLAP_ATTR_IXADD ) {
			rc = index_values( be, ap->a_desc, ap->a_vals, e->e_id,
				  	   SLAP_INDEX_ADD_OP );
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR,
					"ldbm_modify_internal: Attribute index add failure\n",
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index add failure",
			               0, 0, 0 );
#endif
				goto exit;
			}
			ap->a_flags &= ~SLAP_ATTR_IXADD;
		}
	}

exit:
	if ( rc == LDAP_SUCCESS ) {
		attrs_free( save_attrs );
	} else {
		for ( ap = save_attrs; ap; ap = ap->a_next ) {
			ap->a_flags = 0;
		}
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
	}

	return rc;
}

int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval	*dn,
    struct berval	*ndn,
    Modifications	*modlist
)
{
	int rc;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );
	const char *text = NULL;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_modify: enter\n", 0, 0, 0);
#else
	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);
#endif

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	/* acquire and lock entry */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		BerVarray refs;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );
		free( matched_dn );

		return( -1 );
	}

    if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			   "ldbm_back_modify: entry (%s) is referral\n", ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif


		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );

		goto error_return;
	}
	
	/* Modify the entry */
	rc = ldbm_modify_internal( be, conn, op, ndn->bv_val, modlist, e,
		&text, textbuf, textlen );

	if( rc != LDAP_SUCCESS ) {
		if( rc != SLAPD_ABANDON ) {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
		}

		goto error_return;
	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "id2entry failure", NULL, NULL );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );

	cache_return_entry_w( &li->li_cache, e );
	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	return( 0 );

error_return:;
	cache_return_entry_w( &li->li_cache, e );
	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	return( -1 );
}
