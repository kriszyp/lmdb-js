/* add.c - ldap ldbm back-end add routine */
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
ldbm_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct berval	pdn;
	Entry		*p = NULL;
	int			rc;
	ID               id = NOID;
	const char	*text = NULL;
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_add: %s\n", e->e_dn, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_add: %s\n", e->e_dn, 0, 0);
#endif

	rc = entry_schema_check( be, e, NULL, &text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_add: entry (%s) failed schema check.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry failed schema check: %s\n",
			text, 0, 0 );
#endif

		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		return( -1 );
	}

	if ( ! access_allowed( be, conn, op, e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_add: No write access to entry (%s).\n", 
			e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "no write access to entry\n", 0,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
		    NULL, "no write access to entry", NULL, NULL );

		return -1;
	}

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	if ( ( rc = dn2id( be, &e->e_nname, &id ) ) || id != NOID ) {
		/* if (rc) something bad happened to ldbm cache */
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
		send_ldap_result( conn, op, 
			rc ? LDAP_OTHER : LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		return( -1 );
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 * If the parent does not exist, only allow the "root" user to
	 * add the entry.
	 */

	if ( be_issuffix( be, &e->e_nname ) ) {
		pdn = slap_empty_bv;
	} else {
		dnParent( &e->e_nname, &pdn );
	}

	if( pdn.bv_len ) {
		Entry *matched = NULL;

		/* get parent with writer lock */
		if ( (p = dn2entry_w( be, &pdn, &matched )) == NULL ) {
			char *matched_dn = NULL;
			BerVarray refs;

			if ( matched != NULL ) {
				matched_dn = ch_strdup( matched->e_dn );
				refs = is_entry_referral( matched )
					? get_entry_referrals( be, conn, op, matched )
					: NULL;
				cache_return_entry_r( &li->li_cache, matched );

			} else {
				refs = referral_rewrite( default_referral,
					NULL, &e->e_name, LDAP_SCOPE_DEFAULT );
			}

			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_add: Parent of (%s) does not exist.\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_REFERRAL, matched_dn,
				refs == NULL ? "parent does not exist" : "parent is referral",
				refs, NULL );

			ber_bvarray_free( refs );
			free( matched_dn );

			return -1;
		}

		if ( ! access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE, NULL ) )
		{
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_add: No write access to parent (%s).\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "no write access to parent\n", 0,
			    0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    NULL, "no write access to parent", NULL, NULL );

			return -1;
		}

		if ( is_entry_alias( p ) ) {
			/* parent is an alias, don't allow add */

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
			LDAP_LOG(BACK_LDBM, ERR, 
				"ldbm_back_add:  Parent is an alias.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "parent is alias\n", 0,
			    0, 0 );
#endif


			send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM,
			    NULL, "parent is an alias", NULL, NULL );

			return -1;
		}

		if ( is_entry_referral( p ) ) {
			/* parent is a referral, don't allow add */
			char *matched_dn = ch_strdup( p->e_dn );
			BerVarray refs = is_entry_referral( p )
				? get_entry_referrals( be, conn, op, p )
				: NULL;

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR,
				   "ldbm_back_add: Parent is referral.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "parent is referral\n", 0,
			    0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_REFERRAL,
			    matched_dn, NULL, refs, NULL );

			ber_bvarray_free( refs );
			free( matched_dn );
			return -1;
		}

	} else {
		if(pdn.bv_val != NULL) {
			assert( *pdn.bv_val == '\0' );
		}

		/* no parent, must be adding entry to root */
		if ( !be_isroot( be, &op->o_ndn ) ) {
			if ( be_issuffix( be, (struct berval *)&slap_empty_bv ) || be_isupdate( be, &op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;
				
				rc = access_allowed( be, conn, op, p,
					children, NULL, ACL_WRITE, NULL );
				p = NULL;
				
				if ( ! rc ) {
					ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_add: No write "
						"access to parent (\"\").\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE, 
						"no write access to parent\n", 
						0, 0, 0 );
#endif

					send_ldap_result( conn, op, 
						LDAP_INSUFFICIENT_ACCESS,
			    			NULL, 
						"no write access to parent", 
						NULL, NULL );

					return -1;
				}

			} else {
				ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR,
					   "ldbm_back_add: %s add denied.\n",
					   pdn.bv_val == NULL ? "suffix" 
					   : "entry at root", 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "%s add denied\n",
						pdn.bv_val == NULL ? "suffix" 
						: "entry at root", 0, 0 );
#endif

				send_ldap_result( conn, op, 
						LDAP_INSUFFICIENT_ACCESS,
			  			NULL, NULL, NULL, NULL );

				return -1;
			}
		}
	}

	if ( next_id( be, &e->e_id ) ) {
		if( p != NULL) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR,
			"ldbm_back_add: next_id failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ldbm_add: next_id failed\n",
			0, 0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "next_id add failed", NULL, NULL );

		return( -1 );
	}

	/*
	 * Try to add the entry to the cache, assign it a new dnid.
	 */
	rc = cache_add_entry_rw(&li->li_cache, e, CACHE_WRITE_LOCK);

	if ( rc != 0 ) {
		if( p != NULL) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR,
			"ldbm_back_add: cache_add_entry_lock failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );
#endif

		send_ldap_result( conn, op,
			rc > 0 ? LDAP_ALREADY_EXISTS : LDAP_OTHER,
			NULL, rc > 0 ? NULL : "cache add failed", NULL, NULL );

		return( -1 );
	}

	rc = -1;

	/* attribute indexes */
	if ( index_entry_add( be, e, e->e_attrs ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR,
			"ldbm_back_add: index_entry_add failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "index_entry_add failed\n", 0,
		    0, 0 );
#endif
		
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "index generation failed", NULL, NULL );

		goto return_results;
	}

	/* dn2id index */
	if ( dn2id_add( be, &e->e_nname, e->e_id ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR,
			"ldbm_back_add: dn2id_add failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "dn2id_add failed\n", 0,
		    0, 0 );
#endif
		/* FIXME: delete attr indices? */

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index generation failed", NULL, NULL );

		goto return_results;
	}

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR,
			   "ldbm_back_add: id2entry_add failed.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "id2entry_add failed\n", 0,
		    0, 0 );
#endif

		/* FIXME: delete attr indices? */
		(void) dn2id_delete( be, &e->e_nname, e->e_id );
		
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "entry store failed", NULL, NULL );

		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );

	/* marks the entry as committed, so it is added to the cache;
	 * otherwise it is removed from the cache, but not destroyed;
	 * it will be destroyed by the caller */
	rc = 0;
	cache_entry_commit( e );

return_results:;
	if (p != NULL) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p ); 
	}

	if ( rc ) {
		/*
		 * in case of error, writer lock is freed 
		 * and entry's private data is destroyed.
		 * otherwise, this is done when entry is released
		 */
		cache_return_entry_w( &li->li_cache, e );
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	}

	return( rc );
}
