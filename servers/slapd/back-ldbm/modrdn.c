/* modrdn.c - ldbm backend modrdn routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_modrdn(
    Operation	*op,
    SlapReply	*rs )
{
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	struct berval	p_dn, p_ndn;
	struct berval	new_dn = BER_BVNULL, new_ndn = BER_BVNULL;
	struct berval	old_ndn = BER_BVNULL;
	Entry		*e, *p = NULL;
	Entry		*matched;
	/* LDAP v2 supporting correct attribute handling. */
	LDAPRDN		new_rdn = NULL;
	LDAPRDN		old_rdn = NULL;
	int		isroot = -1;
	int 		rc_id = 0;
	ID              id = NOID;
	const char	*text = NULL;
	char		textbuf[SLAP_TEXT_BUFLEN];
	size_t		textlen = sizeof textbuf;
	/* Added to support newSuperior */ 
	Entry		*np = NULL;	/* newSuperior Entry */
	struct berval	*np_ndn = NULL; /* newSuperior ndn */
	struct berval	*new_parent_dn = NULL;	/* np_dn, p_dn, or NULL */
	/* Used to interface with ldbm_modify_internal() */
	Modifications	*mod = NULL;		/* Used to delete old/add new rdn */
	int		manageDSAit = get_manageDSAit( op );

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		"ldbm_back_modrdn: dn: %s newSuperior=%s\n", 
		op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "NULL",
		( op->oq_modrdn.rs_newSup && op->oq_modrdn.rs_newSup->bv_len ) ? op->oq_modrdn.rs_newSup->bv_val : "NULL",0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"==>ldbm_back_modrdn: dn: %s newSuperior=%s\n", 
		op->o_req_dn.bv_len ? op->o_req_dn.bv_val : "NULL",
		( op->oq_modrdn.rs_newSup && op->oq_modrdn.rs_newSup->bv_len )
			? op->oq_modrdn.rs_newSup->bv_val : "NULL", 0 );
#endif

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	e = dn2entry_w( op->o_bd, &op->o_req_ndn, &matched );

	/* get entry with writer lock */
	/* FIXME: dn2entry() should return non-glue entry */
	if (( e == NULL  ) || ( !manageDSAit && e && is_entry_glue( e ))) {
		if ( matched != NULL ) {
			rs->sr_matched = strdup( matched->e_dn );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			BerVarray deref = NULL;
			if ( !LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
				syncinfo_t *si;
				LDAP_STAILQ_FOREACH( si, &op->o_bd->be_syncinfo, si_next ) {
					struct berval tmpbv;
					ber_dupbv( &tmpbv, &si->si_provideruri_bv[0] );
					ber_bvarray_add( &deref, &tmpbv );
				}
			} else {
				deref = default_referral;
			}
			rs->sr_ref = referral_rewrite( deref, NULL, &op->o_req_dn,
							LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		return rs->sr_err;
	}

	/* check entry for "entry" acl */
	if ( ! access_allowed( op, e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_modrdn: no write access to entry of (%s)\n", 
			op->o_req_dn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- ldbm_back_modrdn: no write access to entry\n", 0,
			0, 0 );
#endif

		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
			"no write access to entry" );

		goto return_results;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_modrdn: entry %s is a referral\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s is referral\n", e->e_dn,
		    0, 0 );
#endif

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		goto return_results;
	}

	if ( has_children( op->o_bd, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_modrdn: entry %s has children\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry %s has children\n", e->e_dn,
		    0, 0 );
#endif

		send_ldap_error( op, rs, LDAP_NOT_ALLOWED_ON_NONLEAF,
		    "subtree rename not supported" );
		goto return_results;
	}

	if ( be_issuffix( op->o_bd, &e->e_nname ) ) {
		p_ndn = slap_empty_bv ;
	} else {
		dnParent( &e->e_nname, &p_ndn );
	}

	if ( p_ndn.bv_len != 0 ) {
		/* Make sure parent entry exist and we can write its 
		 * children.
		 */

		if( (p = dn2entry_w( op->o_bd, &p_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_back_modrdn: parent of %s does not exist\n", 
				e->e_ndn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0);
#endif

			send_ldap_error( op, rs, LDAP_OTHER,
				"parent entry does not exist" );

			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( op, p,
			children, NULL, ACL_WRITE, NULL ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, 
				"ldbm_back_modrdn: no access to parent of (%s)\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
				NULL );
			goto return_results;
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_modrdn: wr to children of entry %s OK\n", 
			p_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: wr to children of entry %s OK\n",
		       p_ndn.bv_val, 0, 0 );
#endif

		if ( p_ndn.bv_val == slap_empty_bv.bv_val ) {
			p_dn = slap_empty_bv;
		} else {
			dnParent( &e->e_name, &p_dn );
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			   "ldbm_back_modrdn: parent dn=%s\n", p_dn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: parent dn=%s\n",
		       p_dn.bv_val, 0, 0 );
#endif

	} else {
		/* no parent, must be root to modify rdn */
		isroot = be_isroot( op );
		if ( ! isroot ) {
			if ( be_issuffix( op->o_bd, (struct berval *)&slap_empty_bv ) || be_isupdate( op ) ) {
				int	can_access;
				p = (Entry *)&slap_entry_root;
				
				can_access = access_allowed( op, p,
						children, NULL, ACL_WRITE, NULL );
				p = NULL;
								
				/* check parent for "children" acl */
				if ( ! can_access ) {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_modrdn: no access to parent \"\"\n", 0,0,0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_modrdn: no "
						"access to parent\n", 0, 0, 0 );
#endif

					send_ldap_error( op, rs,
						LDAP_INSUFFICIENT_ACCESS,
						NULL );
					goto return_results;
				}

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_modrdn: (%s) has no parent & not a root.\n", 
					op->o_ndn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"<=- ldbm_back_modrdn: no parent & "
					"not root\n", 0, 0, 0);
#endif

				send_ldap_error( op, rs,
					LDAP_INSUFFICIENT_ACCESS,
					NULL );
				goto return_results;
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
		   "ldbm_back_modrdn: (%s) no parent, locked root.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		       "ldbm_back_modrdn: no parent, locked root\n",
		       0, 0, 0 );
#endif
	}

	new_parent_dn = &p_dn;	/* New Parent unless newSuperior given */

	if ( op->oq_modrdn.rs_newSup != NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1, 
			"ldbm_back_modrdn: new parent \"%s\" requested\n",
			op->oq_modrdn.rs_newSup->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, 
			"ldbm_back_modrdn: new parent \"%s\" requested...\n",
			op->oq_modrdn.rs_newSup->bv_val, 0, 0 );
#endif

		np_ndn = op->oq_modrdn.rs_nnewSup;

		/* newSuperior == oldParent? */
		if ( dn_match( &p_ndn, np_ndn ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, INFO, "ldbm_back_modrdn: "
				"new parent\"%s\" seems to be the same as the "
				"old parent \"%s\"\n", op->oq_modrdn.rs_newSup->bv_val, p_dn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: "
				"new parent\"%s\" seems to be the same as the "
				"old parent \"%s\"\n",
				op->oq_modrdn.rs_newSup->bv_val, p_dn.bv_val, 0 );
#endif

			op->oq_modrdn.rs_newSup = NULL; /* ignore newSuperior */
		}
	}

	if ( op->oq_modrdn.rs_newSup != NULL ) {
		/* newSuperior == entry being moved?, if so ==> ERROR */
		/* Get Entry with dn=newSuperior. Does newSuperior exist? */

		if ( op->oq_modrdn.rs_nnewSup->bv_len ) {
			if( (np = dn2entry_w( op->o_bd, np_ndn, NULL )) == NULL) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_modrdn: newSup(ndn=%s) not found.\n", 
					np_ndn->bv_val, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
				    "ldbm_back_modrdn: newSup(ndn=%s) not here!\n",
				    np_ndn->bv_val, 0, 0);
#endif

				send_ldap_error( op, rs, LDAP_OTHER,
					"newSuperior not found" );
				goto return_results;
			}

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1,
				"ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
				(void *) np, np->e_id, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: wr to new parent OK np=%p, id=%ld\n",
				(void *) np, np->e_id, 0 );
#endif

			/* check newSuperior for "children" acl */
			if ( !access_allowed( op, np, children, NULL,
					      ACL_WRITE, NULL ) )
			{
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
				   "ldbm_back_modrdn: no wr to newSup children.\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
				       "ldbm_back_modrdn: no wr to newSup children\n",
				       0, 0, 0 );
#endif

				send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
				goto return_results;
			}

			if ( is_entry_alias( np ) ) {
				/* parent is an alias, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
				   "ldbm_back_modrdn: entry (%s) is an alias.\n", np->e_dn,0,0);
#else
				Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0, 0, 0 );
#endif


				send_ldap_error( op, rs, LDAP_ALIAS_PROBLEM,
				    "newSuperior is an alias" );

				goto return_results;
			}

			if ( is_entry_referral( np ) ) {
				/* parent is a referral, don't allow add */
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, INFO,
					"ldbm_back_modrdn: entry (%s) is a referral\n",
					np->e_dn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "entry (%s) is referral\n",
					np->e_dn, 0, 0 );
#endif

				send_ldap_error( op, rs, LDAP_OTHER,
				    "newSuperior is a referral" );

				goto return_results;
			}

		} else {

			/* no parent, must be root to modify newSuperior */
			if ( isroot == -1 ) {
				isroot = be_isroot( op );
			}

			if ( ! isroot ) {
				if ( be_issuffix( op->o_bd, (struct berval *)&slap_empty_bv ) || be_isupdate( op ) ) {
					int	can_access;
					np = (Entry *)&slap_entry_root;
				
					can_access = access_allowed( op, np,
							children, NULL, ACL_WRITE, NULL );
					np = NULL;
								
					/* check parent for "children" acl */
					if ( ! can_access ) {
#ifdef NEW_LOGGING
						LDAP_LOG( BACK_LDBM, ERR,
							"ldbm_back_modrdn: no access "
							"to new superior \"\"\n", 0, 0, 0 );
#else
						Debug( LDAP_DEBUG_TRACE,
							"<=- ldbm_back_modrdn: no "
							"access to new superior\n", 0, 0, 0 );
#endif

						send_ldap_error( op, rs,
							LDAP_INSUFFICIENT_ACCESS,
							NULL );
						goto return_results;
					}

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_modrdn: \"\" not allowed as new superior\n",
						0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_modrdn: \"\" "
						"not allowed as new superior\n", 
						0, 0, 0);
#endif

					send_ldap_error( op, rs,
						LDAP_INSUFFICIENT_ACCESS,
						NULL );
					goto return_results;
				}
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1,
			"ldbm_back_modrdn: wr to new parent's children OK.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		    "ldbm_back_modrdn: wr to new parent's children OK\n",
		    0, 0, 0 );
#endif

		new_parent_dn = op->oq_modrdn.rs_newSup;
	}
	
	/* Build target dn and make sure target entry doesn't exist already. */
	build_new_dn( &new_dn, new_parent_dn, &op->oq_modrdn.rs_newrdn, NULL ); 
	dnNormalize( 0, NULL, NULL, &new_dn, &new_ndn, NULL );

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_back_modrdn: new ndn=%s\n", 
		new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: new ndn=%s\n",
	    new_ndn.bv_val, 0, 0 );
#endif

	/* check for abandon */
	if ( op->o_abandon ) {
		goto return_results;
	}

	if ( ( rc_id = dn2id ( op->o_bd, &new_ndn, &id ) ) || id != NOID ) {
		/* if (rc_id) something bad happened to ldbm cache */
		rs->sr_err = rc_id ? LDAP_OTHER : LDAP_ALREADY_EXISTS;
		send_ldap_result( op, rs );
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, INFO, "ldbm_back_modrdn: new ndn (%s) does not exist\n",
		new_ndn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	    "ldbm_back_modrdn: new ndn=%s does not exist\n",
	    new_ndn.bv_val, 0, 0 );
#endif

	/* Get attribute type and attribute value of our new rdn, we will
	 * need to add that to our new entry
	 */
	if ( ldap_bv2rdn( &op->oq_modrdn.rs_newrdn, &new_rdn, (char **)&rs->sr_text,
		LDAP_DN_FORMAT_LDAP ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"ldbm_back_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldbm_back_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX,
				    "unknown type(s) used in RDN" );
		goto return_results;		
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"ldbm_back_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ]->la_attr.bv_val, 
		new_rdn[ 0 ]->la_value.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldbm_back_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ]->la_attr.bv_val,
		new_rdn[ 0 ]->la_value.bv_val, 0 );
#endif

	if ( op->oq_modrdn.rs_deleteoldrdn ) {
		if ( ldap_bv2rdn( &op->o_req_dn, &old_rdn, (char **)&rs->sr_text,
			LDAP_DN_FORMAT_LDAP ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"ldbm_back_modrdn: can't figure out "
				"type(s)/values(s) of old_rdn\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_back_modrdn: can't figure out "
				"the old_rdn type(s)/value(s)\n", 
				0, 0, 0 );
#endif
			send_ldap_error( op, rs, LDAP_OTHER,
				    "cannot parse RDN from old DN" );
			goto return_results;		
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_back_modrdn:  DN_X500\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_modrdn: DN_X500\n",
	       0, 0, 0 );
#endif
	
	if ( slap_modrdn2mods( op, rs, e, old_rdn, new_rdn, &mod ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto return_results;
	}

	/* check for abandon */
	if ( op->o_abandon ) {
		goto return_results;
	}

	(void) cache_delete_entry( &li->li_cache, e );

	free( e->e_dn );
	old_ndn = e->e_nname;
	e->e_name = new_dn;
	e->e_nname = new_ndn;
	new_dn.bv_val = NULL;
	new_ndn.bv_val = NULL;

	/* NOTE: after this you must not free new_dn or new_ndn!
	 * They are used by cache.
	 */

	/* modify memory copy of entry */
	rs->sr_err = ldbm_modify_internal( op, &mod[0], e,
		&rs->sr_text, textbuf, textlen );
	switch ( rs->sr_err ) {
	case LDAP_SUCCESS:
		break;

	default:
		send_ldap_result( op, rs );
		/* FALLTHRU */
	case SLAPD_ABANDON:
    		goto return_results;
	}
	
	/*
	 * NOTE: the backend MUST delete then add the entry,
	 *		otherwise indexing may get hosed
	 * FIXME: if a new ID was used, the add could be done first.
	 *		that would be safer.
	 */

	/* delete old one */
	if ( dn2id_delete( op->o_bd, &old_ndn, e->e_id ) != 0 ) {
		send_ldap_error( op, rs, LDAP_OTHER,
			"DN index delete fail" );
		goto return_results;
	}

	/* add new one */
	if ( dn2id_add( op->o_bd, &e->e_nname, e->e_id ) != 0 ) {
		/* try to repair old entry - probably hopeless */
        if( dn2id_add( op->o_bd, &old_ndn, e->e_id) != 0 ) {
			send_ldap_error( op, rs, LDAP_OTHER,
				"DN index add and repair failed" );
		} else {
			send_ldap_error( op, rs, LDAP_OTHER,
				"DN index add failed" );
		}
		goto return_results;
	}

	/* id2entry index */
	if ( id2entry_add( op->o_bd, e ) != 0 ) {
		/* Try to undo */
		int rc;
		rc = dn2id_delete( op->o_bd, &e->e_nname, e->e_id );
		rc |= dn2id_add( op->o_bd, &old_ndn, e->e_id );
		if( rc ) {
			send_ldap_error( op, rs, LDAP_OTHER,
				"entry update and repair failed" );
		} else {
			send_ldap_error( op, rs, LDAP_OTHER,
				"entry update failed" );
		}
		goto return_results;
	}

	(void) cache_update_entry( &li->li_cache, e );

	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;
	send_ldap_result( op, rs );
	cache_entry_commit( e );

return_results:
	if( new_dn.bv_val != NULL ) free( new_dn.bv_val );
	if( new_ndn.bv_val != NULL ) free( new_ndn.bv_val );
	if( old_ndn.bv_val != NULL ) free( old_ndn.bv_val );

	/* LDAP v2 supporting correct attribute handling. */
	if ( new_rdn != NULL ) {
		ldap_rdnfree( new_rdn );
	}
	if ( old_rdn != NULL ) {
		ldap_rdnfree( old_rdn );
	}
	if ( mod != NULL ) {
		Modifications *tmp;
		for (; mod; mod = tmp ) {
			/* slap_modrdn2mods does things one way,
			 * slap_mods_opattrs does it differently
			 */
			if ( mod->sml_op != SLAP_MOD_SOFTADD &&
				mod->sml_op != LDAP_MOD_DELETE ) break;
			if ( mod->sml_nvalues ) free( mod->sml_nvalues[0].bv_val );
			tmp = mod->sml_next;
			free( mod );
		}
		slap_mods_free( mod );
	}

	/* LDAP v3 Support */
	if( np != NULL ) {
		/* free new parent and writer lock */
		cache_return_entry_w( &li->li_cache, np );
	}

	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	rs->sr_text = NULL;
	return( rs->sr_err );
}
