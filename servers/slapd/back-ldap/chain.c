/* chain.c - chain LDAP operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2006 The OpenLDAP Foundation.
 * Portions Copyright 2003 Howard Chu.
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
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software.
 * This work was subsequently modified by Pierangelo Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

#include "config.h"

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
#define SLAP_CHAINING_DEFAULT				LDAP_CHAINING_PREFERRED
#define SLAP_CH_RESOLVE_SHIFT				SLAP_CONTROL_SHIFT
#define SLAP_CH_RESOLVE_MASK				(0x3 << SLAP_CH_RESOLVE_SHIFT)
#define SLAP_CH_RESOLVE_CHAINING_PREFERRED		(LDAP_CHAINING_PREFERRED << SLAP_CH_RESOLVE_SHIFT)
#define SLAP_CH_RESOLVE_CHAINING_REQUIRED		(LDAP_CHAINING_REQUIRED << SLAP_CH_RESOLVE_SHIFT)
#define SLAP_CH_RESOLVE_REFERRALS_PREFERRED		(LDAP_REFERRALS_PREFERRED << SLAP_CH_RESOLVE_SHIFT)
#define SLAP_CH_RESOLVE_REFERRALS_REQUIRED		(LDAP_REFERRALS_REQUIRED << SLAP_CH_RESOLVE_SHIFT)
#define SLAP_CH_RESOLVE_DEFAULT				(SLAP_CHAINING_DEFAULT << SLAP_CH_RESOLVE_SHIFT)
#define	SLAP_CH_CONTINUATION_SHIFT			(SLAP_CH_RESOLVE_SHIFT + 2)
#define SLAP_CH_CONTINUATION_MASK			(0x3 << SLAP_CH_CONTINUATION_SHIFT)
#define SLAP_CH_CONTINUATION_CHAINING_PREFERRED		(LDAP_CHAINING_PREFERRED << SLAP_CH_CONTINUATION_SHIFT)
#define SLAP_CH_CONTINUATION_CHAINING_REQUIRED		(LDAP_CHAINING_REQUIRED << SLAP_CH_CONTINUATION_SHIFT)
#define SLAP_CH_CONTINUATION_REFERRALS_PREFERRED	(LDAP_REFERRALS_PREFERRED << SLAP_CH_CONTINUATION_SHIFT)
#define SLAP_CH_CONTINUATION_REFERRALS_REQUIRED		(LDAP_REFERRALS_REQUIRED << SLAP_CH_CONTINUATION_SHIFT)
#define SLAP_CH_CONTINUATION_DEFAULT			(SLAP_CHAINING_DEFAULT << SLAP_CH_CONTINUATION_SHIFT)

#define o_chaining			o_ctrlflag[sc_chainingBehavior]
#define get_chaining(op)		((op)->o_chaining & SLAP_CONTROL_MASK)
#define get_chainingBehavior(op)	((op)->o_chaining & (SLAP_CH_RESOLVE_MASK|SLAP_CH_CONTINUATION_MASK))
#define get_resolveBehavior(op)		((op)->o_chaining & SLAP_CH_RESOLVE_MASK)
#define get_continuationBehavior(op)	((op)->o_chaining & SLAP_CH_CONTINUATION_MASK)

static int		sc_chainingBehavior;
#endif /*  LDAP_CONTROL_X_CHAINING_BEHAVIOR */

#define	LDAP_CH_NONE			((void *)(0))
#define	LDAP_CH_RES			((void *)(1))
#define LDAP_CH_ERR			((void *)(2))

static BackendInfo	*lback;

typedef struct ldap_chain_t {
	/*
	 * A "template" ldapinfo_t gets all common configuration items;
	 * then, for each configured URI, an entry is created in the tree;
	 * all the specific configuration items get in the current URI 
	 * structure.
	 *
 	 * Then, for each referral, extract the URI and lookup the
	 * related structure.  If configured to do so, allow URIs
	 * not found in the structure to create a temporary one
	 * that chains anonymously; maybe it can also be added to 
	 * the tree?  Should be all configurable.
	 */

	/* "common" configuration info (anything occurring before an "uri") */
	ldapinfo_t		*lc_common_li;

	/* current configuration info */
	ldapinfo_t		*lc_cfg_li;

	/* tree of configured[/generated?] "uri" info */
	ldap_avl_info_t		lc_lai;

	unsigned		lc_flags;
#define LDAP_CHAIN_F_NONE		(0x00U)
#define	LDAP_CHAIN_F_CHAINING		(0x01U)
#define	LDAP_CHAIN_F_CACHE_URI		(0x10U)

#define	LDAP_CHAIN_CHAINING( lc )	( ( (lc)->lc_flags & LDAP_CHAIN_F_CHAINING ) == LDAP_CHAIN_F_CHAINING )
#define	LDAP_CHAIN_CACHE_URI( lc )	( ( (lc)->lc_flags & LDAP_CHAIN_F_CACHE_URI ) == LDAP_CHAIN_F_CACHE_URI )

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	LDAPControl		lc_chaining_ctrl;
	char			lc_chaining_ctrlflag;
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
} ldap_chain_t;

static int ldap_chain_db_init_common( BackendDB	*be );
static int ldap_chain_db_init_one( BackendDB *be );
#define	ldap_chain_db_open_one(be)	(lback)->bi_db_open( (be) )
#define	ldap_chain_db_close_one(be)	(0)
#define	ldap_chain_db_destroy_one(be)	(lback)->bi_db_destroy( (be) )

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
static int
chaining_control_add(
		ldap_chain_t	*lc,
		Operation 	*op, 
		LDAPControl	***oldctrlsp )
{
	LDAPControl	**ctrls = NULL;
	int		c = 0;

	*oldctrlsp = op->o_ctrls;

	/* default chaining control not defined */
	if ( !LDAP_CHAIN_CHAINING( lc ) ) {
		return 0;
	}

	/* already present */
	if ( get_chaining( op ) > SLAP_CONTROL_IGNORED ) {
		return 0;
	}

	/* FIXME: check other incompatibilities */

	/* add to other controls */
	if ( op->o_ctrls ) {
		for ( c = 0; op->o_ctrls[ c ]; c++ )
			/* count them */ ;
	}

	ctrls = ch_calloc( sizeof( LDAPControl *), c + 2 );
	ctrls[ 0 ] = &lc->lc_chaining_ctrl;
	if ( op->o_ctrls ) {
		for ( c = 0; op->o_ctrls[ c ]; c++ ) {
			ctrls[ c + 1 ] = op->o_ctrls[ c ];
		}
	}
	ctrls[ c + 1 ] = NULL;

	op->o_ctrls = ctrls;

	op->o_chaining = lc->lc_chaining_ctrlflag;

	return 0;
}

static int
chaining_control_remove(
		Operation 	*op, 
		LDAPControl	***oldctrlsp )
{
	LDAPControl	**oldctrls = *oldctrlsp;

	/* we assume that the first control is the chaining control
	 * added by the chain overlay, so it's the only one we explicitly 
	 * free */
	if ( op->o_ctrls != oldctrls ) {
		assert( op->o_ctrls != NULL );
		assert( op->o_ctrls[ 0 ] != NULL );

		free( op->o_ctrls );

		op->o_chaining = 0;
		op->o_ctrls = oldctrls;
	} 

	*oldctrlsp = NULL;

	return 0;
}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

static int
ldap_chain_uri_cmp( const void *c1, const void *c2 )
{
	const ldapinfo_t	*li1 = (const ldapinfo_t *)c1;
	const ldapinfo_t	*li2 = (const ldapinfo_t *)c2;

	assert( li1->li_bvuri != NULL );
	assert( !BER_BVISNULL( &li1->li_bvuri[ 0 ] ) );
	assert( BER_BVISNULL( &li1->li_bvuri[ 1 ] ) );

	assert( li2->li_bvuri != NULL );
	assert( !BER_BVISNULL( &li2->li_bvuri[ 0 ] ) );
	assert( BER_BVISNULL( &li2->li_bvuri[ 1 ] ) );

	/* If local DNs don't match, it is definitely not a match */
	return ber_bvcmp( &li1->li_bvuri[ 0 ], &li2->li_bvuri[ 0 ] );
}

static int
ldap_chain_uri_dup( void *c1, void *c2 )
{
	ldapinfo_t	*li1 = (ldapinfo_t *)c1;
	ldapinfo_t	*li2 = (ldapinfo_t *)c2;

	assert( li1->li_bvuri != NULL );
	assert( !BER_BVISNULL( &li1->li_bvuri[ 0 ] ) );
	assert( BER_BVISNULL( &li1->li_bvuri[ 1 ] ) );

	assert( li2->li_bvuri != NULL );
	assert( !BER_BVISNULL( &li2->li_bvuri[ 0 ] ) );
	assert( BER_BVISNULL( &li2->li_bvuri[ 1 ] ) );

	/* Cannot have more than one shared session with same DN */
	if ( ber_bvcmp( &li1->li_bvuri[ 0 ], &li2->li_bvuri[ 0 ] ) == 0 ) {
		return -1;
	}
		
	return 0;
}

static int
ldap_chain_operational( Operation *op, SlapReply *rs )
{
	/* Trap entries generated by back-ldap.
	 * 
	 * FIXME: we need a better way to recognize them; a cleaner
	 * solution would be to be able to intercept the response
	 * of be_operational(), so that we can divert only those
	 * calls that fail because operational attributes were
	 * requested for entries that do not belong to the underlying
	 * database.  This fix is likely to intercept also entries
	 * generated by back-perl and so. */
	if ( rs->sr_entry->e_private == NULL ) {
		return 0;
	}

	return SLAP_CB_CONTINUE;
}

/*
 * Search specific response that strips entryDN from entries
 */
static int
ldap_chain_cb_search_response( Operation *op, SlapReply *rs )
{
	assert( op->o_tag == LDAP_REQ_SEARCH );

	/* if in error, don't proceed any further */
	if ( op->o_callback->sc_private == LDAP_CH_ERR ) {
		return 0;
	}

	if ( rs->sr_type == REP_SEARCH ) {
		Attribute	**ap = &rs->sr_entry->e_attrs;

		for ( ; *ap != NULL; ap = &(*ap)->a_next ) {
			/* will be generated later by frontend
			 * (a cleaner solution would be that
			 * the frontend checks if it already exists */
			if ( ad_cmp( (*ap)->a_desc, slap_schema.si_ad_entryDN ) == 0 )
			{
				Attribute *a = *ap;

				*ap = (*ap)->a_next;
				attr_free( a );

				/* there SHOULD be one only! */
				break;
			}
		}
		
		return SLAP_CB_CONTINUE;

	} else if ( rs->sr_type == REP_SEARCHREF ) {
		/* if we get it here, it means the library was unable
		 * to chase the referral... */

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
		if ( get_chaining( op ) > SLAP_CONTROL_IGNORED ) {
			switch ( get_continuationBehavior( op ) ) {
			case SLAP_CH_RESOLVE_CHAINING_REQUIRED:
				op->o_callback->sc_private = LDAP_CH_ERR;
				return rs->sr_err = LDAP_X_CANNOT_CHAIN;

			default:
				break;
			}
		}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
		return SLAP_CB_CONTINUE;

	} else if ( rs->sr_type == REP_RESULT ) {
		/* back-ldap tried to send result */
		op->o_callback->sc_private = LDAP_CH_RES;
	}

	return 0;
}

/*
 * Dummy response that simply traces if back-ldap tried to send 
 * anything to the client
 */
static int
ldap_chain_cb_response( Operation *op, SlapReply *rs )
{
	/* if in error, don't proceed any further */
	if ( op->o_callback->sc_private == LDAP_CH_ERR ) {
		return 0;
	}

	if ( rs->sr_type == REP_RESULT ) {
		switch ( rs->sr_err ) {
		case LDAP_COMPARE_TRUE:
		case LDAP_COMPARE_FALSE:
			if ( op->o_tag != LDAP_REQ_COMPARE ) {
				return rs->sr_err;
			}
			/* fallthru */

		case LDAP_SUCCESS:
			op->o_callback->sc_private = LDAP_CH_RES;
			break;

		case LDAP_REFERRAL:
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
			if ( get_chaining( op ) > SLAP_CONTROL_IGNORED ) {
				switch ( get_continuationBehavior( op ) ) {
				case SLAP_CH_RESOLVE_CHAINING_REQUIRED:
					op->o_callback->sc_private = LDAP_CH_ERR;
					return rs->sr_err = LDAP_X_CANNOT_CHAIN;

				default:
					break;
				}
			}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
			break;

		default:
			return rs->sr_err;
		}

	} else if ( op->o_tag == LDAP_REQ_SEARCH && rs->sr_type == REP_SEARCH )
	{
		/* strip the entryDN attribute, but keep returning results */
		(void)ldap_chain_cb_search_response( op, rs );
	}

	return SLAP_CB_CONTINUE;
}

static int
ldap_chain_op(
	Operation	*op,
	SlapReply	*rs,
	int		( *op_f )( Operation *op, SlapReply *rs ), 
	BerVarray	ref )
{
	slap_overinst	*on = (slap_overinst *) op->o_bd->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;
	ldapinfo_t	li = { 0 }, *lip = NULL;
	struct berval	bvuri[ 2 ] = { { 0 } };

	/* NOTE: returned if ref is empty... */
	int		rc = LDAP_OTHER;

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	LDAPControl	**ctrls = NULL;
	
	(void)chaining_control_add( lc, op, &ctrls );
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	li.li_bvuri = bvuri;
	for ( ; !BER_BVISNULL( ref ); ref++ ) {
		LDAPURLDesc	*srv;
		char		*save_dn;
		int		temporary = 0;
			
		/* We're setting the URI of the first referral;
		 * what if there are more?

Document: draft-ietf-ldapbis-protocol-27.txt

4.1.10. Referral 
   ...
   If the client wishes to progress the operation, it MUST follow the 
   referral by contacting one of the supported services. If multiple 
   URIs are present, the client assumes that any supported URI may be 
   used to progress the operation. 

		 * so we actually need to follow exactly one,
		 * and we can assume any is fine.
		 */
	
		/* parse reference and use 
		 * proto://[host][:port]/ only */
		rc = ldap_url_parse_ext( ref->bv_val, &srv );
		if ( rc != LDAP_URL_SUCCESS ) {
			/* try next */
			rc = LDAP_OTHER;
			continue;
		}

		/* remove DN essentially because later on 
		 * ldap_initialize() will parse the URL 
		 * as a comma-separated URL list */
		save_dn = srv->lud_dn;
		srv->lud_dn = "";
		srv->lud_scope = LDAP_SCOPE_DEFAULT;
		li.li_uri = ldap_url_desc2str( srv );
		srv->lud_dn = save_dn;
		ldap_free_urldesc( srv );

		if ( li.li_uri == NULL ) {
			/* try next */
			rc = LDAP_OTHER;
			continue;
		}

		ber_str2bv( li.li_uri, 0, 0, &li.li_bvuri[ 0 ] );

		/* Searches for a ldapinfo in the avl tree */
		ldap_pvt_thread_mutex_lock( &lc->lc_lai.lai_mutex );
		lip = (ldapinfo_t *)avl_find( lc->lc_lai.lai_tree, 
			(caddr_t)&li, ldap_chain_uri_cmp );
		ldap_pvt_thread_mutex_unlock( &lc->lc_lai.lai_mutex );

		if ( lip != NULL ) {
			op->o_bd->be_private = (void *)lip;

		} else {
			rc = ldap_chain_db_init_one( op->o_bd );
			if ( rc != 0 ) {
				goto cleanup;
			}
			lip = (ldapinfo_t *)op->o_bd->be_private;
			lip->li_uri = li.li_uri;
			lip->li_bvuri = bvuri;
			rc = ldap_chain_db_open_one( op->o_bd );
			if ( rc != 0 ) {
				(void)ldap_chain_db_destroy_one( op->o_bd );
				goto cleanup;
			}

			if ( LDAP_CHAIN_CACHE_URI( lc ) ) {
				ldap_pvt_thread_mutex_lock( &lc->lc_lai.lai_mutex );
				if ( avl_insert( &lc->lc_lai.lai_tree,
					(caddr_t)lip, ldap_chain_uri_cmp, ldap_chain_uri_dup ) )
				{
					/* someone just inserted another;
					 * don't bother, use this and then
					 * just free it */
					temporary = 1;
				}
				ldap_pvt_thread_mutex_unlock( &lc->lc_lai.lai_mutex );

			} else {
				temporary = 1;
			}
		}

		rc = ( *op_f )( op, rs );

cleanup:;
		ldap_memfree( li.li_uri );
		li.li_uri = NULL;

		if ( temporary ) {
			lip->li_uri = NULL;
			lip->li_bvuri = NULL;
			(void)ldap_chain_db_close_one( op->o_bd );
			(void)ldap_chain_db_destroy_one( op->o_bd );
		}
		
		if ( rc == LDAP_SUCCESS && rs->sr_err == LDAP_SUCCESS ) {
			break;
		}
	}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	(void)chaining_control_remove( op, &ctrls );
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	return rc;
}

static int
ldap_chain_response( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	void		*private = op->o_bd->be_private;
	slap_callback	*sc = op->o_callback,
			sc2 = { 0 };
	int		rc = 0;
	const char	*matched;
	BerVarray	ref;
	struct berval	ndn = op->o_ndn;

	int		sr_err = rs->sr_err;
	slap_reply_t	sr_type = rs->sr_type;
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	slap_mask_t	chain_mask = 0;
	ber_len_t	chain_shift = 0;
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	if ( rs->sr_err != LDAP_REFERRAL && rs->sr_type != REP_SEARCHREF ) {
		return SLAP_CB_CONTINUE;
	}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	if ( rs->sr_err == LDAP_REFERRAL && get_chaining( op ) > SLAP_CONTROL_IGNORED ) {
		switch ( get_resolveBehavior( op ) ) {
		case SLAP_CH_RESOLVE_REFERRALS_PREFERRED:
		case SLAP_CH_RESOLVE_REFERRALS_REQUIRED:
			return SLAP_CB_CONTINUE;

		default:
			chain_mask = SLAP_CH_RESOLVE_MASK;
			chain_shift = SLAP_CH_RESOLVE_SHIFT;
			break;
		}

	} else if ( rs->sr_type == REP_SEARCHREF && get_chaining( op ) > SLAP_CONTROL_IGNORED ) {
		switch ( get_continuationBehavior( op ) ) {
		case SLAP_CH_CONTINUATION_REFERRALS_PREFERRED:
		case SLAP_CH_CONTINUATION_REFERRALS_REQUIRED:
			return SLAP_CB_CONTINUE;

		default:
			chain_mask = SLAP_CH_CONTINUATION_MASK;
			chain_shift = SLAP_CH_CONTINUATION_SHIFT;
			break;
		}
	}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	/*
	 * TODO: add checks on who/when chain operations; e.g.:
	 *   a) what identities are authorized
	 *   b) what request DN (e.g. only chain requests rooted at <DN>)
	 *   c) what referral URIs
	 *   d) what protocol scheme (e.g. only ldaps://)
	 *   e) what ssf
	 */

	matched = rs->sr_matched;
	rs->sr_matched = NULL;
	ref = rs->sr_ref;
	rs->sr_ref = NULL;

	/* we need this to know if back-ldap returned any result */
	sc2.sc_response = ldap_chain_cb_response;
	op->o_callback = &sc2;

	/* Chaining can be performed by a privileged user on behalf
	 * of normal users, using the ProxyAuthz control, by exploiting
	 * the identity assertion feature of back-ldap; see idassert-*
	 * directives in slapd-ldap(5).
	 *
	 * FIXME: the idassert-authcDN is one, will it be fine regardless
	 * of the URI we obtain from the referral?
	 */

	switch ( op->o_tag ) {
	case LDAP_REQ_BIND: {
		struct berval	rndn = op->o_req_ndn;
		Connection	*conn = op->o_conn;

		/* FIXME: can we really get a referral for binds? */
		op->o_req_ndn = slap_empty_bv;
		op->o_conn = NULL;
		rc = ldap_chain_op( op, rs, lback->bi_op_bind, ref );
		op->o_req_ndn = rndn;
		op->o_conn = conn;
		}
		break;

	case LDAP_REQ_ADD:
		rc = ldap_chain_op( op, rs, lback->bi_op_add, ref );
		break;

	case LDAP_REQ_DELETE:
		rc = ldap_chain_op( op, rs, lback->bi_op_delete, ref );
		break;

	case LDAP_REQ_MODRDN:
		rc = ldap_chain_op( op, rs, lback->bi_op_modrdn, ref );
	    	break;

	case LDAP_REQ_MODIFY:
		rc = ldap_chain_op( op, rs, lback->bi_op_modify, ref );
		break;

	case LDAP_REQ_COMPARE:
		rc = ldap_chain_op( op, rs, lback->bi_op_compare, ref );
		if ( rs->sr_err == LDAP_COMPARE_TRUE || rs->sr_err == LDAP_COMPARE_FALSE ) {
			rc = LDAP_SUCCESS;
		}
		break;

	case LDAP_REQ_SEARCH:
		if ( rs->sr_type == REP_SEARCHREF ) {
			ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;
			ldapinfo_t	li = { 0 }, *lip = NULL;
			struct berval	bvuri[ 2 ] = { { 0 } };

			struct berval	*curr = ref,
					odn = op->o_req_dn,
					ondn = op->o_req_ndn;

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
			LDAPControl	**ctrls = NULL;
	
			(void)chaining_control_add( lc, op, &ctrls );
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

			rs->sr_type = REP_SEARCH;

			sc2.sc_response = ldap_chain_cb_search_response;

			/* if we parse the URI then by no means 
			 * we can cache stuff or reuse connections, 
			 * because in back-ldap there's no caching
			 * based on the URI value, which is supposed
			 * to be set once for all (correct?) */
			li.li_bvuri = bvuri;
			for ( ; !BER_BVISNULL( &curr[0] ); curr++ ) {
				LDAPURLDesc	*srv;
				char		*save_dn;
				int		temporary = 0;

				/* parse reference and use
				 * proto://[host][:port]/ only */
				rc = ldap_url_parse_ext( curr[0].bv_val, &srv );
				if ( rc != LDAP_URL_SUCCESS ) {
					/* try next */
					rs->sr_err = LDAP_OTHER;
					continue;
				}

				/* remove DN essentially because later on 
				 * ldap_initialize() will parse the URL 
				 * as a comma-separated URL list */
				save_dn = srv->lud_dn;
				srv->lud_dn = "";
				srv->lud_scope = LDAP_SCOPE_DEFAULT;
				li.li_uri = ldap_url_desc2str( srv );
				if ( li.li_uri != NULL ) {
					ber_str2bv_x( save_dn, 0, 1, &op->o_req_dn,
							op->o_tmpmemctx );
					ber_dupbv_x( &op->o_req_ndn, &op->o_req_dn,
							op->o_tmpmemctx );
				}

				srv->lud_dn = save_dn;
				ldap_free_urldesc( srv );

				if ( li.li_uri == NULL ) {
					/* try next */
					rs->sr_err = LDAP_OTHER;
					continue;
				}

				ber_str2bv( li.li_uri, 0, 0, &li.li_bvuri[ 0 ] );

				/* Searches for a ldapinfo in the avl tree */
				ldap_pvt_thread_mutex_lock( &lc->lc_lai.lai_mutex );
				lip = (ldapinfo_t *)avl_find( lc->lc_lai.lai_tree, 
					(caddr_t)&li, ldap_chain_uri_cmp );
				ldap_pvt_thread_mutex_unlock( &lc->lc_lai.lai_mutex );

				if ( lip != NULL ) {
					op->o_bd->be_private = (void *)lip;

				} else {
					/* if none is found, create a temporary... */
					rc = ldap_chain_db_init_one( op->o_bd );
					if ( rc != 0 ) {
						goto cleanup;
					}
					lip = (ldapinfo_t *)op->o_bd->be_private;
					lip->li_uri = li.li_uri;
					lip->li_bvuri = bvuri;
					rc = ldap_chain_db_open_one( op->o_bd );
					if ( rc != 0 ) {
						(void)ldap_chain_db_destroy_one( op->o_bd );
						goto cleanup;
					}

					if ( LDAP_CHAIN_CACHE_URI( lc ) ) {
						ldap_pvt_thread_mutex_lock( &lc->lc_lai.lai_mutex );
						if ( avl_insert( &lc->lc_lai.lai_tree,
							(caddr_t)lip, ldap_chain_uri_cmp, ldap_chain_uri_dup ) )
						{
							/* someone just inserted another;
							 * don't bother, use this and then
							 * just free it */
							temporary = 1;
						}
						ldap_pvt_thread_mutex_unlock( &lc->lc_lai.lai_mutex );
		
					} else {
						temporary = 1;
					}
				}

				/* FIXME: should we also copy filter and scope?
				 * according to RFC3296, no */
				rc = lback->bi_op_search( op, rs );

cleanup:;
				ldap_memfree( li.li_uri );
				li.li_uri = NULL;

				op->o_tmpfree( op->o_req_dn.bv_val,
						op->o_tmpmemctx );
				op->o_tmpfree( op->o_req_ndn.bv_val,
						op->o_tmpmemctx );

				if ( temporary ) {
					lip->li_uri = NULL;
					lip->li_bvuri = NULL;
					(void)ldap_chain_db_close_one( op->o_bd );
					(void)ldap_chain_db_destroy_one( op->o_bd );
				}
		
				if ( rc == LDAP_SUCCESS && rs->sr_err == LDAP_SUCCESS ) {
					break;
				}

				rc = rs->sr_err;
			}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
			(void)chaining_control_remove( op, &ctrls );
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

			op->o_req_dn = odn;
			op->o_req_ndn = ondn;
			rs->sr_type = REP_SEARCHREF;
			rs->sr_entry = NULL;

			if ( rc != LDAP_SUCCESS ) {
				/* couldn't chase any of the referrals */
				rc = SLAP_CB_CONTINUE;
			}
			
		} else {
			/* we might get here before any database actually 
			 * performed a search; in those cases, we need
			 * to check limits, to make sure safe defaults
			 * are in place */
			if ( op->ors_limit != NULL || limits_check( op, rs ) == 0 ) {
				rc = ldap_chain_op( op, rs, lback->bi_op_search, ref );

			} else {
				rc = SLAP_CB_CONTINUE;
			}
		}
	    	break;

	case LDAP_REQ_EXTENDED:
		rc = ldap_chain_op( op, rs, lback->bi_extended, ref );
		/* FIXME: ldap_back_extended() by design 
		 * doesn't send result; frontend is expected
		 * to send it... */
		/* FIXME: what aboit chaining? */
		if ( rc != SLAPD_ABANDON ) {
			send_ldap_extended( op, rs );
			rc = LDAP_SUCCESS;
		}
		sc2.sc_private = LDAP_CH_RES;
		break;

	default:
		rc = SLAP_CB_CONTINUE;
		break;
	}

	switch ( rc ) {
	case SLAPD_ABANDON:
		goto dont_chain;

	case LDAP_SUCCESS:
	case LDAP_REFERRAL:
		/* slapd-ldap sent response */
		assert( sc2.sc_private == LDAP_CH_RES );
		break;

	default:
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
		if ( sc2.sc_private == LDAP_CH_ERR && rs->sr_err == LDAP_X_CANNOT_CHAIN ) {
			goto cannot_chain;
		}

		switch ( ( get_chainingBehavior( op ) & chain_mask ) >> chain_shift ) {
		case LDAP_CHAINING_REQUIRED:
cannot_chain:;
			op->o_callback = NULL;
			send_ldap_error( op, rs, LDAP_X_CANNOT_CHAIN,
				"operation cannot be completed without chaining" );
			goto dont_chain;

		default:
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
			rc = SLAP_CB_CONTINUE;
			rs->sr_err = sr_err;
			rs->sr_type = sr_type;
			rs->sr_matched = matched;
			rs->sr_ref = ref;
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
			break;
		}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
	}

	if ( sc2.sc_private == LDAP_CH_NONE && rc != SLAPD_ABANDON ) {
		op->o_callback = NULL;
		rc = rs->sr_err = slap_map_api2result( rs );
		send_ldap_result( op, rs );
	}

dont_chain:;
	rs->sr_err = sr_err;
	rs->sr_type = sr_type;
	rs->sr_matched = matched;
	rs->sr_ref = ref;
	op->o_bd->be_private = private;
	op->o_callback = sc;
	op->o_ndn = ndn;

	return rc;
}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
static int
ldap_chain_parse_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	*ctrl );

static int
str2chain( const char *s )
{
	if ( strcasecmp( s, "chainingPreferred" ) == 0 ) {
		return LDAP_CHAINING_PREFERRED;
		
	} else if ( strcasecmp( s, "chainingRequired" ) == 0 ) {
		return LDAP_CHAINING_REQUIRED;

	} else if ( strcasecmp( s, "referralsPreferred" ) == 0 ) {
		return LDAP_REFERRALS_PREFERRED;
		
	} else if ( strcasecmp( s, "referralsRequired" ) == 0 ) {
		return LDAP_REFERRALS_REQUIRED;
	}

	return -1;
}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

/*
 * configuration...
 */

enum {
	CH_CHAINING = 1,
	CH_CACHE_URI = 2,

	CH_LAST
};

static ConfigDriver chain_cf_gen;
static ConfigCfAdd chain_cfadd;
static ConfigLDAPadd chain_ldadd;

static ConfigTable chaincfg[] = {
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	{ "chain-chaining", "args",
		2, 4, 0, ARG_MAGIC|ARG_BERVAL|CH_CHAINING, chain_cf_gen,
		"( OLcfgOvAt:3.1 NAME 'olcChainingBehavior' "
			"DESC 'Chaining behavior control parameters (draft-sermersheim-ldap-chaining)' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
	{ "chain-cache-uri", "TRUE/FALSE",
		2, 2, 0, ARG_MAGIC|ARG_ON_OFF|CH_CACHE_URI, chain_cf_gen,
		"( OLcfgOvAt:3.2 NAME 'olcCacheURI' "
			"DESC 'Enables caching of URIs not present in configuration' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs chainocs[] = {
	{ "( OLcfgOvOc:3.1 "
		"NAME 'olcChainConfig' "
		"DESC 'Chain configuration' "
		"SUP olcOverlayConfig "
		"MAY ( "
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
			"olcChainingBehavior $ "
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
			"olcCacheURI "
			") )",
		Cft_Overlay, chaincfg, NULL, chain_cfadd },
	{ "( OLcfgOvOc:3.2 "
		"NAME 'olcChainDatabase' "
		"DESC 'Chain remote server configuration' "
		"AUXILIARY )",
		Cft_Misc, chaincfg, chain_ldadd },
	{ NULL, 0, NULL }
};

static int
chain_ldadd( CfEntryInfo *p, Entry *e, ConfigArgs *ca )
{
	slap_overinst		*on;
	ldap_chain_t		*lc;

	ldapinfo_t		*li;

	AttributeDescription	*ad = NULL;
	Attribute		*at;
	const char		*text;

	int			rc;

	if ( p->ce_type != Cft_Overlay
		|| !p->ce_bi
		|| p->ce_bi->bi_cf_ocs != chainocs )
	{
		return LDAP_CONSTRAINT_VIOLATION;
	}

	on = (slap_overinst *)p->ce_bi;
	lc = (ldap_chain_t *)on->on_bi.bi_private;

	assert( ca->be == NULL );
	ca->be = (BackendDB *)ch_calloc( 1, sizeof( BackendDB ) );

	ca->be->bd_info = (BackendInfo *)on;

	rc = slap_str2ad( "olcDbURI", &ad, &text );
	assert( rc == LDAP_SUCCESS );

	at = attr_find( e->e_attrs, ad );
	if ( lc->lc_common_li == NULL && at != NULL ) {
		/* FIXME: we should generate an empty default entry
		 * if none is supplied */
		Debug( LDAP_DEBUG_ANY, "slapd-chain: "
			"first underlying database \"%s\" "
			"cannot contain attribute \"%s\".\n",
			e->e_name.bv_val, ad->ad_cname.bv_val, 0 );
		rc = LDAP_CONSTRAINT_VIOLATION;
		goto done;

	} else if ( lc->lc_common_li != NULL && at == NULL ) {
		/* FIXME: we should generate an empty default entry
		 * if none is supplied */
		Debug( LDAP_DEBUG_ANY, "slapd-chain: "
			"subsequent underlying database \"%s\" "
			"must contain attribute \"%s\".\n",
			e->e_name.bv_val, ad->ad_cname.bv_val, 0 );
		rc = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

	if ( lc->lc_common_li == NULL ) {
		rc = ldap_chain_db_init_common( ca->be );

	} else {
		rc = ldap_chain_db_init_one( ca->be );
	}

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "slapd-chain: "
			"unable to init %sunderlying database \"%s\".\n",
			lc->lc_common_li == NULL ? "common " : "", e->e_name.bv_val, 0 );
		return LDAP_CONSTRAINT_VIOLATION;
	}

	li = ca->be->be_private;

	if ( lc->lc_common_li == NULL ) {
		lc->lc_common_li = li;

	} else if ( avl_insert( &lc->lc_lai.lai_tree, (caddr_t)li,
		ldap_chain_uri_cmp, ldap_chain_uri_dup ) )
	{
		Debug( LDAP_DEBUG_ANY, "slapd-chain: "
			"database \"%s\" insert failed.\n",
			e->e_name.bv_val, 0, 0 );
		rc = LDAP_CONSTRAINT_VIOLATION;
		goto done;
	}

done:;
	if ( rc != LDAP_SUCCESS ) {
		(void)ldap_chain_db_destroy_one( ca->be );
		ch_free( ca->be );
		ca->be = NULL;
	}

	return rc;
}

typedef struct ldap_chain_cfadd_apply_t {
	Operation	*op;
	SlapReply	*rs;
	Entry		*p;
	ConfigArgs	*ca;
	int		count;
} ldap_chain_cfadd_apply_t;

static int
ldap_chain_cfadd_apply( void *datum, void *arg )
{
	ldapinfo_t			*li = (ldapinfo_t *)datum;
	ldap_chain_cfadd_apply_t	*lca = (ldap_chain_cfadd_apply_t *)arg;

	struct berval			bv;

	/* FIXME: should not hardcode "olcDatabase" here */
	bv.bv_len = snprintf( lca->ca->msg, sizeof( lca->ca->msg ),
		"olcDatabase={%d}%s", lca->count, lback->bi_type );
	bv.bv_val = lca->ca->msg;

	lca->ca->be->be_private = (void *)li;
	config_build_entry( lca->op, lca->rs, lca->p->e_private, lca->ca,
		&bv, lback->bi_cf_ocs, &chainocs[1] );

	lca->count++;

	return 0;
}

static int
chain_cfadd( Operation *op, SlapReply *rs, Entry *p, ConfigArgs *ca )
{
	CfEntryInfo	*pe = p->e_private;
	slap_overinst	*on = (slap_overinst *)pe->ce_bi;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;
	void		*priv = (void *)ca->be->be_private;

	if ( lback->bi_cf_ocs ) {
		ldap_chain_cfadd_apply_t	lca = { 0 };

		lca.op = op;
		lca.rs = rs;
		lca.p = p;
		lca.ca = ca;
		lca.count = 0;

		(void)ldap_chain_cfadd_apply( (void *)lc->lc_common_li, (void *)&lca );

		(void)avl_apply( lc->lc_lai.lai_tree, ldap_chain_cfadd_apply,
			&lca, 1, AVL_INORDER );

		ca->be->be_private = priv;
	}

	return 0;
}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
static slap_verbmasks chaining_mode[] = {
	{ BER_BVC("referralsRequired"),		LDAP_REFERRALS_REQUIRED },
	{ BER_BVC("referralsPreferred"),	LDAP_REFERRALS_PREFERRED },
	{ BER_BVC("chainingRequired"),		LDAP_CHAINING_REQUIRED },
	{ BER_BVC("chainingPreferred"),		LDAP_CHAINING_PREFERRED },
	{ BER_BVNULL,				0 }
};
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

static int
chain_cf_gen( ConfigArgs *c )
{
	slap_overinst	*on = (slap_overinst *)c->bi;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

	int		rc = 0;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
		case CH_CHAINING: {
			struct berval	resolve = BER_BVNULL,
					continuation = BER_BVNULL;

			if ( !LDAP_CHAIN_CHAINING( lc ) ) {
				return 1;
			}

			enum_to_verb( chaining_mode, ( ( lc->lc_chaining_ctrlflag & SLAP_CH_RESOLVE_MASK ) >> SLAP_CH_RESOLVE_SHIFT ), &resolve );
			enum_to_verb( chaining_mode, ( ( lc->lc_chaining_ctrlflag & SLAP_CH_CONTINUATION_MASK ) >> SLAP_CH_CONTINUATION_SHIFT ), &continuation );

			c->value_bv.bv_len = STRLENOF( "resolve=" ) + resolve.bv_len
				+ STRLENOF( " " )
				+ STRLENOF( "continuation=" ) + continuation.bv_len;
			c->value_bv.bv_val = ch_malloc( c->value_bv.bv_len + 1 );
			snprintf( c->value_bv.bv_val, c->value_bv.bv_len + 1,
				"resolve=%s continuation=%s",
				resolve.bv_val, continuation.bv_val );

			if ( lc->lc_chaining_ctrl.ldctl_iscritical ) {
				c->value_bv.bv_val = ch_realloc( c->value_bv.bv_val,
					c->value_bv.bv_len + STRLENOF( " critical" ) + 1 );
				AC_MEMCPY( &c->value_bv.bv_val[ c->value_bv.bv_len ],
					" critical", STRLENOF( " critical" ) + 1 );
				c->value_bv.bv_len += STRLENOF( " critical" );
			}

			break;
		}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

		case CH_CACHE_URI:
			c->value_int = LDAP_CHAIN_CACHE_URI( lc );
			break;

		default:
			assert( 0 );
			rc = 1;
		}
		return rc;

	} else if ( c->op == LDAP_MOD_DELETE ) {
		switch( c->type ) {
		case CH_CHAINING:
			return 1;

		case CH_CACHE_URI:
			lc->lc_flags &= ~LDAP_CHAIN_F_CACHE_URI;
			break;

		default:
			return 1;
		}
		return rc;
	}

	switch( c->type ) {
	case CH_CHAINING: {
#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
		char			**argv = c->argv;
		int			argc = c->argc;
		BerElementBuffer	berbuf;
		BerElement		*ber = (BerElement *)&berbuf;
		int			resolve = -1,
					continuation = -1,
					iscritical = 0;
		Operation		op = { 0 };
		SlapReply		rs = { 0 };

		lc->lc_chaining_ctrlflag = 0;

		for ( argc--, argv++; argc > 0; argc--, argv++ ) {
			if ( strncasecmp( argv[ 0 ], "resolve=", STRLENOF( "resolve=" ) ) == 0 ) {
				resolve = str2chain( argv[ 0 ] + STRLENOF( "resolve=" ) );
				if ( resolve == -1 ) {
					Debug( LDAP_DEBUG_ANY, "%s: "
						"illegal <resolve> value %s "
						"in \"chain-chaining>\".\n",
						c->log, argv[ 0 ], 0 );
					return 1;
				}

			} else if ( strncasecmp( argv[ 0 ], "continuation=", STRLENOF( "continuation=" ) ) == 0 ) {
				continuation = str2chain( argv[ 0 ] + STRLENOF( "continuation=" ) );
				if ( continuation == -1 ) {
					Debug( LDAP_DEBUG_ANY, "%s: "
						"illegal <continuation> value %s "
						"in \"chain-chaining\".\n",
						c->log, argv[ 0 ], 0 );
					return 1;
				}

			} else if ( strcasecmp( argv[ 0 ], "critical" ) == 0 ) {
				iscritical = 1;

			} else {
				Debug( LDAP_DEBUG_ANY, "%s: "
					"unknown option in \"chain-chaining\".\n",
					c->log, 0, 0 );
				return 1;
			}
		}

		if ( resolve != -1 || continuation != -1 ) {
			int	err;

			if ( resolve == -1 ) {
				/* default */
				resolve = SLAP_CHAINING_DEFAULT;
			}

			ber_init2( ber, NULL, LBER_USE_DER );

			err = ber_printf( ber, "{e" /* } */, resolve );
	    		if ( err == -1 ) {
				ber_free( ber, 1 );
				Debug( LDAP_DEBUG_ANY, "%s: "
					"chaining behavior control encoding error!\n",
					c->log, 0, 0 );
				return 1;
			}

			if ( continuation > -1 ) {
				err = ber_printf( ber, "e", continuation );
	    			if ( err == -1 ) {
					ber_free( ber, 1 );
					Debug( LDAP_DEBUG_ANY, "%s: "
						"chaining behavior control encoding error!\n",
						c->log, 0, 0 );
					return 1;
				}
			}

			err = ber_printf( ber, /* { */ "N}" );
	    		if ( err == -1 ) {
				ber_free( ber, 1 );
				Debug( LDAP_DEBUG_ANY, "%s: "
					"chaining behavior control encoding error!\n",
					c->log, 0, 0 );
				return 1;
			}

			if ( ber_flatten2( ber, &lc->lc_chaining_ctrl.ldctl_value, 0 ) == -1 ) {
				exit( EXIT_FAILURE );
			}

		} else {
			BER_BVZERO( &lc->lc_chaining_ctrl.ldctl_value );
		}

		lc->lc_chaining_ctrl.ldctl_oid = LDAP_CONTROL_X_CHAINING_BEHAVIOR;
		lc->lc_chaining_ctrl.ldctl_iscritical = iscritical;

		if ( ldap_chain_parse_ctrl( &op, &rs, &lc->lc_chaining_ctrl ) != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY, "%s: "
				"unable to parse chaining control%s%s.\n",
				c->log, rs.sr_text ? ": " : "",
				rs.sr_text ? rs.sr_text : "" );
			return 1;
		}

		lc->lc_chaining_ctrlflag = op.o_chaining;

		lc->lc_flags |= LDAP_CHAIN_F_CHAINING;

		rc = 0;
#else /* ! LDAP_CONTROL_X_CHAINING_BEHAVIOR */
		Debug( LDAP_DEBUG_ANY, "%s: "
			"\"chaining\" control unsupported (ignored).\n",
			c->log, 0, 0 );
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */
		} break;

	case CH_CACHE_URI:
		if ( c->value_int ) {
			lc->lc_flags |= LDAP_CHAIN_F_CACHE_URI;
		} else {
			lc->lc_flags &= ~LDAP_CHAIN_F_CACHE_URI;
		}
		break;

	default:
		assert( 0 );
		return 1;
	}
	return rc;
}

static int
ldap_chain_db_init(
	BackendDB *be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	ldap_chain_t	*lc = NULL;

	if ( lback == NULL ) {
		lback = backend_info( "ldap" );

		if ( lback == NULL ) {
			return 1;
		}
	}

	lc = ch_malloc( sizeof( ldap_chain_t ) );
	if ( lc == NULL ) {
		return 1;
	}
	memset( lc, 0, sizeof( ldap_chain_t ) );

	on->on_bi.bi_private = (void *)lc;

	return 0;
}

static int
ldap_chain_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

	int		rc = SLAP_CONF_UNKNOWN;
		
	if ( lc->lc_common_li == NULL ) {
		void	*be_private = be->be_private;
		ldap_chain_db_init_common( be );
		lc->lc_common_li = lc->lc_cfg_li = (ldapinfo_t *)be->be_private;
		be->be_private = be_private;
	}

	/* Something for the chain database? */
	if ( strncasecmp( argv[ 0 ], "chain-", STRLENOF( "chain-" ) ) == 0 ) {
		char		*save_argv0 = argv[ 0 ];
		BackendInfo	*bd_info = be->bd_info;
		void		*be_private = be->be_private;
		ConfigOCs	*be_cf_ocs = be->be_cf_ocs;
		static char	*allowed_argv[] = {
			/* special: put URI here, so in the meanwhile
			 * it detects whether a new URI is being provided */
			"uri",
			"nretries",
			"timeout",
			/* flags */
			"tls",
			/* FIXME: maybe rebind-as-user should be allowed
			 * only within known URIs... */
			"rebind-as-user",
			"chase-referrals",
			"t-f-support",
			"proxy-whoami",
			NULL
		};
		int		which_argv = -1;

		argv[ 0 ] += STRLENOF( "chain-" );

		for ( which_argv = 0; allowed_argv[ which_argv ]; which_argv++ ) {
			if ( strcasecmp( argv[ 0 ], allowed_argv[ which_argv ] ) == 0 ) {
				break;
			}
		}

		if ( allowed_argv[ which_argv ] == NULL ) {
			which_argv = -1;

			if ( lc->lc_cfg_li == lc->lc_common_li ) {
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"\"%s\" only allowed within a URI directive.\n.",
					fname, lineno, argv[ 0 ] );
				return 1;
			}
		}

		if ( which_argv == 0 ) {
			rc = ldap_chain_db_init_one( be );
			if ( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"underlying slapd-ldap initialization failed.\n.",
					fname, lineno, 0 );
				return 1;
			}
			lc->lc_cfg_li = be->be_private;
		}

		/* TODO: add checks on what other slapd-ldap(5) args
		 * should be put in the template; this is not quite
		 * harmful, because attributes that shouldn't don't
		 * get actually used, but the user should at least
		 * be warned.
		 */

		be->bd_info = lback;
		be->be_private = (void *)lc->lc_cfg_li;
		be->be_cf_ocs = lback->bi_cf_ocs;

		rc = config_generic_wrapper( be, fname, lineno, argc, argv );

		argv[ 0 ] = save_argv0;
		be->be_cf_ocs = be_cf_ocs;
		be->be_private = be_private;
		be->bd_info = bd_info;

		if ( which_argv == 0 ) {
private_destroy:;
			if ( rc != 0 ) {
				BackendDB		db = *be;

				db.bd_info = lback;
				db.be_private = (void *)lc->lc_cfg_li;
				ldap_chain_db_destroy_one( &db );
				lc->lc_cfg_li = NULL;

			} else {
				if ( lc->lc_cfg_li->li_bvuri == NULL
					|| BER_BVISNULL( &lc->lc_cfg_li->li_bvuri[ 0 ] )
					|| !BER_BVISNULL( &lc->lc_cfg_li->li_bvuri[ 1 ] ) )
				{
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"no URI list allowed in slapo-chain.\n",
						fname, lineno, 0 );
					rc = 1;
					goto private_destroy;
				}

				if ( avl_insert( &lc->lc_lai.lai_tree,
					(caddr_t)lc->lc_cfg_li,
					ldap_chain_uri_cmp, ldap_chain_uri_dup ) )
				{
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"duplicate URI in slapo-chain.\n",
						fname, lineno, 0 );
					rc = 1;
					goto private_destroy;
				}
			}
		}
	}
	
	return rc;
}

enum db_which {
	db_open = 0,
	db_close,
	db_destroy,

	db_last
};

typedef struct ldap_chain_db_apply_t {
	BackendDB	*be;
	BI_db_func	*func;
} ldap_chain_db_apply_t;

static int
ldap_chain_db_apply( void *datum, void *arg )
{
	ldapinfo_t		*li = (ldapinfo_t *)datum;
	ldap_chain_db_apply_t	*lca = (ldap_chain_db_apply_t *)arg;

	lca->be->be_private = (void *)li;

	return lca->func( lca->be );
}

static int
ldap_chain_db_func(
	BackendDB *be,
	enum db_which which
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

	int		rc = 0;

	if ( lc ) {
		BI_db_func	*func = (&lback->bi_db_open)[ which ];

		if ( func != NULL && lc->lc_common_li != NULL ) {
			BackendDB		db = *be;

			db.bd_info = lback;
			db.be_private = lc->lc_common_li;

			rc = func( &db );

			if ( rc != 0 ) {
				return rc;
			}

			if ( lc->lc_lai.lai_tree != NULL ) {
				ldap_chain_db_apply_t	lca;

				lca.be = &db;
				lca.func = func;

				rc = avl_apply( lc->lc_lai.lai_tree,
					ldap_chain_db_apply, (void *)&lca,
					1, AVL_INORDER ) != AVL_NOMORE;
			}
		}
	}

	return rc;
}

static int
ldap_chain_db_open(
	BackendDB	*be )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	int	rc = 0;

	rc = overlay_register_control( be, LDAP_CONTROL_X_CHAINING_BEHAVIOR );
	if ( rc != 0 ) {
		return rc;
	}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	if ( lc->lc_common_li == NULL ) {
		void	*be_private = be->be_private;
		ldap_chain_db_init_common( be );
		lc->lc_common_li = lc->lc_cfg_li = (ldapinfo_t *)be->be_private;
		be->be_private = be_private;
	}

	return ldap_chain_db_func( be, db_open );
}

static int
ldap_chain_db_close(
	BackendDB	*be )
{
	return ldap_chain_db_func( be, db_close );
}

static int
ldap_chain_db_destroy(
	BackendDB	*be )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

	int		rc;

	rc = ldap_chain_db_func( be, db_destroy );

	if ( lc ) {
		avl_free( lc->lc_lai.lai_tree, NULL );
		ch_free( lc );
	}

	return rc;
}

/*
 * inits one instance of the slapd-ldap backend, and stores
 * the private info in be_private of the arg
 */
static int
ldap_chain_db_init_common(
	BackendDB	*be )
{
	BackendInfo	*bi = be->bd_info;
	int		t;

	be->bd_info = lback;
	be->be_private = NULL;
	t = lback->bi_db_init( be );
	if ( t != 0 ) {
		return t;
	}
	be->bd_info = bi;

	return 0;
}

/*
 * inits one instance of the slapd-ldap backend, stores
 * the private info in be_private of the arg and fills
 * selected fields with data from the template.
 *
 * NOTE: add checks about the other fields of the template,
 * which are ignored and SHOULD NOT be configured by the user.
 */
static int
ldap_chain_db_init_one(
	BackendDB	*be )
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	ldap_chain_t	*lc = (ldap_chain_t *)on->on_bi.bi_private;

	BackendInfo	*bi = be->bd_info;
	ldapinfo_t	*li;

	int		t;

	be->bd_info = lback;
	be->be_private = NULL;
	t = lback->bi_db_init( be );
	if ( t != 0 ) {
		return t;
	}
	li = (ldapinfo_t *)be->be_private;

	/* copy common data */
	li->li_nretries = lc->lc_common_li->li_nretries;
	li->li_flags = lc->lc_common_li->li_flags;
	li->li_version = lc->lc_common_li->li_version;
	for ( t = 0; t < LDAP_BACK_OP_LAST; t++ ) {
		li->li_timeout[ t ] = lc->lc_common_li->li_timeout[ t ];
	}
	be->bd_info = bi;

	return 0;
}

typedef struct ldap_chain_conn_apply_t {
	BackendDB	*be;
	Connection	*conn;
} ldap_chain_conn_apply_t;

static int
ldap_chain_conn_apply( void *datum, void *arg )
{
	ldapinfo_t		*li = (ldapinfo_t *)datum;
	ldap_chain_conn_apply_t	*lca = (ldap_chain_conn_apply_t *)arg;

	lca->be->be_private = (void *)li;

	return lback->bi_connection_destroy( lca->be, lca->conn );
}

static int
ldap_chain_connection_destroy(
	BackendDB *be,
	Connection *conn
)
{
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	ldap_chain_t		*lc = (ldap_chain_t *)on->on_bi.bi_private;
	void			*private = be->be_private;
	ldap_chain_conn_apply_t	lca;
	int			rc;

	be->be_private = NULL;
	lca.be = be;
	lca.conn = conn;
	ldap_pvt_thread_mutex_lock( &lc->lc_lai.lai_mutex );
	rc = avl_apply( lc->lc_lai.lai_tree, ldap_chain_conn_apply,
		(void *)&lca, 1, AVL_INORDER ) != AVL_NOMORE;
	ldap_pvt_thread_mutex_unlock( &lc->lc_lai.lai_mutex );
	be->be_private = private;

	return rc;
}

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
static int
ldap_chain_parse_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	*ctrl )
{
	ber_tag_t	tag;
	BerElement	*ber;
	ber_int_t	mode,
			behavior;

	if ( get_chaining( op ) != SLAP_CONTROL_NONE ) {
		rs->sr_text = "Chaining behavior control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( op->o_pagedresults != SLAP_CONTROL_NONE ) {
		rs->sr_text = "Chaining behavior control specified with pagedResults control";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		mode = (SLAP_CH_RESOLVE_DEFAULT|SLAP_CH_CONTINUATION_DEFAULT);

	} else {
		ber_len_t	len;

		/* Parse the control value
		 *      ChainingBehavior ::= SEQUENCE { 
		 *           resolveBehavior         Behavior OPTIONAL, 
		 *           continuationBehavior    Behavior OPTIONAL } 
		 *                             
		 *      Behavior :: = ENUMERATED { 
		 *           chainingPreferred       (0), 
		 *           chainingRequired        (1), 
		 *           referralsPreferred      (2), 
		 *           referralsRequired       (3) } 
		 */

		ber = ber_init( &ctrl->ldctl_value );
		if( ber == NULL ) {
			rs->sr_text = "internal error";
			return LDAP_OTHER;
		}

		tag = ber_scanf( ber, "{e" /* } */, &behavior );
		/* FIXME: since the whole SEQUENCE is optional,
		 * should we accept no enumerations at all? */
		if ( tag != LBER_ENUMERATED ) {
			rs->sr_text = "Chaining behavior control: resolveBehavior decoding error";
			return LDAP_PROTOCOL_ERROR;
		}

		switch ( behavior ) {
		case LDAP_CHAINING_PREFERRED:
			mode = SLAP_CH_RESOLVE_CHAINING_PREFERRED;
			break;

		case LDAP_CHAINING_REQUIRED:
			mode = SLAP_CH_RESOLVE_CHAINING_REQUIRED;
			break;

		case LDAP_REFERRALS_PREFERRED:
			mode = SLAP_CH_RESOLVE_REFERRALS_PREFERRED;
			break;

		case LDAP_REFERRALS_REQUIRED:
			mode = SLAP_CH_RESOLVE_REFERRALS_REQUIRED;
			break;

		default:
			rs->sr_text = "Chaining behavior control: unknown resolveBehavior";
			return LDAP_PROTOCOL_ERROR;
		}

		tag = ber_peek_tag( ber, &len );
		if ( tag == LBER_ENUMERATED ) {
			tag = ber_scanf( ber, "e", &behavior );
			if ( tag == LBER_ERROR ) {
				rs->sr_text = "Chaining behavior control: continuationBehavior decoding error";
				return LDAP_PROTOCOL_ERROR;
			}
		}

		if ( tag == LBER_DEFAULT ) {
			mode |= SLAP_CH_CONTINUATION_DEFAULT;

		} else {
			switch ( behavior ) {
			case LDAP_CHAINING_PREFERRED:
				mode |= SLAP_CH_CONTINUATION_CHAINING_PREFERRED;
				break;

			case LDAP_CHAINING_REQUIRED:
				mode |= SLAP_CH_CONTINUATION_CHAINING_REQUIRED;
				break;

			case LDAP_REFERRALS_PREFERRED:
				mode |= SLAP_CH_CONTINUATION_REFERRALS_PREFERRED;
				break;

			case LDAP_REFERRALS_REQUIRED:
				mode |= SLAP_CH_CONTINUATION_REFERRALS_REQUIRED;
				break;

			default:
				rs->sr_text = "Chaining behavior control: unknown continuationBehavior";
				return LDAP_PROTOCOL_ERROR;
			}
		}

		if ( ( ber_scanf( ber, /* { */ "}") ) == LBER_ERROR ) {
			rs->sr_text = "Chaining behavior control: decoding error";
			return LDAP_PROTOCOL_ERROR;
		}

		(void) ber_free( ber, 1 );
	}

	op->o_chaining = mode | ( ctrl->ldctl_iscritical
			? SLAP_CONTROL_CRITICAL
			: SLAP_CONTROL_NONCRITICAL );

	return LDAP_SUCCESS;
}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

static slap_overinst ldapchain;

int
chain_init( void )
{
	int	rc;

	/* Make sure we don't exceed the bits reserved for userland */
	config_check_userland( CH_LAST );

#ifdef LDAP_CONTROL_X_CHAINING_BEHAVIOR
	rc = register_supported_control( LDAP_CONTROL_X_CHAINING_BEHAVIOR,
			/* SLAP_CTRL_GLOBAL| */ SLAP_CTRL_ACCESS|SLAP_CTRL_HIDE, NULL,
			ldap_chain_parse_ctrl, &sc_chainingBehavior );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "slapd-chain: "
			"unable to register chaining behavior control: %d.\n",
			rc, 0, 0 );
		return rc;
	}
#endif /* LDAP_CONTROL_X_CHAINING_BEHAVIOR */

	ldapchain.on_bi.bi_type = "chain";
	ldapchain.on_bi.bi_db_init = ldap_chain_db_init;
	ldapchain.on_bi.bi_db_config = ldap_chain_db_config;
	ldapchain.on_bi.bi_db_open = ldap_chain_db_open;
	ldapchain.on_bi.bi_db_close = ldap_chain_db_close;
	ldapchain.on_bi.bi_db_destroy = ldap_chain_db_destroy;

	/* ... otherwise the underlying backend's function would be called,
	 * likely passing an invalid entry; on the contrary, the requested
	 * operational attributes should have been returned while chasing
	 * the referrals.  This all in all is a bit messy, because part
	 * of the operational attributes are generated by the backend;
	 * part by the frontend; back-ldap should receive all the available
	 * ones from the remote server, but then, on its own, it strips those
	 * it assumes will be (re)generated by the frontend (e.g.
	 * subschemaSubentry.) */
	ldapchain.on_bi.bi_operational = ldap_chain_operational;
	
	ldapchain.on_bi.bi_connection_destroy = ldap_chain_connection_destroy;

	ldapchain.on_response = ldap_chain_response;

	ldapchain.on_bi.bi_cf_ocs = chainocs;

	rc = config_register_schema( chaincfg, chainocs );
	if ( rc ) {
		return rc;
	}

	return overlay_register( &ldapchain );
}

