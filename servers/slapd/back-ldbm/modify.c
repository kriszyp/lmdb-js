/* modify.c - ldbm backend modify routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
    Operation	*op,
    Modifications	*modlist,
    Entry	*e,
	const char **text,
	char *textbuf,
	size_t textlen )
{
	int rc = LDAP_SUCCESS;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;
	Attribute 	*ap;

	Debug(LDAP_DEBUG_TRACE,
		"ldbm_modify_internal: %s\n",
		e->e_name.bv_val,
		get_permissiveModify(op) ? " (permissive)" : "",
		0 );

	if ( !acl_check_modlist( op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			Debug(LDAP_DEBUG_ARGS,
				"ldbm_modify_internal: add\n", 0, 0, 0);

			rc = modify_add_values( e, mod, get_permissiveModify( op ),
				text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
			}
			break;

		case LDAP_MOD_DELETE:
			Debug(LDAP_DEBUG_ARGS,
				"ldbm_modify_internal: delete\n", 0, 0, 0);

			rc = modify_delete_values( e, mod, get_permissiveModify( op ),
				text, textbuf, textlen );
			assert( rc != LDAP_TYPE_OR_VALUE_EXISTS );
			if( rc != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
			}
			break;

		case LDAP_MOD_REPLACE:
			Debug(LDAP_DEBUG_ARGS,
				"ldbm_modify_internal: replace\n", 0, 0, 0);

			rc = modify_replace_values( e, mod, get_permissiveModify( op ),
				text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
			}
			break;

		case LDAP_MOD_INCREMENT:
			Debug(LDAP_DEBUG_ARGS,
				"ldbm_modify_internal:  increment\n",0,0,0);

			rc = modify_increment_values( e, mod, get_permissiveModify( op ),
				text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
			}
			break;

		case SLAP_MOD_SOFTADD:
			Debug(LDAP_DEBUG_ARGS,
				"ldbm_modify_internal: softadd\n", 0, 0, 0);

			/* Avoid problems in index_add_mods()
			 * We need to add index if necessary.
			 */
			mod->sm_op = LDAP_MOD_ADD;

			rc = modify_add_values( e, mod, get_permissiveModify( op ),
				text, textbuf, textlen );
			mod->sm_op = SLAP_MOD_SOFTADD;
			if ( rc == LDAP_TYPE_OR_VALUE_EXISTS ) {
				rc = LDAP_SUCCESS;
			}

			if( rc != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					rc, *text, 0);
			}
			break;

		default:
			Debug(LDAP_DEBUG_ANY, "ldbm_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);

			rc = LDAP_OTHER;
			*text = "Invalid modify operation";
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
				rc, *text, 0);
		}

		if ( rc != LDAP_SUCCESS ) {
			goto exit;
		}

		/* If objectClass was modified, reset the flags */
		if ( mod->sm_desc == slap_schema.si_ad_objectClass ) {
			e->e_ocflags = 0;
		}

		/* check if modified attribute was indexed */
		rc = index_is_indexed( op->o_bd, mod->sm_desc );
		if ( rc == LDAP_SUCCESS ) {
			ap = attr_find( save_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXDEL;

			ap = attr_find( e->e_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXADD;
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( op, e, save_attrs, get_manageDIT(op),
		text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "entry failed schema check: %s\n",
			*text, 0, 0 );

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
			rc = index_values( op, ap->a_desc,
				ap->a_nvals,
				e->e_id, SLAP_INDEX_DELETE_OP );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"ldbm_modify_internal: Attribute index delete failure\n",
					0, 0, 0 );
				goto exit;
			}
			ap->a_flags &= ~SLAP_ATTR_IXDEL;
		}
	}

	/* add the new index entries */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
		if ( ap->a_flags & SLAP_ATTR_IXADD ) {
			rc = index_values( op, ap->a_desc,
				ap->a_nvals,
				e->e_id, SLAP_INDEX_ADD_OP );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"ldbm_modify_internal: Attribute index add failure\n",
					0, 0, 0 );
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
    Operation	*op,
    SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);

	slap_mods_opattrs( op, &op->orm_modlist, 1 );

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	/* acquire and lock entry */
	e = dn2entry_w( op->o_bd, &op->o_req_ndn, &matched );

	/* FIXME: dn2entry() should return non-glue entry */
	if (( e == NULL ) || ( !manageDSAit && e && is_entry_glue( e ))) {
		if ( matched != NULL ) {
			rs->sr_matched = ber_strdup_x( matched->e_dn, op->o_tmpmemctx );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			rs->sr_ref = referral_rewrite( default_referral, NULL,
				&op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_flags = REP_MATCHED_MUSTBEFREED | REP_REF_MUSTBEFREED;
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		rs->sr_ref = get_entry_referrals( op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = ber_strdup_x( e->e_name.bv_val, op->o_tmpmemctx );
		rs->sr_flags = REP_MATCHED_MUSTBEFREED | REP_REF_MUSTBEFREED;
		goto return_results;
	}
	
	/* Modify the entry */
	rs->sr_err = ldbm_modify_internal( op, op->oq_modify.rs_modlist, e,
		&rs->sr_text, textbuf, textlen );

	/* change the entry itself */
	if( rs->sr_err == LDAP_SUCCESS ) {
		if ( id2entry_add( op->o_bd, e ) != 0 ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "id2entry failure";
		}
	}

return_results:;
	if( e != NULL ) cache_return_entry_w( &li->li_cache, e );
	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

	send_ldap_result( op, rs );
	slap_graduate_commit_csn( op );

	rs->sr_text = NULL;
	return rs->sr_err;
}
