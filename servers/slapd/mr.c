/* mr.c - routines to manage matching rule definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

struct mindexrec {
	struct berval	mir_name;
	MatchingRule	*mir_mr;
};

static Avlnode	*mr_index = NULL;
static MatchingRule *mr_list = NULL;

static int
mr_index_cmp(
    struct mindexrec	*mir1,
    struct mindexrec	*mir2
)
{
	int i = mir1->mir_name.bv_len - mir2->mir_name.bv_len;
	if (i) return i;
	return (strcmp( mir1->mir_name.bv_val, mir2->mir_name.bv_val ));
}

static int
mr_index_name_cmp(
    struct berval	*name,
    struct mindexrec	*mir
)
{
	int i = name->bv_len - mir->mir_name.bv_len;
	if (i) return i;
	return (strncmp( name->bv_val, mir->mir_name.bv_val, name->bv_len ));
}

MatchingRule *
mr_find( const char *mrname )
{
	struct berval bv;

	bv.bv_val = (char *)mrname;
	bv.bv_len = strlen( mrname );
	return mr_bvfind( &bv );
}

MatchingRule *
mr_bvfind( struct berval *mrname )
{
	struct mindexrec	*mir = NULL;

	if ( (mir = (struct mindexrec *) avl_find( mr_index, mrname,
	    (AVL_CMP) mr_index_name_cmp )) != NULL ) {
		return( mir->mir_mr );
	}
	return( NULL );
}

void
mr_destroy( void )
{
	MatchingRule *m, *n;

	avl_free(mr_index, ldap_memfree);
	for (m=mr_list; m; m=n) {
		n = m->smr_next;
		ldap_matchingrule_free((LDAPMatchingRule *)m);
	}
}

static int
mr_insert(
    MatchingRule	*smr,
    const char		**err
)
{
	MatchingRule		**mrp;
	struct mindexrec	*mir;
	char			**names;

	mrp = &mr_list;
	while ( *mrp != NULL ) {
		mrp = &(*mrp)->smr_next;
	}
	*mrp = smr;

	if ( smr->smr_oid ) {
		mir = (struct mindexrec *)
			ch_calloc( 1, sizeof(struct mindexrec) );
		mir->mir_name.bv_val = smr->smr_oid;
		mir->mir_name.bv_len = strlen( smr->smr_oid );
		mir->mir_mr = smr;
		if ( avl_insert( &mr_index, (caddr_t) mir,
				 (AVL_CMP) mr_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = smr->smr_oid;
			ldap_memfree(mir);
			return SLAP_SCHERR_MR_DUP;
		}
		/* FIX: temporal consistency check */
		mr_bvfind(&mir->mir_name);
	}
	if ( (names = smr->smr_names) ) {
		while ( *names ) {
			mir = (struct mindexrec *)
				ch_calloc( 1, sizeof(struct mindexrec) );
			mir->mir_name.bv_val = *names;
			mir->mir_name.bv_len = strlen( *names );
			mir->mir_mr = smr;
			if ( avl_insert( &mr_index, (caddr_t) mir,
					 (AVL_CMP) mr_index_cmp,
					 (AVL_DUP) avl_dup_error ) ) {
				*err = *names;
				ldap_memfree(mir);
				return SLAP_SCHERR_MR_DUP;
			}
			/* FIX: temporal consistency check */
			mr_bvfind(&mir->mir_name);
			names++;
		}
	}
	return 0;
}

int
mr_add(
    LDAPMatchingRule		*mr,
    slap_mrule_defs_rec	*def,
	MatchingRule	*amr,
    const char		**err
)
{
	MatchingRule	*smr;
	Syntax		*syn;
	int		code;

	smr = (MatchingRule *) ch_calloc( 1, sizeof(MatchingRule) );
	AC_MEMCPY( &smr->smr_mrule, mr, sizeof(LDAPMatchingRule));

	smr->smr_oidlen = strlen( mr->mr_oid );
	smr->smr_usage = def->mrd_usage;
	smr->smr_convert = def->mrd_convert;
	smr->smr_normalize = def->mrd_normalize;
	smr->smr_match = def->mrd_match;
	smr->smr_indexer = def->mrd_indexer;
	smr->smr_filter = def->mrd_filter;
	smr->smr_associated = amr;

	if ( smr->smr_syntax_oid ) {
		if ( (syn = syn_find(smr->smr_syntax_oid)) ) {
			smr->smr_syntax = syn;
		} else {
			*err = smr->smr_syntax_oid;
			return SLAP_SCHERR_SYN_NOT_FOUND;
		}
	} else {
		*err = "";
		return SLAP_SCHERR_MR_INCOMPLETE;
	}
	code = mr_insert(smr,err);
	return code;
}


int
register_matching_rule(
	slap_mrule_defs_rec *def )
{
	LDAPMatchingRule *mr;
	MatchingRule *amr = NULL;
	int		code;
	const char	*err;

	if( def->mrd_usage == SLAP_MR_NONE ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"register_matching_rule: %s not usable\n", def->mrd_desc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "register_matching_rule: not usable %s\n",
		    def->mrd_desc, 0, 0 );
#endif

		return -1;
	}

	if( def->mrd_associated != NULL ) {
		amr = mr_find( def->mrd_associated );

#if 0
		/* ignore for now */

		if( amr == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "register_matching_rule: could not locate associated "
			   "matching rule %s for %s\n",  def->mrd_associated, def->mrd_desc, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "register_matching_rule: could not locate "
				"associated matching rule %s for %s\n",
				def->mrd_associated, def->mrd_desc, 0 );
#endif

			return -1;
		}
#endif

	}

	mr = ldap_str2matchingrule( def->mrd_desc, &code, &err, LDAP_SCHEMA_ALLOW_ALL);
	if ( !mr ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"register_matching_rule: %s before %s in %s.\n",
			ldap_scherr2str(code), err, def->mrd_desc );
#else
		Debug( LDAP_DEBUG_ANY, "Error in register_matching_rule: %s before %s in %s\n",
		    ldap_scherr2str(code), err, def->mrd_desc );
#endif

		return( -1 );
	}

	code = mr_add( mr, def, amr, &err );

	ldap_memfree( mr );

	if ( code ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"register_matching_rule: %s for %s in %s.\n",
			scherr2str(code), err, def->mrd_desc );
#else
		Debug( LDAP_DEBUG_ANY, "Error in register_matching_rule: %s for %s in %s\n",
		    scherr2str(code), err, def->mrd_desc );
#endif

		return( -1 );
	}

	return( 0 );
}


#if defined( SLAPD_SCHEMA_DN )

int mr_schema_info( Entry *e )
{
	struct berval	vals[2];
	MatchingRule	*mr;

	AttributeDescription *ad_matchingRules = slap_schema.si_ad_matchingRules;

	vals[1].bv_val = NULL;

	for ( mr = mr_list; mr; mr = mr->smr_next ) {
		if ( mr->smr_usage & SLAP_MR_HIDE ) {
			/* skip hidden rules */
			continue;
		}

		if ( ! mr->smr_match ) {
			/* skip rules without matching functions */
			continue;
		}

		if ( ldap_matchingrule2bv( &mr->smr_mrule, vals ) == NULL ) {
			return -1;
		}
#if 0
		Debug( LDAP_DEBUG_TRACE, "Merging mr [%ld] %s\n",
	       (long) vals[0].bv_len, vals[0].bv_val, 0 );
#endif
		attr_merge( e, ad_matchingRules, vals );
		ldap_memfree( vals[0].bv_val );
	}
	return 0;
}

int mru_schema_info( Entry *e )
{
	return 0;
}

#endif
