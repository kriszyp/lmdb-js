/* schema.c - routines to enforce schema definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

static char *	oc_check_required(Entry *e, char *ocname);
static int		oc_check_allowed(char *type, struct berval **ocl);

/*
 * oc_check - check that entry e conforms to the schema required by
 * its object class(es). returns 0 if so, non-zero otherwise.
 */

int
oc_schema_check( Entry *e )
{
	Attribute	*a, *aoc;
	ObjectClass *oc;
	int		i;
	int		ret = 0;


	/* find the object class attribute - could error out here */
	if ( (aoc = attr_find( e->e_attrs, "objectclass" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No object class for entry (%s)\n",
		    e->e_dn, 0, 0 );
		return( 1 );
	}

	/* check that the entry has required attrs for each oc */
	for ( i = 0; aoc->a_vals[i] != NULL; i++ ) {
		if ( (oc = oc_find( aoc->a_vals[i]->bv_val )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"Objectclass \"%s\" not defined\n",
				aoc->a_vals[i]->bv_val, 0, 0 );
		}
		else
		{
			char *s = oc_check_required( e, aoc->a_vals[i]->bv_val );

			if (s != NULL) {
				Debug( LDAP_DEBUG_ANY,
					"Entry (%s), oc \"%s\" requires attr \"%s\"\n",
					e->e_dn, aoc->a_vals[i]->bv_val, s );
				ret = 1;
			}
		}
	}

	if ( ret != 0 ) {
	    return( ret );
	}

	/* check that each attr in the entry is allowed by some oc */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		if ( oc_check_allowed( a->a_type, aoc->a_vals ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, a->a_type, 0 );
			ret = 1;
		}
	}

	return( ret );
}

static char *
oc_check_required( Entry *e, char *ocname )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i;
	Attribute	*a;
	char		**pp;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_required entry (%s), objectclass \"%s\"\n",
	       e->e_dn, ocname, 0 );

	/* find global oc defn. it we don't know about it assume it's ok */
	if ( (oc = oc_find( ocname )) == NULL ) {
		return( 0 );
	}

	/* check for empty oc_required */
	if(oc->soc_required == NULL) {
		return( 0 );
	}

	/* for each required attribute */
	for ( i = 0; oc->soc_required[i] != NULL; i++ ) {
		at = oc->soc_required[i];
		/* see if it's in the entry */
		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
			if ( at->sat_oid &&
			     strcmp( a->a_type, at->sat_oid ) == 0 ) {
				break;
			}
			pp = at->sat_names;
			if ( pp  == NULL ) {
				/* Empty name list => not found */
				a = NULL;
				break;
			}
			while ( *pp ) {
				if ( strcasecmp( a->a_type, *pp ) == 0 ) {
					break;
				}
				pp++;
			}
			if ( *pp ) {
				break;
			}
		}
		/* not there => schema violation */
		if ( a == NULL ) {
			if ( at->sat_names && at->sat_names[0] ) {
				return at->sat_names[0];
			} else {
				return at->sat_oid;
			}
		}
	}

	return( NULL );
}

#ifdef SLAPD_SCHEMA_COMPAT
	/* these shouldn't be hardcoded */

static char *oc_op_usermod_attrs[] = {
	/*
	 * these are operational attributes which are
	 * not defined as NO-USER_MODIFICATION and
	 * which slapd supports modification of.
	 *
	 * Currently none.
	 * Likely candidate, "aci"
	 */
	NULL
};

static char *oc_op_attrs[] = {
	/*
	 * these are operational attributes 
	 * most could be user modifiable
	 */
	"objectClasses",
	"attributeTypes",
	"matchingRules",
	"matchingRuleUse",
	"dITStructureRules",
	"dITContentRules",
	"nameForms",
	"ldapSyntaxes",
	"namingContexts",
	"supportedExtension",
	"supportedControl",
	"supportedSASLMechanisms",
	"supportedLDAPversion",
	"supportedACIMechanisms",
	"subschemaSubentry",		/* NO USER MOD */
	NULL

};

/* this list should be extensible  */
static char *oc_op_no_usermod_attrs[] = {
	/*
	 * Operational and 'no user modification' attributes
	 * which are STORED in the directory server.
	 */

	/* RFC2252, 3.2.1 */
	"creatorsName",
	"createTimestamp",
	"modifiersName",
	"modifyTimestamp",

	NULL
};
#endif


/*
 * check to see if attribute is 'operational' or not.
 */
int
oc_check_op_attr( const char *type )
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	return charray_inlist( oc_op_attrs, type )
		|| charray_inlist( oc_op_usermod_attrs, type )
		|| charray_inlist( oc_op_no_usermod_attrs, type );
#else
	AttributeType *at = at_find( type );

	if( at == NULL ) return 0;

	return at->sat_usage != LDAP_SCHEMA_USER_APPLICATIONS;
#endif
}

/*
 * check to see if attribute can be user modified or not.
 */
int
oc_check_op_usermod_attr( const char *type )
{
#ifdef SLAPD_SCHEMA_COMPAT
	return charray_inlist( oc_op_usermod_attrs, type );
#else
	/* not (yet) in schema */
	return 0;
#endif
}

/*
 * check to see if attribute is 'no user modification' or not.
 */
int
oc_check_op_no_usermod_attr( const char *type )
{
#ifdef SLAPD_SCHEMA_COMPAT
	return charray_inlist( oc_op_no_usermod_attrs, type );
#else
	AttributeType *at = at_find( type );

	if( at == NULL ) return 0;

	return at->sat_no_user_mod;
#endif
}


static int
oc_check_allowed( char *type, struct berval **ocl )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i, j;
	char		**pp;
	char		*p, *t;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_allowed type \"%s\"\n", type, 0, 0 );

	/* always allow objectclass attribute */
	if ( strcasecmp( type, "objectclass" ) == 0 ) {
		return( 0 );
	}

#ifdef SLAPD_SCHEMA_COMPAT
	/* Treat any attribute type with option as an unknown attribute type */
	/*
	 * The "type" we have received is actually an AttributeDescription.
	 * Let's find out the corresponding type.
	 */
	p = strchr( type, ';' );
	if ( p ) {
		t = ch_malloc( p-type+1 );
		strncpy( t, type, p-type );
		t[p-type] = '\0';
		Debug( LDAP_DEBUG_TRACE,
		       "oc_check_allowed type \"%s\" from \"%s\"\n",
		       t, type, 0 );

	} else
#endif
	{
		t = type;
	}


	/*
	 * All operational attributions are allowed by schema rules.
	 */
	if ( oc_check_op_attr( t ) ) {
		return( 0 );
	}

	/* check that the type appears as req or opt in at least one oc */
	for ( i = 0; ocl[i] != NULL; i++ ) {
		/* if we know about the oc */
		if ( (oc = oc_find( ocl[i]->bv_val )) != NULL ) {
			/* does it require the type? */
			for ( j = 0; oc->soc_required != NULL && 
				oc->soc_required[j] != NULL; j++ ) {
				at = oc->soc_required[j];
				if ( at->sat_oid &&
				     strcmp(at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return( 0 );
					}
					pp++;
				}
			}
			/* does it allow the type? */
			for ( j = 0; oc->soc_allowed != NULL && 
				oc->soc_allowed[j] != NULL; j++ ) {
				at = oc->soc_allowed[j];
				if ( at->sat_oid &&
				     strcmp( at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ||
					     strcmp( *pp, "*" ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return( 0 );
					}
					pp++;
				}
			}
			/* maybe the next oc allows it */

#ifdef OC_UNDEFINED_IMPLES_EXTENSIBLE
		/* we don't know about the oc. assume it allows it */
		} else {
			if ( t != type )
				ldap_memfree( t );
			return( 0 );
#endif
		}
	}

	if ( t != type )
		ldap_memfree( t );
	/* not allowed by any oc */
	return( 1 );
}

struct oindexrec {
	char		*oir_name;
	ObjectClass	*oir_oc;
};

static Avlnode	*oc_index = NULL;
static ObjectClass *oc_list = NULL;

static int
oc_index_cmp(
    struct oindexrec	*oir1,
    struct oindexrec	*oir2
)
{
	return (strcasecmp( oir1->oir_name, oir2->oir_name ));
}

static int
oc_index_name_cmp(
    char 		*name,
    struct oindexrec	*oir
)
{
	return (strcasecmp( name, oir->oir_name ));
}

ObjectClass *
oc_find( const char *ocname )
{
	struct oindexrec	*oir = NULL;

	if ( (oir = (struct oindexrec *) avl_find( oc_index, ocname,
            (AVL_CMP) oc_index_name_cmp )) != NULL ) {
		return( oir->oir_oc );
	}
	return( NULL );
}

static int
oc_create_required(
    ObjectClass		*soc,
    char		**attrs,
    const char		**err
)
{
	char		**attrs1;
	AttributeType	*sat;
	AttributeType	**satp;
	int		i;

	if ( attrs ) {
		attrs1 = attrs;
		while ( *attrs1 ) {
			sat = at_find(*attrs1);
			if ( !sat ) {
				*err = *attrs1;
				return SLAP_SCHERR_ATTR_NOT_FOUND;
			}
			if ( at_find_in_list(sat, soc->soc_required) < 0) {
				if ( at_append_to_list(sat, &soc->soc_required) ) {
					*err = *attrs1;
					return SLAP_SCHERR_OUTOFMEM;
				}
			}
			attrs1++;
		}
		/* Now delete duplicates from the allowed list */
		for ( satp = soc->soc_required; *satp; satp++ ) {
			i = at_find_in_list(*satp,soc->soc_allowed);
			if ( i >= 0 ) {
				at_delete_from_list(i, &soc->soc_allowed);
			}
		}
	}
	return 0;
}

static int
oc_create_allowed(
    ObjectClass		*soc,
    char		**attrs,
    const char		**err
)
{
	char		**attrs1;
	AttributeType	*sat;

	if ( attrs ) {
		attrs1 = attrs;
		while ( *attrs1 ) {
			sat = at_find(*attrs1);
			if ( !sat ) {
				*err = *attrs1;
				return SLAP_SCHERR_ATTR_NOT_FOUND;
			}
			if ( at_find_in_list(sat, soc->soc_required) < 0 &&
			     at_find_in_list(sat, soc->soc_allowed) < 0 ) {
				if ( at_append_to_list(sat, &soc->soc_allowed) ) {
					*err = *attrs1;
					return SLAP_SCHERR_OUTOFMEM;
				}
			}
			attrs1++;
		}
	}
	return 0;
}

static int
oc_add_sups(
    ObjectClass		*soc,
    char		**sups,
    const char		**err
)
{
	int		code;
	ObjectClass	*soc1;
	int		nsups;
	char		**sups1;
	int		add_sups = 0;

	if ( sups ) {
		if ( !soc->soc_sups ) {
			/* We are at the first recursive level */
			add_sups = 1;
			nsups = 0;
			sups1 = sups;
			while ( *sups1 ) {
				nsups++;
				sups1++;
			}
			nsups++;
			soc->soc_sups = (ObjectClass **)ch_calloc(1,
					  nsups*sizeof(ObjectClass *));
		}
		nsups = 0;
		sups1 = sups;
		while ( *sups1 ) {
			soc1 = oc_find(*sups1);
			if ( !soc1 ) {
				*err = *sups1;
				return SLAP_SCHERR_CLASS_NOT_FOUND;
			}

			if ( add_sups )
				soc->soc_sups[nsups] = soc1;

			code = oc_add_sups(soc,soc1->soc_sup_oids, err);
			if ( code )
				return code;

			code = oc_create_required(soc,soc1->soc_at_oids_must,err);
			if ( code )
				return code;
			code = oc_create_allowed(soc,soc1->soc_at_oids_may,err);
			if ( code )
				return code;

			nsups++;
			sups1++;
		}
	}
	return 0;
}

static int
oc_insert(
    ObjectClass		*soc,
    const char		**err
)
{
	ObjectClass	**ocp;
	struct oindexrec	*oir;
	char			**names;

	ocp = &oc_list;
	while ( *ocp != NULL ) {
		ocp = &(*ocp)->soc_next;
	}
	*ocp = soc;

	if ( soc->soc_oid ) {
		oir = (struct oindexrec *)
			ch_calloc( 1, sizeof(struct oindexrec) );
		oir->oir_name = soc->soc_oid;
		oir->oir_oc = soc;
		if ( avl_insert( &oc_index, (caddr_t) oir,
				 (AVL_CMP) oc_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = soc->soc_oid;
			ldap_memfree(oir);
			return SLAP_SCHERR_DUP_CLASS;
		}
		/* FIX: temporal consistency check */
		oc_find(oir->oir_name);
	}
	if ( (names = soc->soc_names) ) {
		while ( *names ) {
			oir = (struct oindexrec *)
				ch_calloc( 1, sizeof(struct oindexrec) );
			oir->oir_name = ch_strdup(*names);
			oir->oir_oc = soc;
			if ( avl_insert( &oc_index, (caddr_t) oir,
					 (AVL_CMP) oc_index_cmp,
					 (AVL_DUP) avl_dup_error ) ) {
				*err = *names;
				ldap_memfree(oir);
				return SLAP_SCHERR_DUP_CLASS;
			}
			/* FIX: temporal consistency check */
			oc_find(oir->oir_name);
			names++;
		}
	}
	return 0;
}

int
oc_add(
    LDAP_OBJECT_CLASS	*oc,
    const char		**err
)
{
	ObjectClass	*soc;
	int		code;

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	memcpy( &soc->soc_oclass, oc, sizeof(LDAP_OBJECT_CLASS));
	if ( (code = oc_add_sups(soc,soc->soc_sup_oids,err)) != 0 )
		return code;
	if ( (code = oc_create_required(soc,soc->soc_at_oids_must,err)) != 0 )
		return code;
	if ( (code = oc_create_allowed(soc,soc->soc_at_oids_may,err)) != 0 )
		return code;
	code = oc_insert(soc,err);
	return code;
}

struct sindexrec {
	char		*sir_name;
	Syntax		*sir_syn;
};

static Avlnode	*syn_index = NULL;
static Syntax *syn_list = NULL;

static int
syn_index_cmp(
    struct sindexrec	*sir1,
    struct sindexrec	*sir2
)
{
	return (strcmp( sir1->sir_name, sir2->sir_name ));
}

static int
syn_index_name_cmp(
    char 		*name,
    struct sindexrec	*sir
)
{
	return (strcmp( name, sir->sir_name ));
}

Syntax *
syn_find( const char *synname )
{
	struct sindexrec	*sir = NULL;

	if ( (sir = (struct sindexrec *) avl_find( syn_index, synname,
            (AVL_CMP) syn_index_name_cmp )) != NULL ) {
		return( sir->sir_syn );
	}
	return( NULL );
}

Syntax *
syn_find_desc( const char *syndesc, int *len )
{
	Syntax		*synp;

	for (synp = syn_list; synp; synp = synp->ssyn_next)
		if ((*len = dscompare( synp->ssyn_syn.syn_desc, syndesc, '{')))
			return synp;
	return( NULL );
}

static int
syn_insert(
    Syntax		*ssyn,
    const char		**err
)
{
	Syntax		**synp;
	struct sindexrec	*sir;

	synp = &syn_list;
	while ( *synp != NULL ) {
		synp = &(*synp)->ssyn_next;
	}
	*synp = ssyn;

	if ( ssyn->ssyn_oid ) {
		sir = (struct sindexrec *)
			ch_calloc( 1, sizeof(struct sindexrec) );
		sir->sir_name = ssyn->ssyn_oid;
		sir->sir_syn = ssyn;
		if ( avl_insert( &syn_index, (caddr_t) sir,
				 (AVL_CMP) syn_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = ssyn->ssyn_oid;
			ldap_memfree(sir);
			return SLAP_SCHERR_DUP_SYNTAX;
		}
		/* FIX: temporal consistency check */
		syn_find(sir->sir_name);
	}
	return 0;
}

int
syn_add(
    LDAP_SYNTAX		*syn,
	int flags,
    slap_syntax_validate_func	*validate,
    slap_syntax_transform_func	*ber2str,
    slap_syntax_transform_func	*str2ber,
    const char		**err
)
{
	Syntax		*ssyn;
	int		code;

	ssyn = (Syntax *) ch_calloc( 1, sizeof(Syntax) );
	memcpy( &ssyn->ssyn_syn, syn, sizeof(LDAP_SYNTAX));

	ssyn->ssyn_flags = flags;
	ssyn->ssyn_validate = validate;
	ssyn->ssyn_ber2str = ber2str;
	ssyn->ssyn_str2ber = str2ber;

	code = syn_insert(ssyn,err);
	return code;
}

struct mindexrec {
	char		*mir_name;
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
	return (strcmp( mir1->mir_name, mir2->mir_name ));
}

static int
mr_index_name_cmp(
    char 		*name,
    struct mindexrec	*mir
)
{
	return (strcmp( name, mir->mir_name ));
}

MatchingRule *
mr_find( const char *mrname )
{
	struct mindexrec	*mir = NULL;

	if ( (mir = (struct mindexrec *) avl_find( mr_index, mrname,
            (AVL_CMP) mr_index_name_cmp )) != NULL ) {
		return( mir->mir_mr );
	}
	return( NULL );
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
		mir->mir_name = smr->smr_oid;
		mir->mir_mr = smr;
		if ( avl_insert( &mr_index, (caddr_t) mir,
				 (AVL_CMP) mr_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = smr->smr_oid;
			ldap_memfree(mir);
			return SLAP_SCHERR_DUP_RULE;
		}
		/* FIX: temporal consistency check */
		mr_find(mir->mir_name);
	}
	if ( (names = smr->smr_names) ) {
		while ( *names ) {
			mir = (struct mindexrec *)
				ch_calloc( 1, sizeof(struct mindexrec) );
			mir->mir_name = ch_strdup(*names);
			mir->mir_mr = smr;
			if ( avl_insert( &mr_index, (caddr_t) mir,
					 (AVL_CMP) mr_index_cmp,
					 (AVL_DUP) avl_dup_error ) ) {
				*err = *names;
				ldap_memfree(mir);
				return SLAP_SCHERR_DUP_RULE;
			}
			/* FIX: temporal consistency check */
			mr_find(mir->mir_name);
			names++;
		}
	}
	return 0;
}

int
mr_add(
    LDAP_MATCHING_RULE		*mr,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
    slap_mr_match_func	*match,
	slap_mr_indexer_func *indexer,
    slap_mr_filter_func	*filter,
    const char		**err
)
{
	MatchingRule	*smr;
	Syntax		*syn;
	int		code;

	smr = (MatchingRule *) ch_calloc( 1, sizeof(MatchingRule) );
	memcpy( &smr->smr_mrule, mr, sizeof(LDAP_MATCHING_RULE));

	smr->smr_convert = convert;
	smr->smr_normalize = normalize;
	smr->smr_match = match;
	smr->smr_indexer = indexer;
	smr->smr_filter = filter;

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
register_syntax(
	char * desc, int flags,
	slap_syntax_validate_func *validate,
	slap_syntax_transform_func *ber2str,
	slap_syntax_transform_func *str2ber )
{
	LDAP_SYNTAX	*syn;
	int		code;
	const char	*err;

	syn = ldap_str2syntax( desc, &code, &err);
	if ( !syn ) {
		Debug( LDAP_DEBUG_ANY, "Error in register_syntax: %s before %s in %s\n",
		    ldap_scherr2str(code), err, desc );
		return( -1 );
	}

	code = syn_add( syn, flags, validate, ber2str, str2ber, &err );
	if ( code ) {
		Debug( LDAP_DEBUG_ANY, "Error in register_syntax: %s %s in %s\n",
		    scherr2str(code), err, desc );
		return( -1 );
	}

	return( 0 );
}

int
register_matching_rule(
	char * desc,
	slap_mr_convert_func *convert,
	slap_mr_normalize_func *normalize,
	slap_mr_match_func *match,
	slap_mr_indexer_func *indexer,
	slap_mr_filter_func *filter )
{
	LDAP_MATCHING_RULE *mr;
	int		code;
	const char	*err;

	mr = ldap_str2matchingrule( desc, &code, &err);
	if ( !mr ) {
		Debug( LDAP_DEBUG_ANY, "Error in register_matching_rule: %s before %s in %s\n",
		    ldap_scherr2str(code), err, desc );
		return( -1 );
	}

	code = mr_add( mr, convert, normalize, match, indexer, filter, &err );
	if ( code ) {
		Debug( LDAP_DEBUG_ANY, "Error in register_syntax: %s for %s in %s\n",
		    scherr2str(code), err, desc );
		return( -1 );
	}
	return( 0 );
}


#if defined( SLAPD_SCHEMA_DN )

static int
syn_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	Syntax		*syn;

	vals[0] = &val;
	vals[1] = NULL;

	for ( syn = syn_list; syn; syn = syn->ssyn_next ) {
		val.bv_val = ldap_syntax2str( &syn->ssyn_syn );
		if ( val.bv_val ) {
			val.bv_len = strlen( val.bv_val );
			Debug( LDAP_DEBUG_TRACE, "Merging syn [%ld] %s\n",
			       (long) val.bv_len, val.bv_val, 0 );
			attr_merge( e, "ldapSyntaxes", vals );
			ldap_memfree( val.bv_val );
		} else {
			return -1;
		}
	}
	return 0;
}

static int
mr_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	MatchingRule	*mr;

	vals[0] = &val;
	vals[1] = NULL;

	for ( mr = mr_list; mr; mr = mr->smr_next ) {
		val.bv_val = ldap_matchingrule2str( &mr->smr_mrule );
		if ( val.bv_val ) {
			val.bv_len = strlen( val.bv_val );
			Debug( LDAP_DEBUG_TRACE, "Merging mr [%ld] %s\n",
			       (long) val.bv_len, val.bv_val, 0 );
			attr_merge( e, "matchingRules", vals );
			ldap_memfree( val.bv_val );
		} else {
			return -1;
		}
	}
	return 0;
}

static int
oc_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	ObjectClass	*oc;

	vals[0] = &val;
	vals[1] = NULL;

	for ( oc = oc_list; oc; oc = oc->soc_next ) {
		val.bv_val = ldap_objectclass2str( &oc->soc_oclass );
		if ( val.bv_val ) {
			val.bv_len = strlen( val.bv_val );
			Debug( LDAP_DEBUG_TRACE, "Merging oc [%ld] %s\n",
			       (long) val.bv_len, val.bv_val, 0 );
			attr_merge( e, "objectClasses", vals );
			ldap_memfree( val.bv_val );
		} else {
			return -1;
		}
	}
	return 0;
}

void
schema_info( Connection *conn, Operation *op, char **attrs, int attrsonly )
{
	Entry		*e;
	struct berval	val;
	struct berval	*vals[2];

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	e->e_dn = ch_strdup( SLAPD_SCHEMA_DN );
	e->e_ndn = ch_strdup( SLAPD_SCHEMA_DN );
	(void) dn_normalize( e->e_ndn );
	e->e_private = NULL;

	{
		char *rdn = ch_strdup( SLAPD_SCHEMA_DN );
		val.bv_val = strchr( rdn, '=' );

		if( val.bv_val != NULL ) {
			*val.bv_val = '\0';
			val.bv_len = strlen( ++val.bv_val );

			attr_merge( e, rdn, vals );
		}

		free( rdn );
	}

	if ( syn_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	if ( mr_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	if ( at_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	if ( oc_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	
	val.bv_val = "top";
	val.bv_len = sizeof("top")-1;
	attr_merge( e, "objectClass", vals );

	val.bv_val = "LDAPsubentry";
	val.bv_len = sizeof("LDAPsubentry")-1;
	attr_merge( e, "objectClass", vals );

	val.bv_val = "subschema";
	val.bv_len = sizeof("subschema")-1;
	attr_merge( e, "objectClass", vals );

	val.bv_val = "extensibleObject";
	val.bv_len = sizeof("extensibleObject")-1;
	attr_merge( e, "objectClass", vals );

	send_search_entry( &backends[0], conn, op,
		e, attrs, attrsonly, NULL );
	send_search_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL, 1 );

	entry_free( e );
}
#endif

#ifdef LDAP_DEBUG

static void
oc_print( ObjectClass *oc )
{
	int	i;
	const char *mid;

	printf( "objectclass %s\n", ldap_objectclass2name( &oc->soc_oclass ) );
	if ( oc->soc_required != NULL ) {
		mid = "\trequires ";
		for ( i = 0; oc->soc_required[i] != NULL; i++, mid = "," )
			printf( "%s%s", mid,
			        ldap_attributetype2name( &oc->soc_required[i]->sat_atype ) );
		printf( "\n" );
	}
	if ( oc->soc_allowed != NULL ) {
		mid = "\tallows ";
		for ( i = 0; oc->soc_allowed[i] != NULL; i++, mid = "," )
			printf( "%s%s", mid,
			        ldap_attributetype2name( &oc->soc_allowed[i]->sat_atype ) );
		printf( "\n" );
	}
}

#endif

int is_entry_objectclass(
	Entry*	e,
	const char*	oc)
{
	Attribute *attr;
	struct berval bv;

	if( e == NULL || oc == NULL || *oc == '\0' )
		return 0;

	/*
	 * find objectClass attribute
	 */
	attr = attr_find(e->e_attrs, "objectclass");

	if( attr == NULL ) {
		/* no objectClass attribute */
		return 0;
	}

	bv.bv_val = (char *) oc;
	bv.bv_len = strlen( bv.bv_val );

#ifdef SLAPD_SCHEMA_COMPAT
	if( value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		/* entry is not of this objectclass */
		return 0;
	}
#endif

	return 1;
}
