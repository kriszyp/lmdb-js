/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* at.c - routines for dealing with attribute types */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_pvt.h"
#include "slap.h"

#ifndef SLAPD_SCHEMA_NOT_COMPAT
char *
at_canonical_name( const char * a_type )
{
	AttributeType	*atp;

	atp=at_find(a_type);

	if ( atp == NULL ) {
		return (char *) a_type;

	} else if ( atp->sat_names
		&& atp->sat_names[0] && (*(atp->sat_names[0]) != '\0') )
	{
		return atp->sat_names[0];

	} else if (atp->sat_oid && (*atp->sat_oid != '\0')) {
		return atp->sat_oid;
	}

	return (char *) a_type;
}

#define DEFAULT_SYNTAX	SYNTAX_CIS

/*
 * attr_syntax - return the syntax of attribute type
 */

int
attr_syntax( const char *type )
{
	AttributeType	*sat;

	sat = at_find(type);
	if ( sat ) {
		return( sat->sat_syntax_compat );
	}

	return( DEFAULT_SYNTAX );
}

/*
 * attr_syntax_config - process an attribute syntax config line
 */

void
at_config(
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	char			*save;
	LDAP_ATTRIBUTE_TYPE	*at;
	int			lasti;
	int			code;
	const char		*err;

	if ( argc < 2 ) {
		Debug( LDAP_DEBUG_ANY,
"%s: line %d: missing name in \"attribute <name>+ <syntax>\" (ignored)\n",
		    fname, lineno, 0 );
		return;
	}

	at = (LDAP_ATTRIBUTE_TYPE *)
		ch_calloc( 1, sizeof(LDAP_ATTRIBUTE_TYPE) );

#define SYNTAX_DS_OID	"1.3.6.1.4.1.1466.115.121.1.15"
#define SYNTAX_DSCE_OID	"2.5.13.5"
#define SYNTAX_IA5_OID	"1.3.6.1.4.1.1466.115.121.1.26"
#define SYNTAX_IA5CE_OID	"1.3.6.1.4.1.1466.109.114.1"
#define SYNTAX_DN_OID	SLAPD_OID_DN_SYNTAX
#define SYNTAX_TEL_OID	"1.3.6.1.4.1.1466.115.121.1.50"
#define SYNTAX_BIN_OID	"1.3.6.1.4.1.1466.115.121.1.40" /* octetString */

	lasti = argc - 1;
	if ( strcasecmp( argv[lasti], "caseignorestring" ) == 0 ||
	    strcasecmp( argv[lasti], "cis" ) == 0 ) {
		at->at_syntax_oid = SYNTAX_DS_OID;
		at->at_equality_oid = "2.5.13.2";
		at->at_ordering_oid = "2.5.13.3";
		at->at_substr_oid = "2.5.13.4";

	} else if ( strcasecmp( argv[lasti], "telephone" ) == 0 ||
	    strcasecmp( argv[lasti], "tel" ) == 0 ) {
		at->at_syntax_oid = SYNTAX_TEL_OID;
		at->at_equality_oid = "2.5.13.20";
		at->at_substr_oid = "2.5.13.21";

	} else if ( strcasecmp( argv[lasti], "dn" ) == 0 ) {
		at->at_syntax_oid = SYNTAX_DN_OID;
		at->at_equality_oid = "2.5.13.1";

	} else if ( strcasecmp( argv[lasti], "caseexactstring" ) == 0 ||
	    strcasecmp( argv[lasti], "ces" ) == 0 ) {
		at->at_syntax_oid = SYNTAX_DS_OID;
		at->at_equality_oid = SYNTAX_DSCE_OID;
		at->at_ordering_oid = "2.5.13.6";
		at->at_substr_oid = "2.5.13.7";

	} else if ( strcasecmp( argv[lasti], "binary" ) == 0 ||
	    strcasecmp( argv[lasti], "bin" ) == 0 ) {
		/* bin -> octetString, not binary! */
		at->at_syntax_oid = SYNTAX_BIN_OID;
		at->at_equality_oid = "2.5.13.17";

	} else {
		Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: unknown syntax \"%s\" in attribute line (ignored)\n",
		    fname, lineno, argv[lasti] );
		Debug( LDAP_DEBUG_ANY,
    "possible syntaxes are \"cis\", \"ces\", \"tel\", \"dn\", or \"bin\"\n",
		    0, 0, 0 );
		free( (AttributeType *) at );
		return;
	}

	save = argv[lasti];
	argv[lasti] = NULL;
	at->at_names = charray_dup( argv );
	argv[lasti] = save;

	code = at_add( at, &err );
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
	}

	ldap_memfree(at);
}

int
at_fake_if_needed(
    const char	*name
)
{
	char *argv[3];

	if ( at_find( name ) ) {
		return 0;
	} else {
		argv[0] = (char*) name;
		argv[1] = "cis";
		argv[2] = NULL;
		at_config( "implicit", 0, 2, argv );
		return 0;
	}
}

#endif



struct aindexrec {
	char		*air_name;
	AttributeType	*air_at;
};

static Avlnode	*attr_index = NULL;
static AttributeType *attr_list = NULL;

static int
attr_index_cmp(
    struct aindexrec	*air1,
    struct aindexrec	*air2
)
{
	return (strcasecmp( air1->air_name, air2->air_name ));
}

static int
attr_index_name_cmp(
    char 		*type,
    struct aindexrec	*air
)
{
	return (strcasecmp( type, air->air_name ));
}

AttributeType *
at_find(
    const char		*name
)
{
	struct aindexrec	*air;
	char			*tmpname;

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	/*
	 * The name may actually be an AttributeDescription, i.e. it may
	 * contain options.
	 */
	/* Treat any attribute type with option as an unknown attribute type */
	char *p = strchr( name, ';' );
	if ( p ) {
		tmpname = ch_malloc( p-name+1 );
		strncpy( tmpname, name, p-name );
		tmpname[p-name] = '\0';
	} else
#endif
	{
		tmpname = (char *)name;
	}

	if ( (air = (struct aindexrec *) avl_find( attr_index, tmpname,
            (AVL_CMP) attr_index_name_cmp )) != NULL ) {
		if ( tmpname != name )
			ldap_memfree( tmpname );
		return( air->air_at );
	}

	if ( tmpname != name )
		ldap_memfree( tmpname );
	return( NULL );
}

int
at_append_to_list(
    AttributeType	*sat,
    AttributeType	***listp
)
{
	AttributeType	**list;
	AttributeType	**list1;
	int		size;

	list = *listp;
	if ( !list ) {
		size = 2;
		list = calloc(size, sizeof(AttributeType *));
		if ( !list ) {
			return -1;
		}
	} else {
		size = 0;
		list1 = *listp;
		while ( *list1 ) {
			size++;
			list1++;
		}
		size += 2;
		list1 = realloc(list, size*sizeof(AttributeType *));
		if ( !list1 ) {
			return -1;
		}
		list = list1;
	}
	list[size-2] = sat;
	list[size-1] = NULL;
	*listp = list;
	return 0;
}

int
at_delete_from_list(
    int			pos,
    AttributeType	***listp
)
{
	AttributeType	**list;
	AttributeType	**list1;
	int		i;
	int		j;

	if ( pos < 0 ) {
		return -2;
	}
	list = *listp;
	for ( i=0; list[i]; i++ )
		;
	if ( pos >= i ) {
		return -2;
	}
	for ( i=pos, j=pos+1; list[j]; i++, j++ ) {
		list[i] = list[j];
	}
	list[i] = NULL;
	/* Tell the runtime this can be shrinked */
	list1 = realloc(list, (i+1)*sizeof(AttributeType **));
	if ( !list1 ) {
		return -1;
	}
	*listp = list1;
	return 0;
}

int
at_find_in_list(
    AttributeType	*sat,
    AttributeType	**list
)
{
	int	i;

	if ( !list ) {
		return -1;
	}
	for ( i=0; list[i]; i++ ) {
		if ( sat == list[i] ) {
			return i;
		}
	}
	return -1;
}

static int
at_insert(
    AttributeType	*sat,
    const char		**err
)
{
	AttributeType		**atp;
	struct aindexrec	*air;
	char			**names;

	atp = &attr_list;
	while ( *atp != NULL ) {
		atp = &(*atp)->sat_next;
	}
	*atp = sat;

	if ( sat->sat_oid ) {
		air = (struct aindexrec *)
			ch_calloc( 1, sizeof(struct aindexrec) );
		air->air_name = sat->sat_oid;
		air->air_at = sat;
		if ( avl_insert( &attr_index, (caddr_t) air,
				 (AVL_CMP) attr_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = sat->sat_oid;
			ldap_memfree(air);
			return SLAP_SCHERR_DUP_ATTR;
		}
		/* FIX: temporal consistency check */
		at_find(air->air_name);
	}

	if ( (names = sat->sat_names) ) {
		while ( *names ) {
			air = (struct aindexrec *)
				ch_calloc( 1, sizeof(struct aindexrec) );
			air->air_name = ch_strdup(*names);
			air->air_at = sat;
			if ( avl_insert( &attr_index, (caddr_t) air,
					 (AVL_CMP) attr_index_cmp,
					 (AVL_DUP) avl_dup_error ) ) {
				*err = *names;
				ldap_memfree(air->air_name);
				ldap_memfree(air);
				return SLAP_SCHERR_DUP_ATTR;
			}
			/* FIX: temporal consistency check */
			at_find(air->air_name);
			names++;
		}
	}

	return 0;
}

int
at_add(
    LDAP_ATTRIBUTE_TYPE	*at,
    const char		**err
)
{
	AttributeType	*sat;
	MatchingRule	*mr;
	Syntax		*syn;
	int		code;
	char			*cname;

	if ( at->at_names && at->at_names[0] ) {
		cname = at->at_names[0];
	} else if ( at->at_oid ) {
		cname = at->at_oid;
	} else {
		cname = "";
		return SLAP_SCHERR_ATTR_INCOMPLETE;
	}
	sat = (AttributeType *) ch_calloc( 1, sizeof(AttributeType) );
	memcpy( &sat->sat_atype, at, sizeof(LDAP_ATTRIBUTE_TYPE));

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	sat->sat_cname = cname;
#endif

	if ( at->at_sup_oid ) {
		AttributeType *supsat = at_find(at->at_sup_oid);

		if ( (supsat == NULL ) ) {
			*err = at->at_sup_oid;
			return SLAP_SCHERR_ATTR_NOT_FOUND;
		}

		sat->sat_sup = supsat;

		if ( at_append_to_list(sat, &supsat->sat_subtypes) ) {
			*err = cname;
			return SLAP_SCHERR_OUTOFMEM;
		}
	}

	/*
	 * Inherit definitions from superiors.  We only check the
	 * direct superior since that one has already inherited from
	 * its own superiorss
	 */
	if ( sat->sat_sup ) {
		sat->sat_syntax = sat->sat_sup->sat_syntax;

		sat->sat_equality = sat->sat_sup->sat_equality;
		sat->sat_ordering = sat->sat_sup->sat_ordering;
		sat->sat_substr = sat->sat_sup->sat_substr;
	}

	if ( at->at_syntax_oid ) {
		if ( (syn = syn_find(sat->sat_syntax_oid)) ) {
			sat->sat_syntax = syn;
		} else {
			*err = sat->sat_syntax_oid;
			return SLAP_SCHERR_SYN_NOT_FOUND;
		}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
		if ( !strcmp(at->at_syntax_oid, SYNTAX_DS_OID) ) {
			if ( at->at_equality_oid && (
				!strcmp(at->at_equality_oid, SYNTAX_DSCE_OID) ) )
			{
				sat->sat_syntax_compat = SYNTAX_CES;
			} else {
				sat->sat_syntax_compat = SYNTAX_CIS;
			}

		} else if ( !strcmp(at->at_syntax_oid, SYNTAX_IA5_OID) ) {
			if ( at->at_equality_oid && (
				!strcmp(at->at_equality_oid, SYNTAX_IA5CE_OID) ) )
			{
				sat->sat_syntax_compat = SYNTAX_CES;
			} else {
				sat->sat_syntax_compat = SYNTAX_CIS;
			}

		} else if ( !strcmp(at->at_syntax_oid, SYNTAX_DN_OID ) ) {
			sat->sat_syntax_compat = SYNTAX_CIS | SYNTAX_DN;

		} else if ( !strcmp(at->at_syntax_oid, SYNTAX_TEL_OID ) ) {
			sat->sat_syntax_compat = SYNTAX_CIS | SYNTAX_TEL;

		} else if ( !strcmp(at->at_syntax_oid, SYNTAX_BIN_OID ) ) {
			sat->sat_syntax_compat = SYNTAX_BIN;

		} else {
			sat->sat_syntax_compat = DEFAULT_SYNTAX;
		}
#endif

	} else if ( sat->sat_syntax == NULL ) {
		return SLAP_SCHERR_ATTR_INCOMPLETE;
	}

	if ( sat->sat_equality_oid ) {
		if ( (mr = mr_find(sat->sat_equality_oid)) ) {
			sat->sat_equality = mr;
		} else {
			*err = sat->sat_equality_oid;
			return SLAP_SCHERR_MR_NOT_FOUND;
		}

	}

	if ( sat->sat_ordering_oid ) {
		if ( (mr = mr_find(sat->sat_ordering_oid)) ) {
			sat->sat_ordering = mr;
		} else {
			*err = sat->sat_ordering_oid;
			return SLAP_SCHERR_MR_NOT_FOUND;
		}
	}

	if ( sat->sat_substr_oid ) {
		if ( (mr = mr_find(sat->sat_substr_oid)) ) {
			sat->sat_substr = mr;
		} else {
			*err = sat->sat_substr_oid;
			return SLAP_SCHERR_MR_NOT_FOUND;
		}
	}

	code = at_insert(sat,err);
	return code;
}

#ifdef LDAP_DEBUG
static int
at_index_printnode( struct aindexrec *air )
{

	printf("%s = %s\n",
		air->air_name,
		ldap_attributetype2str(&air->air_at->sat_atype) );
	return( 0 );
}

static void
at_index_print( void )
{
	printf("Printing attribute type index:\n");
	(void) avl_apply( attr_index, (AVL_APPLY) at_index_printnode,
		0, -1, AVL_INORDER );
}
#endif

#if defined( SLAPD_SCHEMA_DN )
int
at_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	AttributeType	*at;

	vals[0] = &val;
	vals[1] = NULL;

	for ( at = attr_list; at; at = at->sat_next ) {
		val.bv_val = ldap_attributetype2str( &at->sat_atype );
		if ( val.bv_val ) {
			val.bv_len = strlen( val.bv_val );
			Debug( LDAP_DEBUG_TRACE, "Merging at [%ld] %s\n",
			       (long) val.bv_len, val.bv_val, 0 );
			attr_merge( e, "attributeTypes", vals );
			ldap_memfree( val.bv_val );
		} else {
			return -1;
		}
	}
	return 0;
}
#endif
