/* syntax.c - routines to manage syntax definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"


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

#if defined( SLAPD_SCHEMA_DN )

int
syn_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	Syntax		*syn;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *ad_ldapSyntaxes = slap_schema.si_ad_ldapSyntaxes;
#else
	char *ad_ldapSyntaxes = "ldapSyntaxes";
#endif

	vals[0] = &val;
	vals[1] = NULL;

	for ( syn = syn_list; syn; syn = syn->ssyn_next ) {
		val.bv_val = ldap_syntax2str( &syn->ssyn_syn );
		if ( val.bv_val == NULL ) {
			return -1;
		}
		val.bv_len = strlen( val.bv_val );
		Debug( LDAP_DEBUG_TRACE, "Merging syn [%ld] %s\n",
	       (long) val.bv_len, val.bv_val, 0 );
		attr_merge( e, ad_ldapSyntaxes, vals );
		ldap_memfree( val.bv_val );
	}
	return 0;
}

#endif
