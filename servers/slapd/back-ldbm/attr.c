/* attr.c - backend routines for dealing with attributes */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

/* for the cache of attribute information (which are indexed, etc.) */
typedef struct ldbm_attrinfo {
	char	*ai_type;	/* type name (cn, sn, ...)	*/
	int	ai_indexmask;	/* how the attr is indexed	*/
} AttrInfo;

static int
ainfo_type_cmp(
    char		*type,
    AttrInfo	*a
)
{
	return( strcasecmp( type, a->ai_type ) );
}

static int
ainfo_cmp(
    AttrInfo	*a,
    AttrInfo	*b
)
{
	return( strcasecmp( a->ai_type, b->ai_type ) );
}

/*
 * Called when a duplicate "index" line is encountered.
 *
 * returns 1 => original from init code, indexmask updated
 *	   2 => original not from init code, warn the user
 */

static int
ainfo_dup(
    AttrInfo	*a,
    AttrInfo	*b
)
{
	/*
	 * if the duplicate definition is because we initialized the attr,
	 * just add what came from the config file. otherwise, complain.
	 */
	if ( a->ai_indexmask & SLAP_INDEX_FROMINIT ) {
		a->ai_indexmask |= b->ai_indexmask;

		return( 1 );
	}

	return( 2 );
}

void
attr_mask(
    struct ldbminfo	*li,
    char		*type,
    int			*indexmask )
{
	AttrInfo	*a;

	*indexmask = 0;
	if ( (a = (AttrInfo *) avl_find( li->li_attrs, type,
	    (AVL_CMP) ainfo_type_cmp )) == NULL ) {
		if ( (a = (AttrInfo *) avl_find( li->li_attrs, "default",
		    (AVL_CMP) ainfo_type_cmp )) == NULL ) {
			return;
		}
	}
	*indexmask = a->ai_indexmask;
}

void
attr_index_config(
    struct ldbminfo	*li,
    const char		*fname,
    int			lineno,
    int			argc,
    char		**argv,
    int			init
)
{
	int		i, j;
	char		**attrs, **indexes;
	AttrInfo	*a;

	attrs = str2charray( argv[0], "," );
	if ( argc > 1 ) {
		indexes = str2charray( argv[1], "," );
	}
	for ( i = 0; attrs[i] != NULL; i++ ) {
		a = (AttrInfo *) ch_malloc( sizeof(AttrInfo) );
		a->ai_type = ch_strdup( attrs[i] );

		if ( argc == 1 ) {
			a->ai_indexmask = (
				SLAP_INDEX_PRESENCE | SLAP_INDEX_EQUALITY |
			    SLAP_INDEX_APPROX | SLAP_INDEX_SUBSTR);
		} else {
			a->ai_indexmask = 0;
			for ( j = 0; indexes[j] != NULL; j++ ) {
				if ( strncasecmp( indexes[j],
					"pres", sizeof("pres")-1 ) == 0 )
				{
					a->ai_indexmask |= SLAP_INDEX_PRESENCE;

				} else if ( strncasecmp( indexes[j],
					"eq", sizeof("eq")-1 ) == 0 )
				{
					a->ai_indexmask |= SLAP_INDEX_EQUALITY;

				} else if ( strncasecmp( indexes[j],
					"approx", sizeof("approx")-1 ) == 0 )
				{
					a->ai_indexmask |= SLAP_INDEX_APPROX;

				} else if ( strncasecmp( indexes[j],
					"sub", sizeof("sub")-1 ) == 0 )
				{
					a->ai_indexmask |= SLAP_INDEX_SUBSTR;

				} else if ( strncasecmp( indexes[j],
					"none", sizeof("none")-1 ) == 0 )
				{
					if ( a->ai_indexmask != 0 ) {
						fprintf( stderr, "%s: line %d: "
							"index type \"none\" cannot be combined with other types\n",
						    fname, lineno );
					}
					a->ai_indexmask = 0;

				} else {
					fprintf( stderr, "%s: line %d: "
						"unknown index type \"%s\" (ignored)\n",
					    fname, lineno, indexes[j] );
					fprintf( stderr, "\tvalid index types are "
						"\"pres\", \"eq\", \"approx\", or \"sub\"\n" );
				}
			}
		}

		if ( init ) {
			a->ai_indexmask |= SLAP_INDEX_FROMINIT;
		}

		switch (avl_insert( &li->li_attrs, (caddr_t) a,
			(AVL_CMP) ainfo_cmp, (AVL_DUP) ainfo_dup ))
		{
		case 1:		/* duplicate - updating init version */
			free( a->ai_type );
			free( (char *) a );
			break;

		case 2:		/* user duplicate - ignore and warn */
			fprintf( stderr,
    "%s: line %d: duplicate index definition for attr \"%s\" (ignored)\n",
			    fname, lineno, a->ai_type );
			free( a->ai_type );
			free( (char *) a );
			break;

		default:;	/* inserted ok */
			/* FALL */
		}
	}
	charray_free( attrs );
	if ( argc > 1 )
		charray_free( indexes );
}


static void
ainfo_free( void *attr )
{
	AttrInfo *ai = attr;
	free( ai->ai_type );
	free( ai );
}

void
attr_index_destroy( Avlnode *tree )
{
	avl_free( tree, ainfo_free );
}

