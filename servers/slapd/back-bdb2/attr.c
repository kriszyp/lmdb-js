/* attr.c - backend routines for dealing with attributes */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"

static int
ainfo_type_cmp(
    char		*type,
    struct attrinfo	*a
)
{
	return( strcasecmp( type, a->ai_type ) );
}

static int
ainfo_cmp(
    struct attrinfo	*a,
    struct attrinfo	*b
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
    struct attrinfo	*a,
    struct attrinfo	*b
)
{
	/*
	 * if the duplicate definition is because we initialized the attr,
	 * just add what came from the config file. otherwise, complain.
	 */
	if ( a->ai_indexmask & INDEX_FROMINIT ) {
		a->ai_indexmask |= b->ai_indexmask;

		return( 1 );
	}

	return( 2 );
}

void
bdb2i_attr_masks(
    struct ldbminfo	*li,
    char		*type,
    int			*indexmask,
    int			*syntaxmask
)
{
	struct attrinfo	*a;

	*indexmask = 0;
	*syntaxmask = 0;
	if ( (a = (struct attrinfo *) avl_find( li->li_attrs, type,
	    (AVL_CMP) ainfo_type_cmp )) == NULL ) {
		if ( (a = (struct attrinfo *) avl_find( li->li_attrs, "default",
		    (AVL_CMP) ainfo_type_cmp )) == NULL ) {
			return;
		}
	}
	*indexmask = a->ai_indexmask;
	if ( strcasecmp( a->ai_type, "default" ) == 0 ) {
		*syntaxmask = attr_syntax( type );
	} else {
		*syntaxmask = a->ai_syntaxmask;
	}
}


/*  BDB2 changed  */
void
bdb2i_attr_index_config(
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
	struct attrinfo	*a;

	attrs = str2charray( argv[0], "," );
	if ( argc > 1 ) {
		indexes = str2charray( argv[1], "," );
	}
	for ( i = 0; attrs[i] != NULL; i++ ) {
		a = (struct attrinfo *) ch_malloc( sizeof(struct attrinfo) );
		a->ai_type = ch_strdup( attrs[i] );
		a->ai_syntaxmask = attr_syntax( a->ai_type );
		if ( argc == 1 ) {
			a->ai_indexmask = (INDEX_PRESENCE | INDEX_EQUALITY |
			    INDEX_APPROX | INDEX_SUB);
		} else {
			a->ai_indexmask = 0;
			for ( j = 0; indexes[j] != NULL; j++ ) {
				if ( strncasecmp( indexes[j], "pres", 4 )
				    == 0 ) {
					a->ai_indexmask |= INDEX_PRESENCE;
				} else if ( strncasecmp( indexes[j], "eq", 2 )
				    == 0 ) {
					a->ai_indexmask |= INDEX_EQUALITY;
				} else if ( strncasecmp( indexes[j], "approx",
				    6 ) == 0 ) {
					a->ai_indexmask |= INDEX_APPROX;
				} else if ( strncasecmp( indexes[j], "sub", 3 )
				    == 0 ) {
					a->ai_indexmask |= INDEX_SUB;
				} else if ( strncasecmp( indexes[j], "none", 4 )
				    == 0 ) {
					if ( a->ai_indexmask != 0 ) {
						fprintf( stderr,
"%s: line %d: index type \"none\" cannot be combined with other types\n",
						    fname, lineno );
					}
					a->ai_indexmask = 0;
				} else {
					fprintf( stderr,
			"%s: line %d: unknown index type \"%s\" (ignored)\n",
					    fname, lineno, indexes[j] );
					fprintf( stderr,
	"valid index types are \"pres\", \"eq\", \"approx\", or \"sub\"\n" );
				}
			}
		}
		if ( init ) {
			a->ai_indexmask |= INDEX_FROMINIT;
		} else {
			if ( a->ai_indexmask )
				bdb2i_txn_attr_config( li, a->ai_type, 0 );
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
