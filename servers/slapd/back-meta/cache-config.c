/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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
 * This work was initially developed by the Apurva Kumar for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

#define MAX_ATTR_SETS 500 
static void find_supersets( struct attr_set* attr_sets, int numsets ); 
static int compare_sets( struct attr_set* setA, int, int );

int
meta_back_cache_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	struct metainfo *li = ( struct metainfo * )be->be_private;

	cache_manager* 	cm = li->cm; 
	query_manager*  qm = cm->qm;
	QueryTemplate* 	temp;
	AttributeName*  attr_name; 
	AttributeName* 	attrs;
	AttributeName* 	attrarray;
	const char* 	text=NULL; 

	int 		index, i; 
	int 		num; 

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: meta backend info is null!\n",
				fname, lineno );
		return 1;
	}

	if ( strcasecmp( argv[0], "cacheparams" ) == 0 ) {
		struct berval cache_suffix; 

		if ( argc < 6 ) {
			fprintf( stderr, "%s: line %d: missing arguments in \"cacheparams"
				" <thresh_lo> <thresh_hi> <numattrsets> <entry limit> "
				"<cycle_time>\" \n", fname, lineno );
			return( 1 );
		}

		cm->caching = 1;  
		cm->thresh_lo = atoi( argv[1] );
		cm->thresh_hi = atoi( argv[2] );
		if ( cm->thresh_hi <= cm->thresh_lo ) {
			fprintf( stderr, "%s: line %d: <thresh_lo> must be < <thresh_hi> "
				"in \"cacheparams <thresh_lo> <thresh_hi> <numattrsets> "
				"<entry limit> <cycle_time>\" \n", fname, lineno );
			return( 1 );
		}

		cm->numattrsets = atoi( argv[3] );
		if ( cm->numattrsets > MAX_ATTR_SETS ) {
			fprintf( stderr, "%s: line %d: <numattrsets> must be <= %d in "
				"\"cacheparams <thresh_lo> <thresh_hi> <numattrsets> "
				"<entry limit> <cycle_time>\" \n",
				fname, lineno, MAX_ATTR_SETS );
			return( 1 );
		}

		cm->num_entries_limit = atoi( argv[4] ); 
		cm->cc_period = atoi( argv[5] ); 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
				"Total # of attribute sets to be cached = %d\n",
				cm->numattrsets, 0, 0 ); 
#else
		Debug( LDAP_DEBUG_ANY,
				"Total # of attribute sets to be cached = %d\n",
				cm->numattrsets, 0, 0 ); 
#endif
		qm->attr_sets = ( struct attr_set * )malloc( cm->numattrsets *
			    			sizeof( struct attr_set ));
		for ( i = 0; i < cm->numattrsets; i++ ) {
			qm->attr_sets[i].attrs = NULL; 
		}
		rewrite_session( li->rwinfo, "cacheBase", be->be_nsuffix[0].bv_val,
					0, &cache_suffix.bv_val );
		if ( cache_suffix.bv_val != NULL ) {
			cache_suffix.bv_len = strlen( cache_suffix.bv_val );
		} else {
			cache_suffix = be->be_nsuffix[0];
		}
		li->glue_be = select_backend( &cache_suffix, 0, 1 );
		li->glue_be->be_flags |= SLAP_BFLAG_NO_SCHEMA_CHECK;
		if ( cache_suffix.bv_val != be->be_nsuffix[0].bv_val ) {
			ch_free( cache_suffix.bv_val );
		}

	} else if ( strcasecmp( argv[0], "attrset" ) == 0 ) {
		if ( argc < 3 ) {
			fprintf( stderr, "%s: line %d: missing arguments in \"attr-set "
				"<index> <attributes>\" line\n", fname, lineno );
			return( 1 );
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "Attribute Set # %d\n",
				atoi( argv[1] ), 0, 0 ); 
#else
		Debug( LDAP_DEBUG_ANY, "Attribute Set # %d\n",
				atoi( argv[1] ), 0, 0 ); 
#endif
		if (atoi(argv[1]) >= cm->numattrsets) {
			fprintf( stderr, "%s; line %d index out of bounds \n",
					fname, lineno );
			return 1; 
		} 
		index = atoi( argv[1] );
		if ( argv[2] && ( strcmp( argv[2], "*" ) != 0 )) {
			for ( i = 2; argv[i] != NULL; i++ ) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1, "\t %s\n",
						argv[i], 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "\t %s\n",
						argv[i], 0, 0 );
#endif
				attrs = qm->attr_sets[index].attrs;
				qm->attr_sets[index].attrs = (AttributeName*)realloc(
						attrs, i * sizeof( AttributeName ));
				attr_name = qm->attr_sets[index].attrs + ( i - 2 ); 
				ber_str2bv( argv[i], strlen(argv[i]), 1,
						&attr_name->an_name); 
				attr_name->an_desc = NULL; 
				slap_bv2ad( &attr_name->an_name,
						&attr_name->an_desc, &text );
				attr_name++; 
				attr_name->an_name.bv_val = NULL; 
				attr_name->an_name.bv_len = 0; 
			}
			qm->attr_sets[index].count = i - 2; 
		}
	} else if ( strcasecmp( argv[0], "addtemplate" ) == 0 ) {
		if ( argc != 4 ) {
			fprintf( stderr, "%s: line %d: missing argument(s) in "
				"\"addtemplate <filter> <proj attr set> <TTL>\" line\n",
				fname, lineno );
			return( 1 );
		}
		if (( i = atoi( argv[2] )) >= cm->numattrsets ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"%s: line %d, template index invalid\n",
					fname, lineno, 0 );  
#else
			Debug( LDAP_DEBUG_ANY,
					"%s: line %d, template index invalid\n",
					fname, lineno, 0 );  
#endif
			return 1; 
		}
		num = cm->numtemplates; 
		if ( num == 0 )
			find_supersets( qm->attr_sets, cm->numattrsets );
		qm->templates = ( QueryTemplate* )realloc( qm->templates,
				( num + 2 ) * sizeof( QueryTemplate ));
		temp = qm->templates + num; 
		ldap_pvt_thread_rdwr_init( &temp->t_rwlock ); 
		temp->query = temp->query_last = NULL;
		temp->ttl = atoi( argv[3] );
		temp->no_of_queries = 0; 
		if ( argv[1] == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, DETAIL1,
					"Templates string not specified "
					"for template %d\n", num, 0, 0 ); 
#else
			Debug( LDAP_DEBUG_ANY,
					"Templates string not specified "
					"for template %d\n", num, 0, 0 ); 
#endif
			return 1; 
		}
		temp->querystr = ch_strdup( argv[1] );
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "Template:\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "Template:\n", 0, 0, 0 );
#endif
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "  query template: %s\n",
				temp->querystr, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "  query template: %s\n",
				temp->querystr, 0, 0 );
#endif
		temp->attr_set_index = i; 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1, "  attributes: \n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "  attributes: \n", 0, 0, 0 );
#endif
		if ( ( attrarray = qm->attr_sets[i].attrs ) != NULL ) {
			for ( i=0; attrarray[i].an_name.bv_val; i++ ) 
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_META, DETAIL1, "\t%s\n",
					attrarray[i].an_name.bv_val, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "\t%s\n",
					attrarray[i].an_name.bv_val, 0, 0 );
#endif
		}
		temp++; 	
		temp->querystr = NULL; 
		cm->numtemplates++;
	} 
	/* anything else */
	else {
		fprintf( stderr, "%s: line %d: unknown directive \"%s\" in meta "
				"database definition (ignored)\n",
				fname, lineno, argv[0] );
	}
	return 0;
}

void
find_supersets ( struct attr_set* attr_sets, int numsets )
{
	int num[MAX_ATTR_SETS];
	int i, j, res;
	int* id_array;
	for ( i = 0; i < MAX_ATTR_SETS; i++ )
		num[i] = 0;

	for ( i = 0; i < numsets; i++ ) {
		attr_sets[i].ID_array = (int*) malloc( sizeof( int ) );
		attr_sets[i].ID_array[0] = -1; 
    	} 

	for ( i = 0; i < numsets; i++ ) {
		for ( j=i+1; j < numsets; j++ ) {
			res = compare_sets( attr_sets, i, j ); 
			switch ( res ) {
			case 0:
				break;
			case 3: 
			case 1: 
				id_array = attr_sets[i].ID_array; 
				attr_sets[i].ID_array = (int *) realloc( id_array,
							( num[i] + 2 ) * sizeof( int )); 
				attr_sets[i].ID_array[num[i]] = j; 
				attr_sets[i].ID_array[num[i]+1] = -1; 
				num[i]++;
				if (res == 1) 
					break;
			case 2: 
				id_array = attr_sets[j].ID_array; 
				attr_sets[j].ID_array = (int *) realloc( id_array,
						( num[j] + 2 ) * sizeof( int )); 
				attr_sets[j].ID_array[num[j]] = i; 
				attr_sets[j].ID_array[num[j]+1] = -1; 
				num[j]++;
				break;
			}
		}
	}
}

/* 
 * compares two sets of attributes (indices i and j) 
 * returns 0: if neither set is contained in the other set 
 *         1: if set i is contained in set j
 *         2: if set j is contained in set i
 *         3: the sets are equivalent 
 */

int 
compare_sets(struct attr_set* set, int i, int j)
{
	int k,l,numI,numJ;
	int common=0;
	int result=0;

	if (( set[i].attrs == NULL ) && ( set[j].attrs == NULL ))
		return 3;	

	if ( set[i].attrs == NULL )
		return 2; 

	if ( set[j].attrs == NULL )
		return 1; 
   
	numI = set[i].count; 
	numJ = set[j].count; 

	for ( l=0; l < numI; l++ ) {
		for ( k = 0; k < numJ; k++ ) {
			if ( strcmp( set[i].attrs[l].an_name.bv_val,
				     set[j].attrs[k].an_name.bv_val ) == 0 )
				common++;	
		}
	}

	if ( common == numI )
		result = 1; 

	if ( common == numJ )
		result += 2;

	return result; 
}
