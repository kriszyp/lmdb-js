/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2008 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENT:
 * This work was initially developed by Pierangelo Masarati for
 * inclusion in OpenLDAP Software.
 */

#include <portable.h>

#define LDAP_DEPRECATED 1
#include "rewrite-int.h"
#include "rewrite-map.h"

/*
 * LDAP map data structure
 */
struct ldap_map_data {
	char                           *lm_url;
	LDAPURLDesc                    *lm_lud;
	int                             lm_attrsonly;
	char                           *lm_binddn;
	char                           *lm_bindpw;

#define MAP_LDAP_EVERYTIME		0x00
#define MAP_LDAP_NOW			0x01
#define MAP_LDAP_LATER			0x02
	int                             lm_when;

	LDAP                           *lm_ld;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_mutex_t         lm_mutex;
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
};

static void
map_ldap_free(
		struct ldap_map_data *data
)
{
	assert( data != NULL );

	if ( data->lm_url != NULL ) {
		free( data->lm_url );
	}

	if ( data->lm_lud != NULL ) {
		ldap_free_urldesc( data->lm_lud );
	}

	if ( data->lm_binddn != NULL ) {
		free( data->lm_binddn );
	}

	if ( data->lm_bindpw != NULL ) {
		free( data->lm_bindpw );
	}

	if ( data->lm_when != MAP_LDAP_EVERYTIME && data->lm_ld != NULL ) {
		ldap_unbind_s( data->lm_ld );
	}

	free( data );
}

void *
map_ldap_parse(
		struct rewrite_info *info,
		const char *fname,
		int lineno,
		int argc,
		char **argv
)
{
	struct ldap_map_data *data;
	char *p;

	assert( info != NULL );
	assert( fname != NULL );
	assert( argv != NULL );

	data = calloc( sizeof( struct ldap_map_data ), 1 );
	if ( data == NULL ) {
		return NULL;
	}

	if ( argc < 1 ) {
		Debug( LDAP_DEBUG_ANY,
				"[%s:%d] ldap map needs URI\n%s",
				fname, lineno, "" );
		free( data );
		return NULL;
	}

	data->lm_url = strdup( argv[ 0 ] );
	if ( data->lm_url == NULL ) {
		map_ldap_free( data );
		return NULL;
	}
	
	if ( ldap_url_parse( argv[ 0 ], &data->lm_lud ) != REWRITE_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
				"[%s:%d] illegal URI '%s'\n",
				fname, lineno, argv[ 0 ] );
		map_ldap_free( data );
		return NULL;
	}

	p = strchr( data->lm_url, '/' );
	assert( p[ 1 ] == '/' );
	if ( ( p = strchr( p + 2, '/' ) ) != NULL ) {
		p[ 0 ] = '\0';
	}

	if ( strcasecmp( data->lm_lud->lud_attrs[ 0 ], "dn" ) == 0 ) {
		data->lm_attrsonly = 1;
	}
	      
	for ( argc--, argv++; argc > 0; argc--, argv++ ) {
		if ( strncasecmp( argv[ 0 ], "binddn=", 7 ) == 0 ) {
			char *p = argv[ 0 ] + 7;
			int l;

			if ( p[ 0 ] == '\"' || p [ 0 ] == '\'' ) {
				l = strlen( p ) - 2;
				p++;
				if ( p[ l ] != p[ 0 ] ) {
					map_ldap_free( data );
					return NULL;
				}
			} else {
				l = strlen( p );
			}
			
			data->lm_binddn = strdup( p );			
			if ( data->lm_binddn == NULL ) {
				map_ldap_free( data );
				return NULL;
			}

			if ( data->lm_binddn[ l ] == '\"' 
					|| data->lm_binddn[ l ] == '\'' ) {
				data->lm_binddn[ l ] = '\0';
			}
		} else if ( strncasecmp( argv[ 0 ], "bindpw=", 7 ) == 0 ) {
			data->lm_bindpw = strdup( argv[ 0 ] + 7 );
			if ( data->lm_bindpw == NULL ) {
				map_ldap_free( data );
				return NULL;
			}
		} else if ( strncasecmp( argv[ 0 ], "bindwhen=", 9 ) == 0 ) {
			char *p = argv[ 0 ] + 9;

			if ( strcasecmp( p, "now" ) == 0 ) {
				int rc;
				
				data->lm_when = MAP_LDAP_NOW;
				
				/*
				 * Init LDAP handler ...
				 */
				rc = ldap_initialize( &data->lm_ld, data->lm_url );
				if ( rc != LDAP_SUCCESS ) {
					map_ldap_free( data );
					return NULL;
				}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_init( &data->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

			} else if ( strcasecmp( p, "later" ) == 0 ) {
				data->lm_when = MAP_LDAP_LATER;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_init( &data->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

			} else if ( strcasecmp( p, "everytime" ) == 0 ) {
				data->lm_when = MAP_LDAP_EVERYTIME;
			} else {
				/* ignore ... */
			}
		}
	}

	return ( void * )data;
}

int
map_ldap_apply(
		struct rewrite_builtin_map *map,
		const char *filter,
		struct berval *val

)
{
	LDAP *ld;
	LDAPMessage *res = NULL, *entry;
	char **values;
	int rc;
	struct ldap_map_data *data = ( struct ldap_map_data * )map->lb_private;
	LDAPURLDesc *lud = data->lm_lud;
	
	int first_try = 1;

	assert( map != NULL );
	assert( map->lb_type == REWRITE_BUILTIN_MAP_LDAP );
	assert( map->lb_private != NULL );
	assert( filter != NULL );
	assert( val != NULL );

	val->bv_val = NULL;
	val->bv_len = 0;

	if ( data->lm_when == MAP_LDAP_EVERYTIME ) {
		rc = ldap_initialize( &ld, data->lm_url );

	} else {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_lock( &data->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		rc = LDAP_SUCCESS;

		if ( data->lm_when == MAP_LDAP_LATER && data->lm_ld == NULL ) {
			rc = ldap_initialize( &data->lm_ld, data->lm_url );
		}
		
		ld = data->lm_ld;
	}

	if ( rc != LDAP_SUCCESS ) {
		rc = REWRITE_ERR;
		goto rc_return;
	}

do_bind:;
	if ( data->lm_binddn != NULL ) {
		rc = ldap_simple_bind_s( ld, data->lm_binddn, data->lm_bindpw );
		if ( rc == LDAP_SERVER_DOWN && first_try ) {
			first_try = 0;
			if ( ldap_initialize( &ld, data->lm_url ) != LDAP_SUCCESS ) {
				rc = REWRITE_ERR;
				goto rc_return;
			}
			goto do_bind;

		} else if ( rc != REWRITE_SUCCESS ) {
			rc = REWRITE_ERR;
			goto rc_return;
		}
	}

	rc = ldap_search_s( ld, lud->lud_dn, lud->lud_scope, ( char * )filter,
			lud->lud_attrs, data->lm_attrsonly, &res );
	if ( rc == LDAP_SERVER_DOWN && first_try ) {
		first_try = 0;
                if ( ldap_initialize( &ld, data->lm_url ) != LDAP_SUCCESS ) {
			rc = REWRITE_ERR;
			goto rc_return;
		}
		goto do_bind;

	} else if ( rc != REWRITE_SUCCESS ) {
		rc = REWRITE_ERR;
		goto rc_return;
	}

	if ( ldap_count_entries( ld, res ) != 1 ) {
		ldap_msgfree( res );
		rc = REWRITE_ERR;
		goto rc_return;
	}

	entry = ldap_first_entry( ld, res );
	assert( entry != NULL );

	if ( data->lm_attrsonly == 1 ) {
		/*
		 * dn is newly allocated, so there's no need to strdup it
		 */
		val->bv_val = ldap_get_dn( ld, entry );

	} else {
		values = ldap_get_values( ld, entry, lud->lud_attrs[ 0 ] );
		if ( values == NULL || values[ 0 ] == NULL ) {
			if ( values != NULL ) {
				ldap_value_free( values );
			}
			ldap_msgfree( res );
			rc = REWRITE_ERR;
			goto rc_return;
		}
		val->bv_val = strdup( values[ 0 ] );
		ldap_value_free( values );
	}
	
	ldap_msgfree( res );

	if ( val->bv_val == NULL ) {
		rc = REWRITE_ERR;
		goto rc_return;
	}
	val->bv_len = strlen( val->bv_val );

rc_return:;
	if ( data->lm_when == MAP_LDAP_EVERYTIME ) {
		if ( ld != NULL ) {
			ldap_unbind_s( ld );
		}

	} else {
		data->lm_ld = ld;
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_unlock( &data->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	}
	
	return rc;
}

int
map_ldap_destroy(
		struct rewrite_builtin_map **pmap
)
{
	struct ldap_map_data *data;

	assert( pmap != NULL );
	assert( *pmap != NULL );
	
	data = ( struct ldap_map_data * )(*pmap)->lb_private;

	if ( data->lm_when != MAP_LDAP_EVERYTIME && data->lm_ld != NULL ) {
		ldap_unbind_s( data->lm_ld );
		data->lm_ld = NULL;
	}

	if ( data->lm_lud ) {
		ldap_free_urldesc( data->lm_lud );
		data->lm_lud = NULL;
	}

	if ( data->lm_url ) {
		free( data->lm_url );
		data->lm_url = NULL;
	}

	if ( data->lm_binddn ) {
		free( data->lm_binddn );
		data->lm_binddn = NULL;
	}

	if (data->lm_bindpw ) {
		memset( data->lm_bindpw, 0, strlen( data->lm_bindpw ) );
		free( data->lm_bindpw );
		data->lm_bindpw = NULL;
	}
	
	free( data );
	(*pmap)->lb_private = NULL;

	return 0;
}

