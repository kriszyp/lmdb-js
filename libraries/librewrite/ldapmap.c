/******************************************************************************
 *
 * Copyright (C) 2000 Pierangelo Masarati, <ando@sys-net.it>
 * All rights reserved.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users
 * ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 ******************************************************************************/

#include <portable.h>

#include "rewrite-int.h"
#include "rewrite-map.h"

/*
 * LDAP map data structure
 */
struct ldap_map_data {
	char                           *url;
	LDAPURLDesc                    *lud;
	int                             attrsonly;
	char                           *binddn;
	char                           *bindpw;

#define MAP_LDAP_EVERYTIME		0x00
#define MAP_LDAP_NOW			0x01
#define MAP_LDAP_LATER			0x02
	int                             when;

	LDAP                           *ld;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
	ldap_pvt_thread_mutex_t         mutex;
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
};

static void
map_ldap_free(
		struct ldap_map_data *data
)
{
	assert( data != NULL );

	if ( data->url != NULL ) {
		free( data->url );
	}

	if ( data->lud != NULL ) {
		ldap_free_urldesc( data->lud );
	}

	if ( data->binddn != NULL ) {
		free( data->binddn );
	}

	if ( data->bindpw != NULL ) {
		free( data->bindpw );
	}

	if ( data->when != MAP_LDAP_EVERYTIME && data->ld != NULL ) {
		ldap_unbind_s( data->ld );
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

	data->url = strdup( argv[ 0 ] );
	if ( data->url == NULL ) {
		map_ldap_free( data );
		return NULL;
	}
	
	if ( ldap_url_parse( argv[ 0 ], &data->lud ) != REWRITE_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
				"[%s:%d] illegal URI '%s'\n",
				fname, lineno, argv[ 0 ] );
		map_ldap_free( data );
		return NULL;
	}

	p = strchr( data->url, '/' );
	assert( p[ 1 ] == '/' );
	if ( ( p = strchr( p + 2, '/' ) ) != NULL ) {
		p[ 0 ] = '\0';
	}

	if ( strcasecmp( data->lud->lud_attrs[ 0 ], "dn" ) == 0 ) {
		data->attrsonly = 1;
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
			
			data->binddn = strdup( p );			
			if ( data->binddn == NULL ) {
				map_ldap_free( data );
				return NULL;
			}

			if ( data->binddn[ l ] == '\"' 
					|| data->binddn[ l ] == '\'' ) {
				data->binddn[ l ] = '\0';
			}
		} else if ( strncasecmp( argv[ 0 ], "bindpw=", 7 ) == 0 ) {
			data->bindpw = strdup( argv[ 2 ] + 7 );
			if ( data->bindpw == NULL ) {
				map_ldap_free( data );
				return NULL;
			}
		} else if ( strncasecmp( argv[ 0 ], "bindwhen=", 9 ) == 0 ) {
			char *p = argv[ 0 ] + 9;

			if ( strcasecmp( p, "now" ) == 0 ) {
				int rc;
				
				data->when = MAP_LDAP_NOW;
				
				/*
				 * Init LDAP handler ...
				 */
				rc = ldap_initialize( &data->ld, data->url );
				if ( rc != LDAP_SUCCESS ) {
					map_ldap_free( data );
					return NULL;
				}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_init( &data->mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

			} else if ( strcasecmp( p, "later" ) == 0 ) {
				data->when = MAP_LDAP_LATER;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_init( &data->mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

			} else if ( strcasecmp( p, "everytime" ) == 0 ) {
				data->when = MAP_LDAP_EVERYTIME;
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
	LDAPURLDesc *lud = data->lud;
	
	int first_try = 1;

	assert( map != NULL );
	assert( map->lb_type == REWRITE_BUILTIN_MAP_LDAP );
	assert( map->lb_private != NULL );
	assert( filter != NULL );
	assert( val != NULL );

	val->bv_val = NULL;
	val->bv_len = 0;

	if ( data->when == MAP_LDAP_EVERYTIME ) {
		rc = ldap_initialize( &ld, data->url );
	} else {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_lock( &data->mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		rc = LDAP_SUCCESS;

		if ( data->when == MAP_LDAP_LATER && data->ld == NULL ) {
			rc = ldap_initialize( &data->ld, data->url );
		}
		
		ld = data->ld;
	}

	if ( rc != LDAP_SUCCESS ) {
		rc = REWRITE_ERR;
		goto rc_return;
	}

do_bind:;
	if ( data->binddn != NULL ) {
		rc = ldap_simple_bind_s( ld, data->binddn, data->bindpw );
		if ( rc == LDAP_SERVER_DOWN && first_try ) {
			first_try = 0;
			if ( ldap_initialize( &ld, data->url ) != LDAP_SUCCESS ) {
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
			lud->lud_attrs, data->attrsonly, &res );
	if ( rc == LDAP_SERVER_DOWN && first_try ) {
		first_try = 0;
                if ( ldap_initialize( &ld, data->url ) != LDAP_SUCCESS ) {
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

	if ( data->attrsonly == 1 ) {
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
	if ( data->when == MAP_LDAP_EVERYTIME ) {
		if ( ld != NULL ) {
			ldap_unbind_s( ld );
		}
	} else {
		data->ld = ld;
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_unlock( &data->mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
	}
	
	return rc;
}

