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

#include <stdio.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include "rewrite-int.h"
#include "rewrite-map.h"

/*
 * Global data
 */
#ifdef USE_REWRITE_LDAP_PVT_THREADS
ldap_pvt_thread_mutex_t xpasswd_mutex;
static int xpasswd_mutex_init = 0;
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

/*
 * Map parsing
 * NOTE: these are old-fashion maps; new maps will be parsed on separate
 * config lines, and referred by name.
 */
struct rewrite_map *
rewrite_xmap_parse(
		struct rewrite_info *info,
		const char *s,
		const char **currpos
)
{
	struct rewrite_map *map;

	assert( info != NULL );
	assert( s != NULL );
	assert( currpos != NULL );

	Debug( LDAP_DEBUG_ARGS, "rewrite_xmap_parse: %s\n%s%s",
			s, "", "" );

	*currpos = NULL;

	map = calloc( sizeof( struct rewrite_map ), 1 );
	if ( map == NULL ) {
		Debug( LDAP_DEBUG_ANY, "rewrite_xmap_parse:"
				" calloc failed\n%s%s%s", "", "", "" );
		return NULL;
	}

	/*
	 * Experimental passwd map:
	 * replaces the uid with the matching gecos from /etc/passwd file 
	 */
	if ( strncasecmp(s, "xpasswd", 7 ) == 0 ) {
		map->lm_type = REWRITE_MAP_XPWDMAP;
		map->lm_name = strdup( "xpasswd" );

		assert( s[7] == '}' );
		*currpos = s + 8;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
		if ( !xpasswd_mutex_init ) {
			xpasswd_mutex_init = 1;
			if ( ldap_pvt_thread_mutex_init( &xpasswd_mutex ) ) {
				free( map );
				return NULL;
			}
		}
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		/* Don't really care if fails */
		return map;
	
	/*
	 * Experimental file map:
	 * looks up key in a `key value' ascii file
	 */
	} else if ( strncasecmp(s, "xfile", 5 ) == 0 ) {
		char *filename;
		const char *p;
		int l;
		int c = 5;
		
		map->lm_type = REWRITE_MAP_XFILEMAP;
		
		if ( s[ c ] != '(' ) {
			free( map );
			return NULL;
		}

		/* Must start with '/' for security concerns */
		c++;
		if ( s[ c ] != '/' ) {
			free( map );
			return NULL;
		}

		for ( p = s + c; p[ 0 ] != '\0' && p[ 0 ] != ')'; p++ );
		if ( p[ 0 ] != ')' ) {
			free( map );
			return NULL;
		}

		l = p - s - c;
		filename = calloc( sizeof( char ), l + 1 );
		AC_MEMCPY( filename, s + c, l );
		filename[ l ] = '\0';
		
		map->lm_args = ( void * )fopen( filename, "r" );
		free( filename );

		if ( map->lm_args == NULL ) {
			free( map );
			return NULL;
		}

		*currpos = p + 1;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
                if ( ldap_pvt_thread_mutex_init( &map->lm_mutex ) ) {
			fclose( ( FILE * )map->lm_args );
			free( map );
			return NULL;
		}
#endif /* USE_REWRITE_LDAP_PVT_THREADS */	
		
		return map;

	/*
         * Experimental ldap map:
         * looks up key on the fly (not implemented!)
         */
        } else if ( strncasecmp(s, "xldap", 5 ) == 0 ) {
		char *p;
		char *url;
		int l, rc;
		int c = 5;
		LDAPURLDesc *lud;

		if ( s[ c ] != '(' ) {
			free( map );
			return NULL;
		}
		c++;
		
		p = strchr( s, '}' );
		if ( p == NULL ) {
			free( map );
			return NULL;
		}
		p--;

		*currpos = p + 2;
	
		/*
		 * Add two bytes for urlencoding of '%s'
		 */
		l = p - s - c;
		url = calloc( sizeof( char ), l + 3 );
		AC_MEMCPY( url, s + c, l );
		url[ l ] = '\0';

		/*
		 * Urlencodes the '%s' for ldap_url_parse
		 */
		p = strchr( url, '%' );
		if ( p != NULL ) {
			AC_MEMCPY( p + 3, p + 1, strlen( p + 1 ) + 1 );
			p[ 1 ] = '2';
			p[ 2 ] = '5';
		}

		rc =  ldap_url_parse( url, &lud );
		free( url );

		if ( rc != LDAP_SUCCESS ) {
			free( map );
			return NULL;
		}
		assert( lud != NULL );

		map->lm_args = ( void * )lud;
		map->lm_type = REWRITE_MAP_XLDAPMAP;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
                if ( ldap_pvt_thread_mutex_init( &map->lm_mutex ) ) {
			ldap_free_urldesc( lud );
			free( map );
			return NULL;
		}
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		return map;
	
	/* Unhandled map */
	}
	
	return NULL;
}

struct rewrite_map *
rewrite_map_parse(
		struct rewrite_info *info,
		const char *string,
		const char **currpos
)
{
	struct rewrite_map *map = NULL;
	struct rewrite_subst *subst = NULL;
	char *s, *begin = NULL, *end;
	const char *p;
	int l, cnt;

	assert( info != NULL );
	assert( string != NULL );
	assert( currpos != NULL );

	*currpos = NULL;

	/*
	 * Go to the end of the map invocation (the right closing brace)
	 */
	for ( p = string, cnt = 1; p[ 0 ] != '\0' && cnt > 0; p++ ) {
		if ( p[ 0 ] == REWRITE_SUBMATCH_ESCAPE ) {
			/*
			 * '%' marks the beginning of a new map
			 */
			if ( p[ 1 ] == '{' ) {
				cnt++;
			/*
			 * '%' followed by a digit may mark the beginning
			 * of an old map
			 */
			} else if ( isdigit( (unsigned char) p[ 1 ] ) && p[ 2 ] == '{' ) {
				cnt++;
				p++;
			}
			if ( p[ 1 ] != '\0' )
				p++;
		} else if ( p[ 0 ] == '}' ) {
			cnt--;
		}
	}
	if ( cnt != 0 ) {
		return NULL;
	}
	*currpos = p;
	
	/*
	 * Copy the map invocation
	 */
	l = p - string - 1;
	s = calloc( sizeof( char ), l + 1 );
	AC_MEMCPY( s, string, l );
	s[ l ] = 0;

	/*
	 * Isolate the map name (except for variable deref)
	 */
	switch ( s[ 0 ] ) {
	case REWRITE_OPERATOR_VARIABLE_GET:
	case REWRITE_OPERATOR_PARAM_GET:
		break;
	default:
		begin = strchr( s, '(' );
		if ( begin == NULL ) {
			free( s );
			return NULL;
		}
		begin[ 0 ] = '\0';
		begin++;
		break;
	}

	/*
	 * Check for special map types
	 */
	p = s;
	switch ( p[ 0 ] ) {
	case REWRITE_OPERATOR_SUBCONTEXT:
	case REWRITE_OPERATOR_COMMAND:
	case REWRITE_OPERATOR_VARIABLE_SET:
	case REWRITE_OPERATOR_VARIABLE_GET:
	case REWRITE_OPERATOR_PARAM_GET:
		p++;
		break;
	}

	/*
	 * Variable set and get may be repeated to indicate session-wide
	 * instead of operation-wide variables
	 */
	switch ( p[ 0 ] ) {
        case REWRITE_OPERATOR_VARIABLE_SET:
	case REWRITE_OPERATOR_VARIABLE_GET:
		p++;
		break;
	}

	/*
	 * Variable get token can be appended to variable set to mean store
	 * AND rewrite
	 */
	if ( p[ 0 ] == REWRITE_OPERATOR_VARIABLE_GET ) {
		p++;
	}
	
	/*
	 * Check the syntax of the variable name
	 */
	if ( !isalpha( (unsigned char) p[ 0 ] ) ) {
		free( s );
		return NULL;
	}
	for ( p++; p[ 0 ] != '\0'; p++ ) {
		if ( !isalnum( (unsigned char) p[ 0 ] ) ) {
			free( s );
			return NULL;
		}
	}

	/*
	 * Isolate the argument of the map (except for variable deref)
	 */
	switch ( s[ 0 ] ) {
	case REWRITE_OPERATOR_VARIABLE_GET:
	case REWRITE_OPERATOR_PARAM_GET:
		break;
	default:
		end = strrchr( begin, ')' );
		if ( end == NULL ) {
			free( s );
			return NULL;
		}
		end[ 0 ] = '\0';

		/*
	 	 * Compile the substitution pattern of the map argument
	 	 */
		subst = rewrite_subst_compile( info, begin );
		if ( subst == NULL ) {
			free( s );
			return NULL;
		}
		break;
	}

	/*
	 * Create the map
	 */
	map = calloc( sizeof( struct rewrite_map ), 1 );
	if ( map == NULL ) {
		if ( subst != NULL ) {
			free( subst );
		}
		free( s );
		return NULL;
	}
	
#ifdef USE_REWRITE_LDAP_PVT_THREADS
        if ( ldap_pvt_thread_mutex_init( &map->lm_mutex ) ) {
		if ( subst != NULL ) {
			free( subst );
		}
		free( s );
		free( map );
		return NULL;
	}
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
			
	/*
	 * No subst for variable deref
	 */
	switch ( s[ 0 ] ) {
	case REWRITE_OPERATOR_VARIABLE_GET:
	case REWRITE_OPERATOR_PARAM_GET:
		break;
	default:
		map->lm_subst = subst;
		break;
	}

	/*
	 * Parses special map types
	 */
	switch ( s[ 0 ] ) {
	
	/*
	 * Subcontext
	 */
	case REWRITE_OPERATOR_SUBCONTEXT:		/* '>' */

		/*
		 * Fetch the rewrite context
		 * it MUST have been defined previously
		 */
		map->lm_type = REWRITE_MAP_SUBCONTEXT;
		map->lm_name = strdup( s + 1 );
		map->lm_data = rewrite_context_find( info, s + 1 );
		if ( map->lm_data == NULL ) {
			free( s );
			free( map );
			return NULL;
		}
		break;

	/*
	 * External command
	 */
	case REWRITE_OPERATOR_COMMAND:		/* '|' */
		free( map );
		map = NULL;
		break;
	
	/*
	 * Variable set
	 */
	case REWRITE_OPERATOR_VARIABLE_SET:	/* '&' */
		if ( s[ 1 ] == REWRITE_OPERATOR_VARIABLE_SET ) {
			if ( s[ 2 ] == REWRITE_OPERATOR_VARIABLE_GET ) {
				map->lm_type = REWRITE_MAP_SETW_SESN_VAR;
				map->lm_name = strdup( s + 3 );
			} else {
				map->lm_type = REWRITE_MAP_SET_SESN_VAR;
				map->lm_name = strdup( s + 2 );
			}
		} else {
			if ( s[ 1 ] == REWRITE_OPERATOR_VARIABLE_GET ) {
				map->lm_type = REWRITE_MAP_SETW_OP_VAR;
				map->lm_name = strdup( s + 2 );
			} else {
				map->lm_type = REWRITE_MAP_SET_OP_VAR;
				map->lm_name = strdup( s + 1 );
			}
		}
		break;
	
	/*
	 * Variable dereference
	 */
	case REWRITE_OPERATOR_VARIABLE_GET:	/* '*' */
		if ( s[ 1 ] == REWRITE_OPERATOR_VARIABLE_GET ) {
			map->lm_type = REWRITE_MAP_GET_SESN_VAR;
			map->lm_name = strdup( s + 2 );
		} else {
			map->lm_type = REWRITE_MAP_GET_OP_VAR;
			map->lm_name = strdup( s + 1 );
		}
		break;
	
	/*
	 * Parameter
	 */
	case REWRITE_OPERATOR_PARAM_GET:		/* '$' */
		map->lm_type = REWRITE_MAP_GET_PARAM;
		map->lm_name = strdup( s + 1 );
		break;
	
	/*
	 * Built-in map
	 */
	default:
		map->lm_type = REWRITE_MAP_BUILTIN;
		map->lm_name = strdup( s );
		map->lm_data = rewrite_builtin_map_find( info, s );
		if ( map->lm_data == NULL ) {
			return NULL;
		}
		break;

	}
	
	free( s );
	return map;
}

/*
 * Map key -> value resolution
 * NOTE: these are old-fashion maps; new maps will be parsed on separate
 * config lines, and referred by name.
 */
int
rewrite_xmap_apply(
		struct rewrite_info *info,
		struct rewrite_op *op,
		struct rewrite_map *map,
		struct berval *key,
		struct berval *val
)
{
	int rc = REWRITE_SUCCESS;
	
	assert( info != NULL );
	assert( op != NULL );
	assert( map != NULL );
	assert( key != NULL );
	assert( val != NULL );
	
	val->bv_val = NULL;
	val->bv_len = 0;
	
	switch ( map->lm_type ) {
#ifdef HAVE_GETPWNAM
	case REWRITE_MAP_XPWDMAP: {
		struct passwd *pwd;

#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_lock( &xpasswd_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
		
		pwd = getpwnam( key->bv_val );
		if ( pwd == NULL ) {

#ifdef USE_REWRITE_LDAP_PVT_THREADS
			ldap_pvt_thread_mutex_unlock( &xpasswd_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

			rc = REWRITE_NO_SUCH_OBJECT;
			break;
		}

#ifdef HAVE_PW_GECOS
		if ( pwd->pw_gecos != NULL && pwd->pw_gecos[0] != '\0' ) {
			int l = strlen( pwd->pw_gecos );
			
			val->bv_val = strdup( pwd->pw_gecos );
			if ( val->bv_val == NULL ) {

#ifdef USE_REWRITE_LDAP_PVT_THREADS
		                ldap_pvt_thread_mutex_unlock( &xpasswd_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

				rc = REWRITE_ERR;
				break;
			}
			val->bv_len = l;
		} else
#endif /* HAVE_PW_GECOS */
		{
			val->bv_val = strdup( key->bv_val );
			val->bv_len = key->bv_len;
		}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_unlock( &xpasswd_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
			
		break;
	}
#endif /* HAVE_GETPWNAM*/
	
	case REWRITE_MAP_XFILEMAP: {
		char buf[1024];
		
		if ( map->lm_args == NULL ) {
			rc = REWRITE_ERR;
			break;
		}
		
#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_lock( &map->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		rewind( ( FILE * )map->lm_args );
		
		while ( fgets( buf, sizeof( buf ), ( FILE * )map->lm_args ) ) {
			char *p;
			int blen;
			
			blen = strlen( buf );
			if ( buf[ blen - 1 ] == '\n' ) {
				buf[ blen - 1 ] = '\0';
			}
			
			p = strtok( buf, " " );
			if ( p == NULL ) {
#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_unlock( &map->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
				rc = REWRITE_ERR;
				goto rc_return;
			}
			if ( strcasecmp( p, key->bv_val ) == 0 
					&& ( p = strtok( NULL, "" ) ) ) {
				val->bv_val = strdup( p );
				if ( val->bv_val == NULL ) {
					return REWRITE_ERR;
				}

				val->bv_len = strlen( p );
				
#ifdef USE_REWRITE_LDAP_PVT_THREADS
				ldap_pvt_thread_mutex_unlock( &map->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */
				
				goto rc_return;
			}
		}

#ifdef USE_REWRITE_LDAP_PVT_THREADS
		ldap_pvt_thread_mutex_unlock( &map->lm_mutex );
#endif /* USE_REWRITE_LDAP_PVT_THREADS */

		rc = REWRITE_ERR;
		
		break;
	}

	case REWRITE_MAP_XLDAPMAP: {
		LDAP *ld;
		char filter[1024];
		LDAPMessage *res = NULL, *entry;
		LDAPURLDesc *lud = ( LDAPURLDesc * )map->lm_args;
		int attrsonly = 0;
		char **values;

		assert( lud != NULL );

		/*
		 * No mutex because there is no write on the map data
		 */
		
		ld = ldap_init( lud->lud_host, lud->lud_port );
		if ( ld == NULL ) {
			rc = REWRITE_ERR;
			goto rc_return;
		}

		snprintf( filter, sizeof( filter ), lud->lud_filter,
				key->bv_val );

		if ( strcasecmp( lud->lud_attrs[ 0 ], "dn" ) == 0 ) {
			attrsonly = 1;
		}
		rc = ldap_search_s( ld, lud->lud_dn, lud->lud_scope,
				filter, lud->lud_attrs, attrsonly, &res );
		if ( rc != LDAP_SUCCESS ) {
			ldap_unbind( ld );
			rc = REWRITE_ERR;
			goto rc_return;
		}

		if ( ldap_count_entries( ld, res ) != 1 ) {
			ldap_unbind( ld );
			rc = REWRITE_ERR;
			goto rc_return;
		}

		entry = ldap_first_entry( ld, res );
		if ( entry == NULL ) {
			ldap_msgfree( res );
			ldap_unbind( ld );
			rc = REWRITE_ERR;
			goto rc_return;
		}
		if ( attrsonly == 1 ) {
			val->bv_val = ldap_get_dn( ld, entry );
			if ( val->bv_val == NULL ) {
				ldap_msgfree( res );
                                ldap_unbind( ld );
                                rc = REWRITE_ERR;
                                goto rc_return;
                        }
		} else {
			values = ldap_get_values( ld, entry,
					lud->lud_attrs[0] );
			if ( values == NULL ) {
				ldap_msgfree( res );
				ldap_unbind( ld );
				rc = REWRITE_ERR;
				goto rc_return;
			}
			val->bv_val = strdup( values[ 0 ] );
			ldap_value_free( values );
		}
		val->bv_len = strlen( val->bv_val );

		ldap_msgfree( res );
		ldap_unbind( ld );
		
		rc = REWRITE_SUCCESS;
	}
	}

rc_return:;
	return rc;
}

/*
 * Applies the new map type
 */
int
rewrite_map_apply(
		struct rewrite_info *info,
		struct rewrite_op *op,
		struct rewrite_map *map,
		struct berval *key,
		struct berval *val
)
{
	int rc = REWRITE_SUCCESS;

	assert( info != NULL );
	assert( op != NULL );
	assert( map != NULL );
	assert( key != NULL );
	assert( val != NULL );

	val->bv_val = NULL;
	val->bv_len = 0;
	
	switch ( map->lm_type ) {
	case REWRITE_MAP_SUBCONTEXT:
		rc = rewrite_context_apply( info, op, 
				( struct rewrite_context * )map->lm_data,
				key->bv_val, &val->bv_val );
		if ( val->bv_val != NULL ) {
			val->bv_len = strlen( val->bv_val );
		}
		break;

	case REWRITE_MAP_SET_OP_VAR:
	case REWRITE_MAP_SETW_OP_VAR:
		rc = rewrite_var_set( &op->lo_vars, map->lm_name,
				key->bv_val, 1 )
			? REWRITE_SUCCESS : REWRITE_ERR;
		if ( map->lm_type == REWRITE_MAP_SET_OP_VAR ) {
			val->bv_val = strdup( "" );
		} else {
			val->bv_val = strdup( key->bv_val );
			val->bv_len = key->bv_len;
		}
		break;
	
	case REWRITE_MAP_GET_OP_VAR: {
		struct rewrite_var *var;

		var = rewrite_var_find( op->lo_vars, map->lm_name );
		if ( var == NULL ) {
			rc = REWRITE_ERR;
		} else {
			val->bv_val = strdup( var->lv_value.bv_val );
			val->bv_len = var->lv_value.bv_len;
		}
		break;	
	}

	case REWRITE_MAP_SET_SESN_VAR:
	case REWRITE_MAP_SETW_SESN_VAR:
		if ( op->lo_cookie == NULL ) {
			rc = REWRITE_ERR;
			break;
		}
		rc = rewrite_session_var_set( info, op->lo_cookie, 
				map->lm_name, key->bv_val );
		if ( map->lm_type == REWRITE_MAP_SET_SESN_VAR ) {
			val->bv_val = strdup( "" );
		} else {
			val->bv_val = strdup( key->bv_val );
			val->bv_len = key->bv_len;
		}
		break;

	case REWRITE_MAP_GET_SESN_VAR:
		rc = rewrite_session_var_get( info, op->lo_cookie,
				map->lm_name, val );
		break;		

	case REWRITE_MAP_GET_PARAM:
		rc = rewrite_param_get( info, map->lm_name, val );
		break;

	case REWRITE_MAP_BUILTIN: {
		struct rewrite_builtin_map *bmap = map->lm_data;
		switch ( bmap->lb_type ) {
		case REWRITE_BUILTIN_MAP_LDAP:
			rc = map_ldap_apply( bmap, key->bv_val, val );
			break;
		default:
			rc = REWRITE_ERR;
			break;
		}
		break;
	}

	default:
		rc = REWRITE_ERR;
		break;
	}

	return rc;
}

