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

/*
 * Compiles a substitution pattern
 */
struct rewrite_subst *
rewrite_subst_compile(
		struct rewrite_info *info,
		const char *result
)
{
	size_t subs_len;
	struct berval *subs = NULL, *tmps;
	struct rewrite_submatch *submatch = NULL;

	struct rewrite_subst *s = NULL;

	const char *begin, *p;
	int nsub = 0, l;

	assert( info != NULL );
	assert( result != NULL );

	/*
	 * Take care of substitution string
	 */
	for ( p = begin = result, subs_len = 0; p[ 0 ] != '\0'; p++ ) {
		
		/*
		 * Keep only single escapes '%'
		 */
		if ( p[ 0 ] != REWRITE_SUBMATCH_ESCAPE ) {
			continue;
		} 

		if ( p[ 1 ] == REWRITE_SUBMATCH_ESCAPE ) {
			/* Pull &p[1] over p, including the trailing '\0' */
			AC_MEMCPY((char *)p, &p[ 1 ], strlen( p ) );
			continue;
		}

		tmps = (struct berval *)realloc( subs,
				sizeof( struct berval )*( nsub + 1 ) );
		if ( tmps == NULL ) {
			/* FIXME: cleanup */
			return NULL;
		}
		subs = tmps;
		
		/*
		 * I think an `if l > 0' at runtime is better outside than
		 * inside a function call ...
		 */
		l = p - begin;
		if ( l > 0 ) {
			subs_len += l;
			subs[ nsub ].bv_len = l;
			subs[ nsub ].bv_val = malloc( l + 1 );
			if ( subs[ nsub ].bv_val == NULL ) {
				return NULL;
			}
			AC_MEMCPY( subs[ nsub ].bv_val, begin, l );
			subs[ nsub ].bv_val[ l ] = '\0';
		} else {
			subs[ nsub ].bv_val = NULL;
			subs[ nsub ].bv_len = 0;
		}
		
		/*
		 * Substitution pattern
		 */
		if ( isdigit( (unsigned char) p[ 1 ] ) ) {
			int d = p[ 1 ] - '0';
			struct rewrite_submatch *tmpsm;

			/*
			 * Add a new value substitution scheme
			 */
			tmpsm = realloc( submatch, 
	sizeof( struct rewrite_submatch )*( nsub + 1 ) );
			if ( tmpsm == NULL ) {
				/* cleanup */
				return NULL;
			}
			submatch = tmpsm;
			submatch[ nsub ].ls_submatch = d;

			/*
			 * If there is no argument, use default
			 * (substitute substring as is)
			 */
			if ( p[ 2 ] != '{' ) {
				submatch[ nsub ].ls_type = 
					REWRITE_SUBMATCH_ASIS;
				begin = ++p + 1;
			} else {
				struct rewrite_map *map;

				submatch[ nsub ].ls_type =
					REWRITE_SUBMATCH_XMAP;

				map = rewrite_xmap_parse( info,
						p + 3, &begin );
				if ( map == NULL ) {
					/* cleanup */
					return NULL;
				}
				p = begin - 1;

				submatch[ nsub ].ls_map = map;
			}

		/*
		 * Map with args ...
		 */
		} else if ( p[ 1 ] == '{' ) {
			struct rewrite_map *map;
			struct rewrite_submatch *tmpsm;

			map = rewrite_map_parse( info, p + 2, &begin );
			if ( map == NULL ) {
				/* cleanup */
				return NULL;
			}
			p = begin - 1;

			/*
			 * Add a new value substitution scheme
			 */
			tmpsm = realloc( submatch,
					sizeof( struct rewrite_submatch )*( nsub + 1 ) );
			if ( tmpsm == NULL ) {
				/* cleanup */
				return NULL;
			}
			submatch = tmpsm;
			submatch[ nsub ].ls_type =
				REWRITE_SUBMATCH_MAP_W_ARG;
			
			submatch[ nsub ].ls_map = map;
		}

		nsub++;
	}
	
	/*
	 * Last part of string
	 */
	tmps = realloc( subs, sizeof( struct berval )*( nsub + 1 ) );
	if ( tmps == NULL ) {
		/*
		 * XXX need to free the value subst stuff!
		 */
		free( submatch );
		return NULL;
	}
	subs = tmps;
	l = p - begin;
	if ( l > 0 ) {
		subs_len += l;
		subs[ nsub ].bv_len = l;
		subs[ nsub ].bv_val = malloc( l + 1 );
		AC_MEMCPY( subs[ nsub ].bv_val, begin, l );
		subs[ nsub ].bv_val[ l ] = '\0';
	} else {
		subs[ nsub ].bv_val = NULL;
		subs[ nsub ].bv_len = 0;
	}

	s = calloc( sizeof( struct rewrite_subst ), 1 );
	if ( s == NULL ) {
		/* cleanup */
		return NULL;
	}

	s->lt_subs_len = subs_len;
        s->lt_subs = subs;
        s->lt_num_submatch = nsub;
        s->lt_submatch = submatch;

	return s;
}

/*
 * Copies the match referred to by submatch and fetched in string by match.
 * Helper for rewrite_rule_apply.
 */
static int
submatch_copy(
		struct rewrite_submatch *submatch,
		const char *string,
		const regmatch_t *match,
		struct berval *val
)
{
	int		c, l;
	const char	*s;

	assert( submatch != NULL );
	assert( submatch->ls_type == REWRITE_SUBMATCH_ASIS
			|| submatch->ls_type == REWRITE_SUBMATCH_XMAP );
	assert( string != NULL );
	assert( match != NULL );
	assert( val != NULL );
	assert( val->bv_val == NULL );
	
	c = submatch->ls_submatch;
	s = string + match[ c ].rm_so;
	l = match[ c ].rm_eo - match[ c ].rm_so;
	
	val->bv_len = l;
	val->bv_val = calloc( sizeof( char ), l + 1 );
	if ( val->bv_val == NULL ) {
		return REWRITE_ERR;
	}
	
	AC_MEMCPY( val->bv_val, s, l );
	val->bv_val[ l ] = '\0';
	
	return REWRITE_SUCCESS;
}

/*
 * Substitutes a portion of rewritten string according to substitution
 * pattern using submatches
 */
int
rewrite_subst_apply(
		struct rewrite_info *info,
		struct rewrite_op *op,
		struct rewrite_subst *subst,
		const char *string,
		const regmatch_t *match,
		struct berval *val
)
{
	struct berval *submatch = NULL;
	char *res = NULL;
	int n = 0, l, cl;
	int rc = REWRITE_REGEXEC_OK;

	assert( info != NULL );
	assert( op != NULL );
	assert( subst != NULL );
	assert( string != NULL );
	assert( match != NULL );
	assert( val != NULL );

	assert( val->bv_val == NULL );

	val->bv_val = NULL;
	val->bv_len = 0;

	/*
	 * Prepare room for submatch expansion
	 */
	if ( subst->lt_num_submatch > 0 ) {
		submatch = calloc( sizeof( struct berval ),
				subst->lt_num_submatch );
		if ( submatch == NULL ) {
			return REWRITE_REGEXEC_ERR;
		}
	}
	
	/*
	 * Resolve submatches (simple subst, map expansion and so).
	 */
	for ( n = 0, l = 0; n < subst->lt_num_submatch; n++ ) {
		struct berval	key = { 0, NULL };

		submatch[ n ].bv_val = NULL;
		
		/*
		 * Get key
		 */
		switch ( subst->lt_submatch[ n ].ls_type ) {
		case REWRITE_SUBMATCH_ASIS:
		case REWRITE_SUBMATCH_XMAP:
			rc = submatch_copy( &subst->lt_submatch[ n ],
					string, match, &key );
			if ( rc != REWRITE_SUCCESS ) {
				rc = REWRITE_REGEXEC_ERR;
				goto cleanup;
			}
			break;
			
		case REWRITE_SUBMATCH_MAP_W_ARG:
			switch ( subst->lt_submatch[ n ].ls_map->lm_type ) {
			case REWRITE_MAP_GET_OP_VAR:
			case REWRITE_MAP_GET_SESN_VAR:
			case REWRITE_MAP_GET_PARAM:
				rc = REWRITE_SUCCESS;
				break;

			default:
				rc = rewrite_subst_apply( info, op, 
					subst->lt_submatch[ n ].ls_map->lm_subst,
					string, match, &key);
			}
			
			if ( rc != REWRITE_SUCCESS ) {
				rc = REWRITE_REGEXEC_ERR;
				goto cleanup;
			}
			break;

		default:
			Debug( LDAP_DEBUG_ANY, "Not Implemented\n", 0, 0, 0 );
			rc = REWRITE_ERR;
			break;
		}
		
		if ( rc != REWRITE_SUCCESS ) {
			rc = REWRITE_REGEXEC_ERR;
			goto cleanup;
		}

		/*
		 * Resolve key
		 */
		switch ( subst->lt_submatch[ n ].ls_type ) {
		case REWRITE_SUBMATCH_ASIS:
			submatch[ n ] = key;
			rc = REWRITE_SUCCESS;
			break;
			
		case REWRITE_SUBMATCH_XMAP:
			rc = rewrite_xmap_apply( info, op,
					subst->lt_submatch[ n ].ls_map,
					&key, &submatch[ n ] );
			break;
			
		case REWRITE_SUBMATCH_MAP_W_ARG:
			rc = rewrite_map_apply( info, op,
					subst->lt_submatch[ n ].ls_map,
					&key, &submatch[ n ] );
			break;

		default:
			/*
			 * When implemented, this might return the
                         * exit status of a rewrite context,
                         * which may include a stop, or an
                         * unwilling to perform
                         */
			rc = REWRITE_ERR;
			break;
		}
		
		if ( rc != REWRITE_SUCCESS ) {
			rc = REWRITE_REGEXEC_ERR;
		}
		
		/*
                 * Increment the length of the resulting string
                 */
		l += submatch[ n ].bv_len;
	}
	
	/*
         * Alloc result buffer as big as the constant part 
         * of the subst pattern and initialize it
         */
	l += subst->lt_subs_len;
	res = calloc( sizeof( char ), l + 1 );
	if ( res == NULL ) {
		rc = REWRITE_REGEXEC_ERR;
		goto cleanup;
	}

	/*
	 * Apply submatches (possibly resolved thru maps
	 */
        for ( n = 0, cl = 0; n < subst->lt_num_submatch; n++ ) {
		if ( subst->lt_subs[ n ].bv_val != NULL ) {
                	AC_MEMCPY( res + cl, subst->lt_subs[ n ].bv_val,
					subst->lt_subs[ n ].bv_len );
			cl += subst->lt_subs[ n ].bv_len;
		}
		AC_MEMCPY( res + cl, submatch[ n ].bv_val, 
				submatch[ n ].bv_len );
		cl += submatch[ n ].bv_len;
	}
	if ( subst->lt_subs[ n ].bv_val != NULL ) {
		AC_MEMCPY( res + cl, subst->lt_subs[ n ].bv_val,
				subst->lt_subs[ n ].bv_len );
	}

	val->bv_val = res;
	val->bv_len = l;

cleanup:;
	if ( submatch ) {
        	for ( ; --n >= 0; ) {
			if ( submatch[ n ].bv_val ) {
				free( submatch[ n ].bv_val );
			}
		}
		free( submatch );
	}

	return rc;
}

/*
 * frees data
 */
int
rewrite_subst_destroy(
		struct rewrite_subst **psubst
)
{
	int			n;
	struct rewrite_subst	*subst;

	assert( psubst );
	assert( *psubst );

	subst = *psubst;

	for ( n = 0; n < subst->lt_num_submatch; n++ ) {
		if ( subst->lt_subs[ n ].bv_val ) {
			free( subst->lt_subs[ n ].bv_val );
			subst->lt_subs[ n ].bv_val = NULL;
		}

		switch ( subst->lt_submatch[ n ].ls_type ) {
		case REWRITE_SUBMATCH_ASIS:
			break;

		case REWRITE_SUBMATCH_XMAP:
			rewrite_xmap_destroy( &subst->lt_submatch[ n ].ls_map );
			break;

		case REWRITE_SUBMATCH_MAP_W_ARG:
			rewrite_map_destroy( &subst->lt_submatch[ n ].ls_map );
			break;

		default:
			break;
		}
	}

	/* last one */
	if ( subst->lt_subs[ n ].bv_val ) {
		free( subst->lt_subs[ n ].bv_val );
		subst->lt_subs[ n ].bv_val = NULL;
	}

	free( subst );
	*psubst = NULL;

	return 0;
}

