/* limits.c - routines to handle regex-based size and time limits */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/string.h>

#include "slap.h"

int
get_limits( 
	Backend			*be, 
	struct berval		*ndn, 
	struct slap_limits_set 	**limit
)
{
	struct slap_limits **lm;

	assert( be );
	assert( limit );

	/*
	 * default values
	 */
	*limit = &be->be_def_limit;

	if ( be->be_limits == NULL ) {
		return( 0 );
	}

	for ( lm = be->be_limits; lm[0] != NULL; lm++ ) {
		switch ( lm[0]->lm_type ) {
		case SLAP_LIMITS_EXACT:
			if ( ndn->bv_len == 0 ) {
				break;
			}
			if ( dn_match( &lm[0]->lm_dn_pat, ndn ) ) {
				*limit = &lm[0]->lm_limits;
				return( 0 );
			}
			break;

		case SLAP_LIMITS_ONE:
		case SLAP_LIMITS_SUBTREE:
		case SLAP_LIMITS_CHILDREN: {
			size_t d;
			
			if ( ndn->bv_len == 0 ) {
				break;
			}

			/* ndn shorter than dn_pat */
			if ( ndn->bv_len < lm[0]->lm_dn_pat.bv_len ) {
				break;
			}
			d = ndn->bv_len - lm[0]->lm_dn_pat.bv_len;

			/* allow exact match for SUBTREE only */
			if ( d == 0 ) {
				if ( lm[0]->lm_type != SLAP_LIMITS_SUBTREE ) {
					break;
				}
			} else {
				/* check for unescaped rdn separator */
				if ( !DN_SEPARATOR( ndn->bv_val[d-1] ) ) {
					break;
				}
			}

			/* in case of (sub)match ... */
			if ( lm[0]->lm_dn_pat.bv_len == ( ndn->bv_len - d )
					&& strcmp( lm[0]->lm_dn_pat.bv_val, &ndn->bv_val[d] ) == 0 ) {
				/* check for exactly one rdn in case of ONE */
				if ( lm[0]->lm_type == SLAP_LIMITS_ONE ) {
					/*
					 * if ndn is more that one rdn
					 * below dn_pat, continue
					 */
					if ( (size_t) dn_rdnlen( NULL, ndn ) != d - 1 ) {
						break;
					}
				}

				*limit = &lm[0]->lm_limits;
				return( 0 );
			}

			break;
		}

		case SLAP_LIMITS_REGEX:
			if ( ndn->bv_len == 0 ) {
				break;
			}
			if ( regexec( &lm[0]->lm_dn_regex, ndn->bv_val, 0, NULL, 0 )
				== 0 )
			{
				*limit = &lm[0]->lm_limits;
				return( 0 );
			}
			break;

		case SLAP_LIMITS_ANONYMOUS:
			if ( ndn->bv_len == 0 ) {
				*limit = &lm[0]->lm_limits;
				return( 0 );
			}
			break;

		case SLAP_LIMITS_USERS:
			if ( ndn->bv_len != 0 ) {
				*limit = &lm[0]->lm_limits;
				return( 0 );
			}
			break;

		case SLAP_LIMITS_ANY:
			*limit = &lm[0]->lm_limits;
			return( 0 );

		default:
			assert( 0 );	/* unreachable */
			return( -1 );
		}
	}

	return( 0 );
}

static int
add_limits(
	Backend 	        *be,
	int			type,
	const char		*pattern,
	struct slap_limits_set	*limit
)
{
	int 			i;
	struct slap_limits	*lm;
	
	assert( be );
	assert( limit );

	switch ( type ) {
	case SLAP_LIMITS_ANONYMOUS:
	case SLAP_LIMITS_USERS:
	case SLAP_LIMITS_ANY:
		for ( i = 0; be->be_limits && be->be_limits[ i ]; i++ ) {
			if ( be->be_limits[ i ]->lm_type == type ) {
				return( -1 );
			}
		}
		break;
	}


	lm = ( struct slap_limits * )ch_calloc( sizeof( struct slap_limits ), 1 );

	switch ( type ) {
	case SLAP_LIMITS_EXACT:
	case SLAP_LIMITS_ONE:
	case SLAP_LIMITS_SUBTREE:
	case SLAP_LIMITS_CHILDREN:
		lm->lm_type = type;
		{
			int rc;
			struct berval bv;
			bv.bv_val = (char *) pattern;
			bv.bv_len = strlen( pattern );

			rc = dnNormalize2( NULL, &bv, &lm->lm_dn_pat );
			if ( rc != LDAP_SUCCESS ) {
				ch_free( lm );
				return( -1 );
			}
		}
		break;
		
	case SLAP_LIMITS_REGEX:
	case SLAP_LIMITS_UNDEFINED:
		lm->lm_type = SLAP_LIMITS_REGEX;
		ber_str2bv( pattern, 0, 1, &lm->lm_dn_pat );
		if ( regcomp( &lm->lm_dn_regex, lm->lm_dn_pat.bv_val, 
					REG_EXTENDED | REG_ICASE ) ) {
			free( lm->lm_dn_pat.bv_val );
			ch_free( lm );
			return( -1 );
		}
		break;

	case SLAP_LIMITS_ANONYMOUS:
	case SLAP_LIMITS_USERS:
	case SLAP_LIMITS_ANY:
		lm->lm_type = type;
		lm->lm_dn_pat.bv_val = NULL;
		lm->lm_dn_pat.bv_len = 0;
		break;
	}

	lm->lm_limits = *limit;

	i = 0;
	if ( be->be_limits != NULL ) {
		for ( ; be->be_limits[i]; i++ );
	}

	be->be_limits = ( struct slap_limits ** )ch_realloc( be->be_limits,
			sizeof( struct slap_limits * ) * ( i + 2 ) );
	be->be_limits[i] = lm;
	be->be_limits[i+1] = NULL;
	
	return( 0 );
}

int
parse_limits(
	Backend     *be,
	const char  *fname,
	int         lineno,
	int         argc,
	char        **argv
)
{
	int 	type = SLAP_LIMITS_UNDEFINED;
	char 	*pattern;
	struct slap_limits_set limit;
	int 	i, rc = 0;

	assert( be );

	if ( argc < 3 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"%s : line %d: missing arg(s) in "
			"\"limits <pattern> <limits>\" line.\n", fname, lineno, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"%s : line %d: missing arg(s) in "
			"\"limits <pattern> <limits>\" line.\n%s",
			fname, lineno, "" );
#endif
		return( -1 );
	}

	limit = be->be_def_limit;

	/*
	 * syntax:
	 *
	 * "limits" <pattern> <limit> [ ... ]
	 * 
	 * 
	 * <pattern>:
	 * 
	 * "anonymous"
	 * "users"
	 * [ "dn" [ "." { "exact" | "base" | "one" | "sub" | children" 
	 *	| "regex" | "anonymous" } ] "=" ] <dn pattern>
	 *
	 * Note:
	 *	"exact" and "base" are the same (exact match);
	 *	"one" means exactly one rdn below, NOT including the pattern
	 *	"sub" means any rdn below, including the pattern
	 *	"children" means any rdn below, NOT including the pattern
	 *	
	 *	"anonymous" may be deprecated in favour 
	 *	of the pattern = "anonymous" form
	 *
	 *
	 * <limit>:
	 *
	 * "time" [ "." { "soft" | "hard" } ] "=" <integer>
	 *
	 * "size" [ "." { "soft" | "hard" | "unchecked" } ] "=" <integer>
	 */
	
	pattern = argv[1];
	if ( strcmp( pattern, "*" ) == 0) {
		type = SLAP_LIMITS_ANY;

	} else if ( strcasecmp( pattern, "anonymous" ) == 0 ) {
		type = SLAP_LIMITS_ANONYMOUS;

	} else if ( strcasecmp( pattern, "users" ) == 0 ) {
		type = SLAP_LIMITS_USERS;
		
	} else if ( strncasecmp( pattern, "dn", sizeof( "dn") - 1 ) == 0 ) {
		pattern += 2;
		if ( pattern[0] == '.' ) {
			pattern++;
			if ( strncasecmp( pattern, "exact", sizeof( "exact" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_EXACT;
				pattern += 5;

			} else if ( strncasecmp( pattern, "base", sizeof( "base " ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_BASE;
				pattern += 4;

			} else if ( strncasecmp( pattern, "one", sizeof( "one" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_ONE;
				pattern += 3;

			} else if ( strncasecmp( pattern, "subtree", sizeof( "subtree" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_SUBTREE;
				pattern += 7;

			} else if ( strncasecmp( pattern, "children", sizeof( "children" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_CHILDREN;
				pattern += 8;

			} else if ( strncasecmp( pattern, "regex", sizeof( "regex" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_REGEX;
				pattern += 5;

			/* 
			 * this could be deprecated in favour
			 * of the pattern = "anonymous" form
			 */
			} else if ( strncasecmp( pattern, "anonymous", sizeof( "anonymous" ) - 1 ) == 0 ) {
				type = SLAP_LIMITS_ANONYMOUS;
				pattern = NULL;
			}
		}

		/* pre-check the data */
		switch ( type ) {
		case SLAP_LIMITS_ANONYMOUS:
		case SLAP_LIMITS_USERS:

			/* no need for pattern */
			pattern = NULL;
			break;

		default:
			if ( pattern[0] != '=' ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s : line %d: missing '=' in "
					"\"dn[.{exact|base|one|subtree"
					"|children|regex|anonymous}]" "=<pattern>\" in "
					"\"limits <pattern> <limits>\" line.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s : line %d: missing '=' in "
					"\"dn[.{exact|base|one|subtree"
					"|children|regex|anonymous}]"
					"=<pattern>\" in "
					"\"limits <pattern> <limits>\" "
					"line.\n%s",
					fname, lineno, "" );
#endif
				return( -1 );
			}

			/* skip '=' (required) */
			pattern++;

			/* trim obvious cases */
			if ( strcmp( pattern, "*" ) == 0 ) {
				type = SLAP_LIMITS_ANY;
				pattern = NULL;

			} else if ( ( type == SLAP_LIMITS_REGEX || type == SLAP_LIMITS_UNDEFINED ) 
					&& strcmp( pattern, ".*" ) == 0 ) {
				type = SLAP_LIMITS_ANY;
				pattern = NULL;
			}
		}
	}

	/* get the limits */
	for ( i = 2; i < argc; i++ ) {
		if ( parse_limit( argv[i], &limit ) ) {

#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, CRIT, 
				"%s : line %d: unknown limit type \"%s\" in "
				"\"limits <pattern> <limits>\" line.\n",
				fname, lineno, argv[i] );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s : line %d: unknown limit type \"%s\" in "
				"\"limits <pattern> <limits>\" line.\n",
			fname, lineno, argv[i] );
#endif

			return( 1 );
		}
	}

	/*
	 * sanity checks ...
	 */
	if ( limit.lms_t_hard > 0 && 
			( limit.lms_t_hard < limit.lms_t_soft 
			  || limit.lms_t_soft == -1 ) ) {
		limit.lms_t_hard = limit.lms_t_soft;
	}
	
	if ( limit.lms_s_hard > 0 && 
			( limit.lms_s_hard < limit.lms_s_soft 
			  || limit.lms_s_soft == -1 ) ) {
		limit.lms_s_hard = limit.lms_s_soft;
	}
	
	rc = add_limits( be, type, pattern, &limit );
	if ( rc ) {

#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"%s : line %d: unable to add limit in "
			"\"limits <pattern> <limits>\" line.\n",
			fname, lineno, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"%s : line %d: unable to add limit in "
			"\"limits <pattern> <limits>\" line.\n",
		fname, lineno, 0 );
#endif
	}

	return( rc );
}

int
parse_limit(
	const char 		*arg,
	struct slap_limits_set 	*limit
)
{
	assert( arg );
	assert( limit );

	if ( strncasecmp( arg, "time", sizeof( "time" ) - 1 ) == 0 ) {
		arg += 4;

		if ( arg[0] == '.' ) {
			arg++;
			if ( strncasecmp( arg, "soft", sizeof( "soft" ) - 1 ) == 0 ) {
				arg += 4;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "none" ) == 0 ) {
					limit->lms_t_soft = -1;
				} else {
					char	*next = NULL;

					limit->lms_t_soft = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_t_soft < -1 ) {
						return( 1 );
					}
				}
				
			} else if ( strncasecmp( arg, "hard", sizeof( "hard" ) - 1 ) == 0 ) {
				arg += 4;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "soft" ) == 0 ) {
					limit->lms_t_hard = 0;
				} else if ( strcasecmp( arg, "none" ) == 0 ) {
					limit->lms_t_hard = -1;
				} else {
					char	*next = NULL;

					limit->lms_t_hard = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_t_hard < -1 ) {
						return( 1 );
					}
				}
				
			} else {
				return( 1 );
			}
			
		} else if ( arg[0] == '=' ) {
			arg++;
			if ( strcasecmp( arg, "none" ) == 0 ) {
				limit->lms_t_soft = -1;
			} else {
				char	*next = NULL;

				limit->lms_t_soft = strtol( arg, &next, 10 );
				if ( next == arg || limit->lms_t_soft < -1 ) {
					return( 1 );
				}
			}
			limit->lms_t_hard = 0;
			
		} else {
			return( 1 );
		}

	} else if ( strncasecmp( arg, "size", sizeof( "size" ) - 1 ) == 0 ) {
		arg += 4;
		
		if ( arg[0] == '.' ) {
			arg++;
			if ( strncasecmp( arg, "soft", sizeof( "soft" ) - 1 ) == 0 ) {
				arg += 4;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "none" ) == 0 ) {
					limit->lms_s_soft = -1;
				} else {
					char	*next = NULL;

					limit->lms_s_soft = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_s_soft < -1 ) {
						return( 1 );
					}
				}
				
			} else if ( strncasecmp( arg, "hard", sizeof( "hard" ) - 1 ) == 0 ) {
				arg += 4;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "soft" ) == 0 ) {
					limit->lms_s_hard = 0;
				} else if ( strcasecmp( arg, "none" ) == 0 ) {
					limit->lms_s_hard = -1;
				} else {
					char	*next = NULL;

					limit->lms_s_hard = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_s_hard < -1 ) {
						return( 1 );
					}
				}
				
			} else if ( strncasecmp( arg, "unchecked", sizeof( "unchecked" ) - 1 ) == 0 ) {
				arg += 9;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "none" ) == 0 ) {
					limit->lms_s_unchecked = -1;
				} else {
					char	*next = NULL;

					limit->lms_s_unchecked = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_s_unchecked < -1 ) {
						return( 1 );
					}
				}

			} else if ( strncasecmp( arg, "pr", sizeof( "pr" ) - 1 ) == 0 ) {
				arg += sizeof( "pr" ) - 1;
				if ( arg[0] != '=' ) {
					return( 1 );
				}
				arg++;
				if ( strcasecmp( arg, "noEstimate" ) == 0 ) {
					limit->lms_s_pr_hide = 1;
				} else {
					char	*next = NULL;

					limit->lms_s_pr = 
						strtol( arg, &next, 10 );
					if ( next == arg || limit->lms_s_pr < -1 ) {
						return( 1 );
					}
				}
				
			} else {
				return( 1 );
			}
			
		} else if ( arg[0] == '=' ) {
			arg++;
			if ( strcasecmp( arg, "none" ) == 0 ) {
				limit->lms_s_soft = -1;
			} else {
				char	*next = NULL;

				limit->lms_s_soft = strtol( arg, &next, 10 );
				if ( next == arg || limit->lms_s_soft < -1 ) {
					return( 1 );
				}
			}
			limit->lms_s_hard = 0;
			
		} else {
			return( 1 );
		}
	}

	return 0;
}

