/* limits.c - routines to handle regex-based size and time limits */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/string.h>

#include "slap.h"

int
get_limits( 
	Backend		*be, 
	const char	*ndn, 
	int		*timelimit, 
	int		*sizelimit 
)
{
	struct slap_limits **lm;

	assert( be );
	assert( timelimit );
	assert( sizelimit );

	/*
	 * default values
	 */
	*timelimit = be->be_timelimit;
	*sizelimit = be->be_sizelimit;

	/*
	 * anonymous or no regex-based limits? 
	 */
	if ( be->be_limits == NULL || ndn == NULL || ndn[0] == '\0' ) {
		return( 0 );
	}

	for ( lm = be->be_limits; lm[0] != NULL; lm++ ) {
		switch ( lm[0]->lm_type) {
		case SLAP_LIMITS_EXACT:
			if ( strcmp( lm[0]->lm_dn_pat, ndn ) == 0 ) {
				*timelimit = lm[0]->lm_timelimit;
				*sizelimit = lm[0]->lm_sizelimit;
				return( 0 );
			}
			break;

		case SLAP_LIMITS_REGEX:
			if ( regexec( &lm[0]->lm_dn_regex, ndn, 0, NULL, 0) == 0 ) {
				*timelimit = lm[0]->lm_timelimit;
				*sizelimit = lm[0]->lm_sizelimit;
				return( 0 );
			}
			break;
			
		default:
			assert( 0 );	/* unreachable */
			return( -1 );
		}
	}

	return( 0 );
}

int
add_limits(
	Backend         *be,
	int		type,
	const char	*pattern,
	int		timelimit,
	int		sizelimit
)
{
	int 			i;
	struct slap_limits	*lm;
	
	assert( be );
	assert( pattern);

	lm = ( struct slap_limits * )ch_calloc( sizeof( struct slap_limits ), 1 );

	switch ( type ) {
	case SLAP_LIMITS_EXACT:
		lm->lm_type = SLAP_LIMITS_EXACT;
		lm->lm_dn_pat = ch_strdup( pattern );
		if ( dn_normalize( lm->lm_dn_pat ) == NULL ) {
			ch_free( lm->lm_dn_pat );
			ch_free( lm );
			return( -1 );
		}
		break;
		
	case SLAP_LIMITS_REGEX:
	case SLAP_LIMITS_UNDEFINED:
		lm->lm_type = SLAP_LIMITS_REGEX;
		lm->lm_dn_pat = ch_strdup( pattern );
		if ( regcomp( &lm->lm_dn_regex, lm->lm_dn_pat, REG_EXTENDED | REG_ICASE ) ) {
			ch_free( lm->lm_dn_pat );
			ch_free( lm );
			return( -1 );
		}
		break;
	}

	lm->lm_timelimit = timelimit;
	lm->lm_sizelimit = sizelimit;

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
	int	timelimit;
	int 	sizelimit;
	int 	i;

	assert( be );

	if ( argc < 3 ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			"%s : line %d: missing arg(s) in "
			"\"limits <pattern> <limits>\" line.\n",
			fname, lineno ));
#else
		Debug( LDAP_DEBUG_ANY,
			"%s : line %d: missing arg(s) in "
			"\"limits <pattern> <limits>\" line.\n%s",
			fname, lineno, "" );
#endif
		return( -1 );
	}

	timelimit = be->be_timelimit;
	sizelimit = be->be_sizelimit;

	/*
	 * syntax:
	 *
	 * "limits" <pattern> <limit> [ <limit> [ ... ] ]
	 * 
	 * 
	 * <pattern>:
	 * 
	 * [ "dn" [ "." { "exact" | "regex" } ] "=" ] <dn pattern>
	 *
	 * 
	 * <limit>:
	 *
	 * { "time" | "size" } "=" <value>
	 */
	
	pattern = argv[1];
	if ( strncasecmp( pattern, "dn", 2 ) == 0 ) {
		pattern += 2;
		if ( pattern[0] == '.' ) {
			pattern++;
			if ( strncasecmp( pattern, "exact", 5 ) == 0 ) {
				type = SLAP_LIMITS_EXACT;
				pattern += 5;
			} else if ( strncasecmp( pattern, "regex", 5 ) == 0 ) {
				type = SLAP_LIMITS_REGEX;
				pattern += 5;
			}
		}

		if ( pattern[0] != '=' ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
				"%s : line %d: missing '=' in "
				"\"dn[.{exact|regex}]=<pattern>\" in "
				"\"limits <pattern> <limits>\" line.\n",
			fname, lineno ));
#else
			Debug( LDAP_DEBUG_ANY,
				"%s : line %d: missing '=' in "
				"\"dn[.{exact|regex}]=<pattern>\" in "
				"\"limits <pattern> <limits>\" line.\n%s",
			fname, lineno, "" );
#endif
			return( -1 );
		}

		/* skip '=' (required) */
		pattern++;
	}

	for ( i = 2; i < argc; i++ ) {
		if ( strncasecmp( argv[i], "time=", 5) == 0 ) {
			timelimit = atoi( argv[i]+5 );
		} else if ( strncasecmp( argv[i], "size=", 5) == 0 ) {
			sizelimit = atoi( argv[i]+5 );
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
				"%s : line %d: unknown limit type \"%s\" in "
				"\"limits <pattern> <limits>\" line "
				"(ignored).\n",
			fname, lineno, argv[i] ));
#else
			Debug( LDAP_DEBUG_ANY,
				"%s : line %d: unknown limit type \"%s\" in "
				"\"limits <pattern> <limits>\" line "
				"(ignored).\n",
			fname, lineno, argv[i] );
#endif
		}
	}
	
	return( add_limits( be, type, pattern, timelimit, sizelimit ) );
}

