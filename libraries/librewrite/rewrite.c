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

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/unistd.h>
#include <ac/ctype.h>
#include <ac/string.h>
#include <stdio.h>

#include <rewrite.h>

int ldap_debug;
int ldap_syslog;
int ldap_syslog_level;

char *
apply( 
		FILE *fin, 
		const char *rewriteContext,
		const char *arg
)
{
	struct rewrite_info *info;
	char *string, *sep, *result = NULL;
	int rc;
	void *cookie = &info;

	info = rewrite_info_init(REWRITE_MODE_ERR);

	if ( rewrite_read( fin, info ) != 0 ) {
		exit( EXIT_FAILURE );
	}

	rewrite_param_set( info, "prog", "rewrite" );

	rewrite_session_init( info, cookie );

	string = strdup( arg );
	for ( sep = strchr( rewriteContext, ',' );
			rewriteContext != NULL;
			rewriteContext = sep,
			sep ? sep = strchr( rewriteContext, ',' ) : NULL ) {
		if ( sep != NULL ) {
			sep[ 0 ] = '\0';
			sep++;
		}
		/* rc = rewrite( info, rewriteContext, string, &result ); */
		rc = rewrite_session( info, rewriteContext, string,
				cookie, &result );
		
		fprintf( stdout, "%s -> %s\n", string, 
				( result ? result : "unwilling to perform" ) );
		if ( result == NULL ) {
			break;
		}
		free( string );
		string = result;
	}

	rewrite_session_delete( info, cookie );

	return result;
}

int
main( int argc, char *argv[] )
{
	FILE *fin = NULL;
	char *rewriteContext = REWRITE_DEFAULT_CONTEXT;

	while ( 1 ) {
		int opt = getopt( argc, argv, "f:hr:" );

		if ( opt == EOF ) {
			break;
		}

		switch ( opt ) {
		case 'f':
			fin = fopen( optarg, "r" );
			if ( fin == NULL ) {
				fprintf( stderr, "unable to open file '%s'\n",
						optarg );
				exit( EXIT_FAILURE );
			}
			break;
			
		case 'h':
			fprintf( stderr, 
	"usage: rewrite [options] string\n"
	"\n"
	"\t\t-f file\t\tconfiguration file\n"
	"\t\t-r rule[s]\tlist of comma-separated rules\n"
	"\n"
	"\tsyntax:\n"
	"\t\trewriteEngine\t{on|off}\n"
	"\t\trewriteContext\tcontextName [alias aliasedContextName]\n"
	"\t\trewriteRule\tpattern subst [flags]\n"
	"\n" 
				);
			exit( EXIT_SUCCESS );
			
		case 'r':
			rewriteContext = strdup( optarg );
			break;
		}
	}
	
	if ( optind >= argc ) {
		return -1;
	}

	apply( ( fin ? fin : stdin ), rewriteContext, argv[ optind ] );

	return 0;
}

