/* schemaparse.c - routines to parse config file objectclass definitions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

struct objclass		*global_oc;
int			global_schemacheck;

static void		oc_usage(void);

void
parse_oc(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		i;
	char		last;
	struct objclass	*oc;
	struct objclass	**ocp;

	oc = (struct objclass *) ch_calloc( 1, sizeof(struct objclass) );
	oc->oc_name = strdup( argv[1] );
	for ( i = 2; i < argc; i++ ) {
		/* required attributes */
		if ( strcasecmp( argv[i], "requires" ) == 0 ) {
			do {
				i++;
				if ( i < argc ) {
					char **s = str2charray( argv[i], "," );
					last = argv[i][strlen( argv[i] ) - 1];
					charray_merge( &oc->oc_required, s );
					charray_free( s );
				}
			} while ( i < argc && last == ',' );

		/* optional attributes */
		} else if ( strcasecmp( argv[i], "allows" ) == 0 ) {
			do {
				i++;
				if ( i < argc ) {
					char **s = str2charray( argv[i], "," );
					last = argv[i][strlen( argv[i] ) - 1];
					
					charray_merge( &oc->oc_allowed, s );
					charray_free( s );
				}
			} while ( i < argc && last == ',' );

		} else {
			fprintf( stderr,
	    "%s: line %d: expecting \"requires\" or \"allows\" got \"%s\"\n",
			    fname, lineno, argv[i] );
			oc_usage();
		}
	}

	ocp = &global_oc;
	while ( *ocp != NULL ) {
		ocp = &(*ocp)->oc_next;
	}
	*ocp = oc;
}

static void
oc_usage( void )
{
	fprintf( stderr, "<oc clause> ::= objectclass <ocname>\n" );
	fprintf( stderr, "                [ requires <attrlist> ]\n" );
	fprintf( stderr, "                [ allows <attrlist> ]\n" );
	exit( 1 );
}

