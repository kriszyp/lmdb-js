/* schemaparse.c - routines to parse config file objectclass definitions */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

extern char		**str2charray();
extern void		charray_merge();

struct objclass		*global_oc;
int			global_schemacheck;

static void		oc_usage();

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
					last = argv[i][strlen( argv[i] ) - 1];
					charray_merge( &oc->oc_required,
						str2charray( argv[i], "," ) );
				}
			} while ( i < argc && last == ',' );

		/* optional attributes */
		} else if ( strcasecmp( argv[i], "allows" ) == 0 ) {
			do {
				i++;
				if ( i < argc ) {
					last = argv[i][strlen( argv[i] ) - 1];
					charray_merge( &oc->oc_allowed,
						str2charray( argv[i], "," ) );
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
oc_usage()
{
	fprintf( stderr, "<oc clause> ::= objectclass <ocname>\n" );
	fprintf( stderr, "                [ requires <attrlist> ]\n" );
	fprintf( stderr, "                [ allows <attrlist> ]\n" );
	exit( 1 );
}

