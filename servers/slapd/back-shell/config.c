/* config.c - shell backend configuration file routine */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

extern char	**charray_dup();

shell_back_config(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;

	if ( si == NULL ) {
		fprintf( stderr, "%s: line %d: shell backend info is null!\n",
		    fname, lineno );
		exit( 1 );
	}

	/* command + args to exec for binds */
	if ( strcasecmp( argv[0], "bind" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"bind <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_bind = charray_dup( &argv[1] );

	/* command + args to exec for unbinds */
	} else if ( strcasecmp( argv[0], "unbind" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"unbind <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_unbind = charray_dup( &argv[1] );

	/* command + args to exec for searches */
	} else if ( strcasecmp( argv[0], "search" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"search <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_search = charray_dup( &argv[1] );

	/* command + args to exec for compares */
	} else if ( strcasecmp( argv[0], "compare" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"compare <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_compare = charray_dup( &argv[1] );

	/* command + args to exec for modifies */
	} else if ( strcasecmp( argv[0], "modify" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"modify <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_modify = charray_dup( &argv[1] );

	/* command + args to exec for modrdn */
	} else if ( strcasecmp( argv[0], "modrdn" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"modrdn <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_modrdn = charray_dup( &argv[1] );

	/* command + args to exec for add */
	} else if ( strcasecmp( argv[0], "add" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"add <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_add = charray_dup( &argv[1] );

	/* command + args to exec for delete */
	} else if ( strcasecmp( argv[0], "delete" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"delete <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_delete = charray_dup( &argv[1] );

	/* command + args to exec for abandon */
	} else if ( strcasecmp( argv[0], "abandon" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing executable in \"abandon <executable>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		si->si_abandon = charray_dup( &argv[1] );

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in shell database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}
}
