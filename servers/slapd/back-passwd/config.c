/* config.c - passwd backend configuration file routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "external.h"

int
passwd_back_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	/* alternate passwd file */
	if ( strcasecmp( argv[0], "file" ) == 0 ) {
#ifdef HAVE_SETPWFILE
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing filename in \"file <filename>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		be->be_private = ch_strdup( argv[1] );
#else /* HAVE_SETPWFILE */
		fprintf( stderr,
    "%s: line %d: ignoring \"file\" option (not supported on this platform)\n",
			    fname, lineno );
#endif /* HAVE_SETPWFILE */

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in passwd database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}

	return( 0 );
}
