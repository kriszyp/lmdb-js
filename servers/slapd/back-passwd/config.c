/* config.c - passwd backend configuration file routine */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "portable.h"
#include "slap.h"

passwd_back_config(
    Backend	*be,
    char	*fname,
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
			exit( 1 );
		}
		be->be_private = strdup( argv[1] );
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
}
