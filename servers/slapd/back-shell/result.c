/* result.c - shell backend result reading function */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slap.h"
#include "shell.h"

int
read_and_send_results(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    FILE	*fp,
    char	**attrs,
    int		attrsonly
)
{
	int	bsize, len;
	char	*buf, *bp;
	char	line[BUFSIZ];
	Entry	*e;
	int	err;
	char	*matched, *info;

	/* read in the result and send it along */
	buf = (char *) ch_malloc( BUFSIZ );
	buf[0] = '\0';
	bsize = BUFSIZ;
	bp = buf;
	while ( fgets( line, sizeof(line), fp ) != NULL ) {
		Debug( LDAP_DEBUG_SHELL, "shell search reading line (%s)\n",
		    line, 0, 0 );
		/* ignore lines beginning with DEBUG: */
		if ( strncasecmp( line, "DEBUG:", 6 ) == 0 ) {
			continue;
		}
		len = strlen( line );
		while ( bp + len - buf > bsize ) {
			bsize += BUFSIZ;
			buf = (char *) ch_realloc( buf, bsize );
		}
		strcpy( bp, line );
		bp += len;

		/* line marked the end of an entry or result */
		if ( *line == '\n' ) {
			if ( strncasecmp( buf, "RESULT", 6 ) == 0 ) {
				break;
			}

			if ( (e = str2entry( buf )) == NULL ) {
				Debug( LDAP_DEBUG_ANY, "str2entry(%s) failed\n",
				    buf, 0, 0 );
			} else {
				send_search_entry( be, conn, op, e, attrs,
				    attrsonly, NULL );
				entry_free( e );
			}

			bp = buf;
		}
	}
	(void) str2result( buf, &err, &matched, &info );

	/* otherwise, front end will send this result */
	if ( err != 0 || op->o_tag != LDAP_REQ_BIND ) {
		send_ldap_result( conn, op, err, matched, info, NULL, NULL );
	}

	free( buf );

	return( err );
}

void
print_suffixes(
    FILE	*fp,
    Backend	*be
)
{
	int	i;

	for ( i = 0; be->be_suffix[i] != NULL; i++ ) {
		fprintf( fp, "suffix: %s\n", be->be_suffix[i] );
	}
}
