/* line64.c - routines for dealing with the slapd line format */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#ifdef HAVE_FETCH
#include <fetch.h>
#endif

#include "ldap_log.h"
#include "lber_pvt.h"
#include "ldif.h"

int
ldif_fetch_url(
    LDAP_CONST char	*urlstr,
    char	**valuep,
    ber_len_t *vlenp
)
{
#ifdef HAVE_FETCH
	FILE *url = fetchGetURL( (char*) urlstr, "" );
	char buffer[1024];
	char *p = NULL;
	size_t total;
	size_t bytes;

	if( url == NULL ) {
		return -1;
	}

	total = 0;

	while( bytes = fread( buffer, 1, sizeof(buffer), url ) ) {
		char *newp = ber_memrealloc( p, total + bytes );
		if( newp == NULL ) {
			ber_memfree( p );
			fclose( url );
			return -1;
		}
		newp = p;
		SAFEMEMCPY( &p[total], buffer, bytes );
		total += bytes;
	}

	fclose( url );

	*valuep = p;
	*vlenp = total;

	return 0;

#else
	*valuep = NULL;
	*vlenp = NULL;
	return -1;
#endif
}

