#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldif2common.h"
#include "../back-ldbm/back-ldbm.h"
#include "ldif.h"

int
main( int argc, char **argv )
{
	int		i, stop;
	char		*linep, *buf, *attr;
	char		line[BUFSIZ];
	int		lineno, elineno;
	int      	lmax, lcur, indexmask, syntaxmask;
	unsigned long	id;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];

	ldbm_ignore_nextid_file = 1;

	slap_ldif_init( argc, argv, LDIF2INDEX, "ldbm", SLAP_TOOL_MODE );
	attr = attr_normalize( argv[argc - 1] );

	slap_startup(dbnum);

	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	attr_masks( be->be_private, attr, &indexmask, &syntaxmask );
	if ( indexmask == 0 ) {
		exit( EXIT_SUCCESS );
	}

	id = 0;
	stop = 0;
	lineno = 0;
	buf = NULL;
	lcur = lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( ! stop ) {
		char		*type, *val, *s;
		ber_len_t		vlen;

		if ( fgets( line, sizeof(line), stdin ) != NULL ) {
			int     len;

			lineno++;
			len = strlen( line );
			while ( lcur + len + 1 > lmax ) {
				lmax += BUFSIZ;
				buf = (char *) ch_realloc( buf, lmax );
			}
			strcpy( buf + lcur, line );
			lcur += len;
		} else {
			stop = 1;
		}
		if ( line[0] == '\n' || stop && buf && *buf ) {
			if ( *buf != '\n' ) {
				if (isdigit((unsigned char) *buf)) {
					id = atol(buf);
				} else {
					id++;
				}
				s = buf;
				elineno = 0;
				while ( (linep = ldif_getline( &s )) != NULL ) {
					elineno++;
					if ( ldif_parse_line( linep, &type, &val,
					    &vlen ) != 0 ) {
						Debug( LDAP_DEBUG_PARSE,
			    "bad line %d in entry ending at line %d ignored\n",
						    elineno, elineno, 0 );
						continue;
					}

					if ( strcasecmp( type, attr ) == 0 ) {
						bv.bv_val = val;
						bv.bv_len = vlen;
						index_change_values( be,
								     attr,
								     vals,
								     id,
							       __INDEX_ADD_OP);
					}
				}
			}
			*buf = '\0';
			lcur = 0;
		}
	}

	slap_shutdown(dbnum);
	slap_destroy();

	return( EXIT_SUCCESS );
}
