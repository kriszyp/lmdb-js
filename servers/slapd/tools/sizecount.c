/* $OpenLDAP$ */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <ldap.h>
#include <ldbm.h>

#define CACHE_SIZE	1000000
#define MODE		0600
#define DB_FLAGS	(LDBM_WRCREAT|LDBM_NEWDB)
#define SUBLEN		3

extern char	*first_word(char *);
extern char	*next_word(char *);
extern char	*word_dup(char *);
extern char	*phonetic(char *);

extern int ldap_debug;

int slap_debug;
int	ldap_syslog;
int	ldap_syslog_level;

static void	add(LDBM ldbm, char *s, int *count, int *size, int freeit);

int
main( int argc, char **argv )
{
	LDAP			*ld;
	LDAPMessage		*res, *e;
	int				i, j, k, count, len, nentries;
	int				vcount, wcount, pcount, scount;
	int				vsize, wsize, psize, ssize;
	struct berval	**bvals;
	char			**vals;
	char			*dn, *p, *val;
	char			buf[SUBLEN+1];
	LDBM			wldbm, pldbm, sldbm;
	static char		*attrs[] = { "cn", "nentries", NULL };

/*
	ldap_debug = 255;
*/
	if ( (ld = ldap_init( "vertigo:5555", 0 )) == NULL ) {
		perror( "ldap_init" );
		exit( EXIT_FAILURE );
	}

	if ( ldap_search( ld, "cn=index", LDAP_SCOPE_ONELEVEL, "(objectclass=*)",
	  attrs, 0 ) == -1 ) {
		ldap_perror( ld, "ldap_search" );
		exit( EXIT_FAILURE );
	}

	printf( "attr\tdn\tnentries\tvcount\tvsize\twcount\twsize\tpcount\tpsize\tscount\tssize\n" );
	fflush( stdout );
	count = 0;
	while ( ldap_result( ld, LDAP_RES_ANY, 0, NULL, &res )
	  == LDAP_RES_SEARCH_ENTRY ) {
		count++;
		e = ldap_first_entry( ld, res );
		dn = ldap_get_dn( ld, e );
		if ( (vals = ldap_get_values( ld, e, "nentries" )) != NULL ) {
			nentries = atoi( vals[0] );
			ldap_value_free( vals );
		} else {
			fprintf( stderr, "no nentries attribute for (%s)\n", dn );
			nentries = -1;
		}

		for ( i = 0; attrs[i] != NULL; i++ ) {
			if ( strcasecmp( attrs[i], "nentries" ) == 0 ) {
				continue;
			}
			if ( (wldbm = ldbm_open( "wcount.ldbm", DB_FLAGS, MODE,
			  CACHE_SIZE )) == NULL || (pldbm = ldbm_open( "pcount.ldbm",
			  DB_FLAGS, MODE, CACHE_SIZE )) == NULL || (sldbm = ldbm_open(
			  "scount.ldbm", DB_FLAGS, MODE, CACHE_SIZE )) == NULL ) {
				perror( "ldbm_open" );
				exit( EXIT_FAILURE );
			}
			vcount = 0; vsize = 0;
			wcount = 0; wsize = 0;
			pcount = 0; psize = 0;
			scount = 0; ssize = 0;
			if ( (bvals = ldap_get_values_len( ld, e, attrs[i] )) != NULL ) {
				for ( j = 0; bvals[j] != NULL; j++ ) {
					char	*w;

					/* update value count */
					vcount++;
					vsize += bvals[j]->bv_len;

					/* update word and phoneme counts */
					for ( w = first_word( bvals[j]->bv_val ); w != NULL;
					  w = next_word( w ) ) {
						add( wldbm, word_dup( w ), &wcount, &wsize, 1 );

						add( pldbm, phonetic( w ), &pcount, &psize, 1 );
					}

					/* update substring count */
					len = bvals[j]->bv_len;
					val = bvals[j]->bv_val;
					if ( len > SUBLEN - 2 ) {
						buf[0] = '^';
						for ( k = 0; k < SUBLEN - 1; k++ ) {
							buf[k + 1] = val[k];
						}
						buf[SUBLEN] = '\0';
						add( sldbm, buf, &scount, &ssize, 0 );

						p = val + len - SUBLEN + 1;
						for ( k = 0; k < SUBLEN; k++ ) {
							buf[k] = p[k];
						}
						buf[SUBLEN - 1] = '$';
						buf[SUBLEN] = '\0';
						add( sldbm, buf, &scount, &ssize, 0 );
					}
					for ( p = val; p < (val + len - SUBLEN + 1); p++ ) {
						for ( k = 0; k < SUBLEN; k++ ) {
							buf[k] = p[k];
						}
						buf[SUBLEN] = '\0';
						add( sldbm, buf, &scount, &ssize, 0 );
					}
				}
				ldap_value_free_len( bvals );
			}
			printf( "%s\t%s\t%d", attrs[i], dn, nentries );
			printf( "\t%d\t%d", vcount, vsize );
			printf( "\t%d\t%d", wcount, wsize );
			printf( "\t%d\t%d", pcount, psize );
			printf( "\t%d\t%d\n", scount, ssize );
			fflush( stdout );

			ldbm_close( wldbm );
			ldbm_close( pldbm );
			ldbm_close( sldbm );
		}

		free( dn );
		ldap_msgfree( res );
	}
	printf( "%d entries\n", count );
	fflush( stdout );

	if ( ldap_result2error( ld, res, 1 ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_result" );
	}
	ldap_unbind( ld );

	(void) unlink( "wcount.ldbm" );
	(void) unlink( "pcount.ldbm" );
	(void) unlink( "scount.ldbm" );

	exit( EXIT_SUCCESS );
}

static void
add(
    LDBM	ldbm,
    char	*s,
    int		*count,
    int		*size,
    int		freeit
)
{
	Datum	key, data;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.dptr = s;
	key.dsize = strlen( key.dptr ) + 1;
	data.dptr = "";
	data.dsize = 0;
	if ( ldbm_store( ldbm, key, data, LDBM_INSERT ) == 0 ) {
		(*count)++;
		(*size) += strlen( key.dptr );
	}
	if ( freeit && ( key.dptr != NULL ) )
		ldbm_datum_free( ldbm, key );
}
