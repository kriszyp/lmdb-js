/* $OpenLDAP$ */
/*
 * Copyright (c) 1990, 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/*
 * chlog2replog - read a quipu-style changelog on stdin and write a
 * slapd-style replog on stdout, or write to a file, respecting
 * slapd/slurpd locking conventions.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>

#include "ldif.h"

static int dn2ldif(PS ps, DN dn);
static void de_t61(char *s, int t61mark);

extern FILE *lock_fopen( char *, char *, FILE ** );
extern int lock_fclose( FILE *, FILE * );
extern void *ch_realloc( void *, unsigned long ); 

short	ldap_dn_syntax;
PS	rps;
char	*progname;
int	ldap_syslog = 0;
int	ldap_syslog_level = 0;


#define	ST_START	0
#define ST_DN		2
#define	ST_TYPE		3
#define	ST_ARGS		4
#define	ST_NL1		5
#define	ST_PUNT		6
#define	ST_BAD		7
#define	ST_CONCAT	8

#define TY_MODIFYTYPE	1
#define	TY_ADD		2
#define	TY_REMOVE	3
#define TY_NEWRDN	4
#define TY_PUNT		5
#define TY_MODIFYARGS	6

#define	MOD_ADDVALUES		1
#define MOD_ADDATTRIBUTE	2
#define MOD_REMOVEATTRIBUTE	3
#define	MOD_REMOVEVALUES	4


char *
dn2ldap( char *edbdn )
{
    DN		dn;
    PS		str_ps;
    char	*ldapdn;
    int		len;
    static int	inited = 0;

    if ( !inited ) {
	/* load & initialize quipu syntax handlers */
	quipu_syntaxes();

#ifdef LDAP_USE_PP
	pp_quipu_init( progname );
#endif

	dsap_init( NULL, NULL );

	if (( ldap_dn_syntax = str2syntax( "DN" )) == 0 ) {
	    return( NULL );
	}
	inited = 1;
    }

    if (( dn = str2dn( edbdn )) == NULLDN ) {
	return( NULL );
    }

    if (( str_ps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( str_ps, NULLCP, 0, 0 ) == NOTOK ) {
	dn_free( dn );
	return( NULL );
    }

    if ( dn2ldif( str_ps, dn ) != 0 ) {
	ps_free( str_ps );
	dn_free( dn );
	return( NULL );
    }

    dn_free( dn );
    len = ( str_ps->ps_ptr - str_ps->ps_base );

    if (( ldapdn = malloc( len + 1 )) == NULL ) {
	ps_free( str_ps );
	return( NULL );
    }

    memcpy( ldapdn, str_ps->ps_base, len );
    ldapdn[ len ] = '\0';
    ps_free( str_ps );
    return( ldapdn );
}


#define SEPARATOR(c)	((c) == ',' || (c) == ';')
#define SPACE(c)    	((c) == ' ' || (c) == '\n')

static int
dn2ldif( PS ps, DN dn )
{
    RDN	rdn;
    int	firstrdn, rc;
    char	*value;
    PS	rps;

    if ( dn == NULLDN ) {
	return( 0 );
    }

    if ( dn->dn_parent != NULLDN ) {
	if (( rc = dn2ldif( ps, dn->dn_parent )) != 0 ) {
	    return( rc );
	}
	ps_print( ps, ", " );
    }

    if ( (rps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( rps, NULLCP, 0, 0 ) == NOTOK ) {
	return( -1 );
    }

    firstrdn = 1;
    for ( rdn = dn->dn_rdn; rdn != NULLRDN; rdn = rdn->rdn_next ) {
	if ( firstrdn ) {
	    firstrdn = 0;
	} else {
	    ps_print( ps, " + " );
	}

	AttrT_print( ps, rdn->rdn_at, EDBOUT );
	ps_print( ps, "=" );

	if ( rdn->rdn_at->oa_syntax == ldap_dn_syntax ) {
	    if (( rc = dn2ldif( rps, (DN) rdn->rdn_av.av_struct )) != 0 ) {
		return( rc );
	    }
	    *rps->ps_ptr = '\0';
	    value = rps->ps_base;
	} else {
	    AttrV_print( rps, &rdn->rdn_av, EDBOUT );
	    *rps->ps_ptr = '\0';
	    value = rps->ps_base;
	    de_t61( value, 0 );
	}

	/*
	 * ,+="\\\n all go in quotes.  " and \\ need to
	 * be preceeded by \\.
	 */

	if ( strpbrk( value, ",+=\"\\\n" ) != NULL || SPACE( value[0] )
		|| SPACE( value[max( strlen(value) - 1, 0 )] ) ) {
	    char	*p, *t, *tmp;
	    int	specialcount;

	    ps_print( ps, "\"" );

	    specialcount = 0;
	    for ( p = value; *p != '\0'; p++ ) {
		if ( *p == '"' || *p == '\\' ) {
		    specialcount++;
		}
	    }
	    if ( specialcount > 0 ) {
		tmp = smalloc( strlen( value ) + specialcount + 1 );
		for ( p = value, t = tmp; *p != '\0'; p++ ) {
		    switch ( *p ) {
		    case '"':
		    case '\\':
			    *t++ = '\\';
			    /* FALL THROUGH */
		    default:
			    *t++ = *p;
		    }
		}
		*t = '\0';
		ps_print( ps, tmp );
		free( tmp );
	    } else {
		ps_print( ps, value );
	    }

	    ps_print( ps, "\"" );
	} else {
	    ps_print( ps, value );
	}

	rps->ps_ptr = rps->ps_base;
    }

    ps_free( rps );

    return( 0 );
}

#define T61	"{T.61}"
#define T61LEN	6



static void
de_t61(char *s, int t61mark)
{
	char	*next = s;
	unsigned char	c;
	unsigned int	hex;

	while ( *s ) {
		switch ( *s ) {
		case '{' :
			if ( strncasecmp( s, T61, T61LEN) == 0 ) {
				s += T61LEN;
				if ( t61mark )
					*next++ = '@';
			} else {
				*next++ = *s++;
			}
			break;

		case '\\':
			c = *(s + 1);
			if ( c == '\n' ) {
				s += 2;
				if ( *s == '\t' )
					s++;
				break;
			}
			if ( isdigit( c ) )
				hex = c - '0';
			else if ( c >= 'A' && c <= 'F' )
				hex = c - 'A' + 10;
			else if ( c >= 'a' && c <= 'f' )
				hex = c - 'a' + 10;
			else {
				*next++ = *s++;
				break;
			}
			hex <<= 4;
			c = *(s + 2);
			if ( isdigit( c ) )
				hex += c - '0';
			else if ( c >= 'A' && c <= 'F' )
				hex += c - 'A' + 10;
			else if ( c >= 'a' && c <= 'f' )
				hex += c - 'a' + 10;
			else {
				*next++ = *s++;
				*next++ = *s++;
				break;
			}

			*next++ = hex;
			s += 3;
			break;

		default:
			*next++ = *s++;
			break;
		}
	}
	*next = '\0';
}




char *
getattr(char *buf, char sep)
{
    char *val;
#define RBSIZE 255
    static char retbuf[ RBSIZE ];

    if (( val = strchr( buf, sep )) != NULL ) {
	strncpy( retbuf, buf, val - buf );
	retbuf[ val - buf ] = '\0';
    } else {
	retbuf[ 0 ] = '\0';
    }
    return( retbuf );
}


char *
getattr_ldif(char *buf)
{
    return( getattr( buf, ':' ));
}


char *
getattr_edb(char *buf)
{
    return( getattr( buf, '=' ));
}

char *
getval(char *buf, char sep)
{
    char *val;

    if (( val = strchr( buf, sep )) != NULL ) {
	return( strdup( ++val ));
    } else {
	return( NULL );
    }
}

char *
getval_ldif(char *buf)
{
    return( getval( buf, ':' ));
}


char *
getval_edb(char *buf)
{
    return( getval( buf, '=' ));
}




int
isDNsyntax(char *attr)
{
    oid_table_attr *p, *name2attr(char *);

    p = name2attr( attr );
    if ( p == ( oid_table_attr * ) 0 ) {
	return( -1 );
    }
    if ( p->oa_syntax == ldap_dn_syntax ) {
	return( 1 );
    } else {
	return( 0 );
    }
}



void
print_as(Attr_Sequence as, int modtype, FILE *ofp)
{
    Attr_Sequence p;
    AV_Sequence	av;
    char *attrname, *tmpdn, *obuf;

    p = as;
    for ( p = as; p != NULLATTR; p = p->attr_link) {
	rps->ps_ptr = rps->ps_base;
	AttrT_print( rps,  p->attr_type, EDBOUT );
	*rps->ps_ptr = '\0';
	attrname = strdup( rps->ps_base  );
	if ( modtype != 0 ) {
	    switch ( modtype ) {
	    case MOD_ADDVALUES:
	    case MOD_ADDATTRIBUTE:
		fprintf( ofp, "add: %s\n", attrname );
		break;
	    case MOD_REMOVEATTRIBUTE:
	    case MOD_REMOVEVALUES:
		fprintf( ofp, "delete: %s\n", attrname );
		break;
	    default:
		break;
	    }
	}
	for ( av = p->attr_value; av != NULLAV; av = av->avseq_next ) {
	    rps->ps_ptr = rps->ps_base;
	    AttrV_print( rps, &av->avseq_av, EDBOUT );
	    *rps->ps_ptr = '\0';
	    de_t61( rps->ps_base, 0 );
	    if ( isDNsyntax( attrname )) {
		tmpdn = dn2ldap( rps->ps_base );
		obuf = ldif_type_and_value( attrname, tmpdn,
			strlen( tmpdn ));
		free( tmpdn );
	    } else {
		obuf = ldif_type_and_value( attrname, rps->ps_base,
			strlen( rps->ps_base ));
	    }
	    if ( obuf != NULL ) {
		fputs( obuf, ofp );
		ber_memfree( obuf );
	    }
	}
	if ( modtype != 0 ) {
	    fprintf( ofp, "-\n" );
	}
	free( attrname );
    }
}



void
usage( char *name )
{
    fprintf( stderr, "usage: %s -d dn-suffix -r replica:port ", name );
    fprintf( stderr, "[-r replica:port...] [-o outputfile]\n" );
}



main( int argc, char **argv )
{
    char		*ldapdn, nbuf[ 4096 ], *buf, *p;
    int			state, prevstate, modstate, modtype, i;
    int			buflen, nbuflen;
    Attr_Sequence	as;
    PS			std_ps;
    int			arg;
    char		*ofile = NULL;
    FILE		*ofp, *lfp;

    extern char		*optarg;
    char		**replicas = NULL;
    int			nreplicas = 0;
    char		*dn_suffix = NULL;

    if (( progname = strrchr( argv[ 0 ], '/' )) == NULL ) {
	progname = argv[ 0 ];
    } else {
	++progname;
    }

    while (( arg = getopt( argc, argv, "o:r:d:" )) != EOF ) {
	switch( arg ) {
	case 'o':
	    ofile = optarg;
	    break;
	case 'r':
	    replicas = (char **) ch_realloc( (char *) replicas, (unsigned long)
		    ( nreplicas + 2 ) * sizeof( char * ));
	    replicas[ nreplicas ] = optarg;
	    replicas[ nreplicas + 1 ] = NULL;
	    nreplicas++;
	    break;
	case 'd':
	    dn_suffix = optarg;
	    break;
	default:
	    usage( progname );
	    exit( EXIT_FAILURE );
	}
    }

    if (( dn_suffix == NULL ) || ( nreplicas == 0 )) {
	usage( progname );
	exit( EXIT_FAILURE );
    }

    if ( ofile == NULL ) {
	/* Just write to stdout */
	ofp = stdout;
    }


    state = prevstate = ST_START;
    buf = NULL;
    as = NULL;
    if (( std_ps = ps_alloc( std_open )) == NULLPS ||
	    std_setup( std_ps, ofp ) != OK ) {
	fprintf( stderr, "std_ps setup failed - help!\n" );
	exit( EXIT_FAILURE );
    }
    if (( rps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( rps, NULLCP, 0, 0 ) != OK ) {
	fprintf( stderr, "rps setup failed - help!\n" );
	exit( EXIT_FAILURE );
    }


    while ( gets( nbuf ) != NULL ) {
	if ( nbuf[ 0 ] == '\0' ) {
	    if ( state == ST_NL1 ) {
		if ( prevstate == ST_ARGS ) {
		    /* We've got an attribute sequence to print */
		    if ( modtype == TY_ADD ) {
			print_as( as, 0, ofp ); 
		    } else {
			print_as( as, modstate, ofp ); 
		    }
		    /* as_print( std_ps, as, EDBOUT ); */
		    as_free( as );
		    as = NULL;
		}
		state = ST_START;
		fprintf( ofp, "\n" );
		fflush( ofp );
		/* If writing to a file, release the lock */
		if ( ofile != NULL ) {
		    lock_fclose( ofp, lfp );
		}
	    } else {
		prevstate = state;
		state = ST_NL1;
	    }
	    continue;
	}

	/* See if we've got a line continuation to deal with */
	nbuflen = strlen( nbuf );
	if ( state == ST_CONCAT ) {
	    for ( p = nbuf; isspace( (unsigned char) *p ); p++, nbuflen-- )
		; /* skip space */
	    buf = realloc( buf, buflen + nbuflen + 1 );
	    strcat( buf, p );
	    buflen += ( nbuflen );
	} else {
	    if ( buf != NULL ) {
		free( buf );
	    }
	    buf = strdup( nbuf );
	    buflen = nbuflen;
	}
	if ( buf[ buflen - 1 ] == '\\' ) {
	    if ( state != ST_CONCAT ) {
		prevstate = state;
	    }
	    state = ST_CONCAT;
	    buf[ buflen - 1 ] = '\0';
	    buflen--;
	    continue;
	} else if ( state == ST_CONCAT ) {
	    state = prevstate;
	}

	if ( state == ST_PUNT ) {
	    continue;
	}

	if ( state == ST_START ) {
	    /*
	     * Acquire the file lock if writing to a file.
	     */
	    if ( ofile != NULL ) {
		if (( ofp = lock_fopen( ofile, "a", &lfp )) == NULL ) {
		    perror( "open" );
		    exit( EXIT_FAILURE );
		}
	    }
	    /*
	     * If we have a changelog entry, then go ahead
	     * and write the replica: lines for the replog entry.
	     */
	    for ( i = 0; replicas[ i ] != NULL; i++ ) {
		fprintf( ofp, "replica: %s\n", replicas[ i ] );
	    }
	    fprintf( ofp, "time: %ld\n", time( NULL ));
	    state = ST_DN;
	    continue;
	}

	if ( state == ST_DN ) {
	    /* Second line - dn (quipu-style) of entry to be modified */
	    if (( ldapdn = dn2ldap( buf )) == NULL ) {
		fprintf( ofp, "dn: (conversion failed)\n" );
	    } else {
		fprintf( ofp, "dn: %s%s\n", ldapdn, dn_suffix );
		free( ldapdn );
	    }
	    state = ST_TYPE;
	    continue;
	}

	if ( state == ST_TYPE ) {
	    state = ST_ARGS;
	    modstate = 0;
	    if ( !strcmp( buf, "modify" )) {
		modtype = TY_MODIFYTYPE;
		fprintf( ofp, "changetype: modify\n" );
	    } else if ( !strcmp( buf, "add" )) {
		modtype = TY_ADD;
		fprintf( ofp, "changetype: add\n" );
		as = NULL;
	    } else if ( !strcmp( buf, "remove" )) {
		modtype = TY_REMOVE;
		fprintf( ofp, "changetype: delete\n" );
	    } else if ( !strcmp( buf, "newrdn" )) {
		modtype = TY_NEWRDN;
		fprintf( ofp, "changetype: modrdn\n" );
	    } else {
		modtype = TY_PUNT;
		state = ST_BAD;
	    }
	    continue;
	}

	if ( state == ST_ARGS ) {
	    switch ( modtype ) {
	    case TY_NEWRDN:
		fprintf( ofp, "newrdn: %s\n", buf );
		break;
	    case TY_REMOVE:	/* No additional args */
		break;
	    case TY_ADD:
		as = as_combine( as, buf, 0 );
		break;
	    case TY_MODIFYTYPE:
	    case TY_MODIFYARGS:
		if ( buf[ 0 ] == '\0' ) {
		    state == ST_NL1;
		    if ( as != NULL ) {
			print_as( as, modstate, ofp);
			as_free( as );
			as = NULL;
		    }
		    continue;
		}
		if (!strcmp( buf, "addvalues" )) {
		    if ( as != NULL ) {
			print_as( as, modstate, ofp );
			as_free( as );
			as = NULL;
		    }
		    modstate = MOD_ADDVALUES;
		    continue;
		} else if (!strcmp( buf, "removevalues" )) {
		    if ( as != NULL ) {
			print_as( as, modstate, ofp );
			as_free( as );
			as = NULL;
		    }
		    modstate = MOD_REMOVEVALUES;
		    continue;
		} else if (!strcmp( buf, "addattribute" )) {
		    if ( as != NULL ) {
			print_as( as, modstate, ofp );
			as_free( as );
			as = NULL;
		    }
		    modstate = MOD_ADDATTRIBUTE;
		    continue;
		} else if (!strcmp( buf, "removeattribute" )) {
		    if ( as != NULL ) {
			print_as( as, modstate, ofp );
			as_free( as );
			as = NULL;
		    }
		    modstate = MOD_REMOVEATTRIBUTE;
		    continue;
		} 
		switch ( modstate ) {
		case MOD_ADDVALUES:
		    as = as_combine( as, buf, 0 );
		    break;
		case MOD_REMOVEVALUES:
		    as = as_combine( as, buf, 0 );
		    break;
		case MOD_ADDATTRIBUTE:
		    as = as_combine( as, buf, 0 );
		    break;
		case MOD_REMOVEATTRIBUTE:
		    fprintf( ofp, "delete: %s\n-\n", buf);
		    break;
		}
	    }
	    continue;
	}
    }

    if ( ofile != NULL ) {
	lock_fclose( ofp, lfp );
	sprintf( nbuf, "%s.lock", ofile );
	(void) unlink( nbuf );
    }
    exit( EXIT_SUCCESS );
}
