/* test.c - lber encoding test program */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_CONSOLE_H
#include <console.h>
#endif /* HAVE_CONSOLE_H */

#include "lber-int.h"

static void usage( char *name )
{
	fprintf( stderr, "usage: %s fmtstring\n", name );
}

static char* getbuf() {
	char *p;
	static char buf[128];

	if ( fgets( buf, sizeof(buf), stdin ) == NULL )
		return NULL;

	if ( (p = strchr( buf, '\n' )) != NULL )
		*p = '\0';

	return buf;
}

int
main( int argc, char **argv )
{
	char	*s;

	int			fd, rc;
	BerElement	*ber;
	Sockbuf		*sb;

	/* enable debugging */
	ber_int_debug = -1;

	if ( argc < 2 ) {
		usage( argv[0] );
		exit( 1 );
	}

#ifdef HAVE_CONSOLE_H
	ccommand( &argv );
	cshow( stdout );

	if (( fd = open( "lber-test", O_WRONLY|O_CREAT|O_TRUNC|O_BINARY ))
		< 0 ) {
	    perror( "open" );
	    exit( 1 );
	}

#else
	fd = fileno(stdout);
#endif /* MACOS */

	sb = ber_sockbuf_alloc_fd( fd );

	if( sb == NULL ) {
		perror( "lber_sockbuf_alloc_fd" );
		exit( 1 );
	}

	if ( (ber = ber_alloc_t( LBER_USE_DER )) == NULL ) {
		perror( "ber_alloc" );
		exit( 1 );
	}

	for ( s = argv[1]; *s; s++ ) {
		char *buf;
		char fmt[2];

		fmt[0] = *s;
		fmt[1] = '\0';

		printf("encode: %s\n", fmt );
		switch ( *s ) {
		case 'i':	/* int */
		case 'b':	/* boolean */
		case 'e':	/* enumeration */
			buf = getbuf();
			rc = ber_printf( ber, fmt, atoi(buf) );
			break;

		case 'n':	/* null */
		case '{':	/* begin sequence */
		case '}':	/* end sequence */
		case '[':	/* begin set */
		case ']':	/* end set */
			rc = ber_printf( ber, fmt );
			break;

		case 'o':	/* octet string (non-null terminated) */
		case 'B':	/* bit string */
			buf = getbuf();
			rc = ber_printf( ber, fmt, buf, strlen(buf) );
			break;

		case 's':	/* string */
		case 't':	/* tag for the next element */
			buf = getbuf();
			rc = ber_printf( ber, fmt, buf );
			break;

		default:
#ifdef LDAP_LIBUI
			fprintf( stderr, "unknown fmt %c\n", *fmt );
#endif /* LDAP_LIBUI */
			rc = -1;
			break;
		}

		if( rc == -1 ) {
			perror( "ber_printf" );
			exit( 1 );
		}
	}

	if ( ber_flush( sb, ber, 1 ) == -1 ) {
		perror( "ber_flush" );
		exit( 1 );
	}

	ber_sockbuf_free( sb );
	return( 0 );
}
