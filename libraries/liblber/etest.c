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

#include <lber.h>

static void usage( char *name )
{
	fprintf( stderr, "usage: %s fmtstring\n", name );
}

int
main( int argc, char **argv )
{
#ifdef notdef
	int		i, len;
	char	*s, *p;
#endif
	int			fd, num;
	Seqorset	*sos = NULL;
	BerElement	*ber;
	Sockbuf		*sb;

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

	sb = ber_sockbuf_alloc_fd( fd);

	if( sb == NULL ) {
		perror( "lber_sockbuf_alloc_fd" );
		exit( 1 );
	}

	if ( (ber = ber_alloc_t( LBER_USE_DER )) == NULL ) {
		perror( "ber_alloc" );
		exit( 1 );
	}

#ifndef notdef
	num = 7;
	if ( ber_printf( ber, "{ti}", 0x1f44U, num ) == -1 ) {
		fprintf( stderr, "ber_printf returns -1" );
		exit( 1 );
	}

#else
	for ( s = argv[1]; *s; s++ ) {
		if ( fgets( buf, sizeof(buf), stdin ) == NULL )
			break;
		if ( (p = strchr( buf, '\n' )) != NULL )
			*p = '\0';

		switch ( *s ) {
		case 'i':	/* int */
		case 'b':	/* boolean */
			i = atoi( buf );
			if ( ber_printf( ber, "i", i ) == -1 ) {
				fprintf( stderr, "ber_printf i\n" );
				exit( 1 );
			}
			break;

		case 'e':	/* enumeration */
			i = va_arg( ap, int );
			rc = ber_put_enum( ber, i, (char)ber->ber_tag );
			break;

		case 'n':	/* null */
			rc = ber_put_null( ber, (char)ber->ber_tag );
			break;

		case 'o':	/* octet string (non-null terminated) */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );
			rc = ber_put_ostring( ber, s, len, (char)ber->ber_tag );
			break;

		case 's':	/* string */
			s = va_arg( ap, char * );
			rc = ber_put_string( ber, s, (char)ber->ber_tag );
			break;

		case 'B':	/* bit string */
			s = va_arg( ap, char * );
			len = va_arg( ap, int );	/* in bits */
			rc = ber_put_bitstring( ber, s, len, (char)ber->ber_tag );
			break;

		case 't':	/* tag for the next element */
			ber->ber_tag = va_arg( ap, int );
			ber->ber_usertag = 1;
			break;

		case 'v':	/* vector of strings */
			if ( (ss = va_arg( ap, char ** )) == NULL )
				break;
			for ( i = 0; ss[i] != NULL; i++ ) {
				if ( (rc = ber_put_string( ber, ss[i],
				    (char)ber->ber_tag )) == -1 )
					break;
			}
			break;

		case 'V':	/* sequences of strings + lengths */
			if ( (bv = va_arg( ap, struct berval ** )) == NULL )
				break;
			for ( i = 0; bv[i] != NULL; i++ ) {
				if ( (rc = ber_put_ostring( ber, bv[i]->bv_val,
				    bv[i]->bv_len, (char)ber->ber_tag )) == -1 )
					break;
			}
			break;

		case '{':	/* begin sequence */
			rc = ber_start_seq( ber, (char)ber->ber_tag );
			break;

		case '}':	/* end sequence */
			rc = ber_put_seqorset( ber );
			break;

		case '[':	/* begin set */
			rc = ber_start_set( ber, (char)ber->ber_tag );
			break;

		case ']':	/* end set */
			rc = ber_put_seqorset( ber );
			break;

		default:
#ifdef LDAP_LIBUI
			fprintf( stderr, "unknown fmt %c\n", *fmt );
#endif /* LDAP_LIBUI */
			rc = -1;
			break;
		}
		}
	}
#endif

	if ( ber_flush( sb, ber, 1 ) == -1 ) {
		perror( "ber_flush" );
		exit( 1 );
	}

	ber_sockbuf_free( sb );
	return( 0 );
}
