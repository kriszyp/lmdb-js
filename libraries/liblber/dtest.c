/* dtest.c - lber decoding test program */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#ifdef HAVE_CONSOLE_H
#include <console.h>
#endif /* MACOS */

#include "lber.h"

static void usage( char *name )
{
	fprintf( stderr, "usage: %s fmt\n", name );
}

int
main( int argc, char **argv )
{
	long		i;
	unsigned long	len;
	int		tag;
	BerElement	ber;
	Sockbuf		sb;

#ifdef HAVE_CONSOLE_H
	ccommand( &argv );
	cshow( stdout );
#endif /* MACOS */

	memset( &sb, 0, sizeof(sb) );
	sb.sb_sd = 0;
	sb.sb_ber.ber_buf = NULL;

	if ( (tag = ber_get_next( &sb, &len, &ber )) == -1 ) {
		perror( "ber_get_next" );
		exit( 1 );
	}
	printf( "message has tag 0x%x and length %ld\n", tag, len );

	if ( ber_scanf( &ber, "i", &i ) == -1 ) {
		fprintf( stderr, "ber_scanf returns -1\n" );
		exit( 1 );
	}
	printf( "got int %d\n", i );

	return( 0 );
}
