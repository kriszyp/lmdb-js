/******************************************************************************
 *
 * Copyright (C) 2000 Pierangelo Masarati, <ando@sys-net.it>
 * All rights reserved.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users
 * ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 ******************************************************************************/

#include <portable.h>

#include <stdio.h>

#include "rewrite-int.h"

static int
parse_line(
		char **argv,
		int *argc,
		int maxargs, 
		char *buf
)
{
	char *p, *begin;
	int in_quoted_field = 0, cnt = 0;
	char quote = '\0';
	
	for ( p = buf; isspace( (unsigned char) p[ 0 ] ); p++ );
	
	if ( p[ 0 ] == '#' ) {
		return 0;
	}
	
	for ( begin = p;  p[ 0 ] != '\0'; p++ ) {
		if ( p[ 0 ] == '\\' && p[ 1 ] != '\0' ) {
			p++;
		} else if ( p[ 0 ] == '\'' || p[ 0 ] == '\"') {
			if ( in_quoted_field && p[ 0 ] == quote ) {
				in_quoted_field = 1 - in_quoted_field;
				quote = '\0';
				p[ 0 ] = '\0';
				argv[ cnt ] = begin;
				if ( ++cnt == maxargs ) {
					*argc = cnt;
					return 1;
				}
				for ( p++; isspace( (unsigned char) p[ 0 ] ); p++ );
				begin = p;
				p--;
				
			} else if ( !in_quoted_field ) {
				if ( p != begin ) {
					return -1;
				}
				begin++;
				in_quoted_field = 1 - in_quoted_field;
				quote = p[ 0 ];
			}
		} else if ( isspace( (unsigned char) p[ 0 ] ) && !in_quoted_field ) {
			p[ 0 ] = '\0';
			argv[ cnt ] = begin;

			if ( ++cnt == maxargs ) {
				*argc = cnt;
				return 1;
			}

			for ( p++; isspace( (unsigned char) p[ 0 ] ); p++ );
			begin = p;
			p--;
		}
	}
	
	*argc = cnt;

	return 1;
}

int
rewrite_read( 
		FILE *fin,
		struct rewrite_info *info
)
{
	char buf[ 1024 ];
	char *argv[11];
	int argc, lineno;

	/* 
	 * Empty rule at the beginning of the context
	 */

	for ( lineno = 0; fgets( buf, sizeof( buf ), fin ); lineno++ ) {
		switch ( parse_line( argv, &argc, sizeof( argv ) - 1, buf ) ) {
		case -1:
			return REWRITE_ERR;
		case 0:
			break;
		case 1:
			if ( strncasecmp( argv[ 0 ], "rewrite", 7 ) == 0 ) {
				int rc;
				rc = rewrite_parse( info, "file", lineno, 
						argc, argv );
				if ( rc != REWRITE_SUCCESS ) {
					return rc;
				}
			}
			break;
		}
	}

	return REWRITE_SUCCESS;
}

