/* ldif.c - routines for dealing with LDIF files */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1992-1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.  This
 * software is provided ``as is'' without express or implied warranty.
 */
/* This work was originally developed by the University of Michigan
 * and distributed as part of U-MICH LDAP.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

int ldif_debug = 0;

#include "ldap_log.h"
#include "lber_pvt.h"
#include "ldif.h"

#define RIGHT2			0x03
#define RIGHT4			0x0f
#define CONTINUED_LINE_MARKER	'\r'

#ifdef CSRIMALLOC
#define ber_memalloc malloc
#define ber_memcalloc calloc
#define ber_memrealloc realloc
#define ber_strdup strdup
#endif

static const char nib2b64[0x40] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char b642nib[0x80] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * ldif_parse_line - takes a line of the form "type:[:] value" and splits it
 * into components "type" and "value".  if a double colon separates type from
 * value, then value is encoded in base 64, and parse_line un-decodes it
 * (in place) before returning.
 */

int
ldif_parse_line(
    LDAP_CONST char	*line,
    char	**typep,
    char	**valuep,
    ber_len_t *vlenp
)
{
	char	*s, *p, *d; 
	char	nib;
	int	b64, url;
	char	*freeme, *type, *value;
	ber_len_t vlen;

	*typep = NULL;
	*valuep = NULL;
	*vlenp = 0;

	/* skip any leading space */
	while ( isspace( (unsigned char) *line ) ) {
		line++;
	}

	freeme = ber_strdup( line );

	if( freeme == NULL ) {
		ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
			_("ldif_parse_line: line malloc failed\n"));
		return( -1 );
	}

	type = freeme;

	s = strchr( type, ':' );

	if ( s == NULL ) {
		ber_pvt_log_printf( LDAP_DEBUG_PARSE, ldif_debug,
			_("ldif_parse_line: missing ':' after %s\n"),
			type );
		ber_memfree( freeme );
		return( -1 );
	}

	/* trim any space between type and : */
	for ( p = &s[-1]; p > type && isspace( * (unsigned char *) p ); p-- ) {
		*p = '\0';
	}
	*s++ = '\0';

	url = 0;
	b64 = 0;

	if ( *s == '<' ) {
		s++;
		url = 1;

	} else if ( *s == ':' ) {
		/* base 64 encoded value */
		s++;
		b64 = 1;
	}

	/* skip space between : and value */
	while ( isspace( (unsigned char) *s ) ) {
		s++;
	}

	/* check for continued line markers that should be deleted */
	for ( p = s, d = s; *p; p++ ) {
		if ( *p != CONTINUED_LINE_MARKER )
			*d++ = *p;
	}
	*d = '\0';

	if ( b64 ) {
		char *byte = s;

		if ( *s == '\0' ) {
			/* no value is present, error out */
			ber_pvt_log_printf( LDAP_DEBUG_PARSE, ldif_debug,
				_("ldif_parse_line: %s missing base64 value\n"), type );
			ber_memfree( freeme );
			return( -1 );
		}

		byte = value = s;

		for ( p = s, vlen = 0; p < d; p += 4, vlen += 3 ) {
			int i;
			for ( i = 0; i < 4; i++ ) {
				if ( p[i] != '=' && (p[i] & 0x80 ||
				    b642nib[ p[i] & 0x7f ] > 0x3f) ) {
					ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
						_("ldif_parse_line: %s: invalid base64 encoding"
						" char (%c) 0x%x\n"),
					    type, p[i], p[i] );
					ber_memfree( freeme );
					return( -1 );
				}
			}

			/* first digit */
			nib = b642nib[ p[0] & 0x7f ];
			byte[0] = nib << 2;
			/* second digit */
			nib = b642nib[ p[1] & 0x7f ];
			byte[0] |= nib >> 4;
			byte[1] = (nib & RIGHT4) << 4;
			/* third digit */
			if ( p[2] == '=' ) {
				vlen += 1;
				break;
			}
			nib = b642nib[ p[2] & 0x7f ];
			byte[1] |= nib >> 2;
			byte[2] = (nib & RIGHT2) << 6;
			/* fourth digit */
			if ( p[3] == '=' ) {
				vlen += 2;
				break;
			}
			nib = b642nib[ p[3] & 0x7f ];
			byte[2] |= nib;

			byte += 3;
		}
		s[ vlen ] = '\0';

	} else if ( url ) {
		if ( *s == '\0' ) {
			/* no value is present, error out */
			ber_pvt_log_printf( LDAP_DEBUG_PARSE, ldif_debug,
				_("ldif_parse_line: %s missing URL value\n"), type );
			ber_memfree( freeme );
			return( -1 );
		}

		if( ldif_fetch_url( s, &value, &vlen ) ) {
			ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
				_("ldif_parse_line: %s: URL \"%s\" fetch failed\n"),
				type, s );
			ber_memfree( freeme );
			return( -1 );
		}

	} else {
		value = s;
		vlen = (int) (d - s);
	}

	type = ber_strdup( type );

	if( type == NULL ) {
		ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
			_("ldif_parse_line: type malloc failed\n"));
		if( url ) ber_memfree( value );
		ber_memfree( freeme );
		return( -1 );
	}

	if( !url ) {
		p = ber_memalloc( vlen + 1 );
		if( p == NULL ) {
			ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
				_("ldif_parse_line: value malloc failed\n"));
			ber_memfree( type );
			ber_memfree( freeme );
			return( -1 );
		}
		AC_MEMCPY( p, value, vlen );
		p[vlen] = '\0';
		value = p;
	}

	ber_memfree( freeme );

	*typep = type;
	*valuep = value;
	*vlenp = vlen;

	return( 0 );
}

/*
 * ldif_getline - return the next "line" (minus newline) of input from a
 * string buffer of lines separated by newlines, terminated by \n\n
 * or \0.  this routine handles continued lines, bundling them into
 * a single big line before returning.  if a line begins with a white
 * space character, it is a continuation of the previous line. the white
 * space character (nb: only one char), and preceeding newline are changed
 * into CONTINUED_LINE_MARKER chars, to be deleted later by the
 * ldif_parse_line() routine above.
 *
 * ldif_getline will skip over any line which starts '#'.
 *
 * ldif_getline takes a pointer to a pointer to the buffer on the first call,
 * which it updates and must be supplied on subsequent calls.
 */

char *
ldif_getline( char **next )
{
	char *line;

	do {
		if ( *next == NULL || **next == '\n' || **next == '\0' ) {
			return( NULL );
		}

		line = *next;

		while ( (*next = strchr( *next, '\n' )) != NULL ) {
#if CONTINUED_LINE_MARKER != '\r'
			if ( (*next)[-1] == '\r' ) {
				(*next)[-1] = CONTINUED_LINE_MARKER;
			}
#endif

			if ( (*next)[1] != ' ' ) {
				if ( (*next)[1] == '\r' && (*next)[2] == '\n' ) {
					*(*next)++ = '\0';
				}
				*(*next)++ = '\0';
				break;
			}

			**next = CONTINUED_LINE_MARKER;
			(*next)[1] = CONTINUED_LINE_MARKER;
			(*next)++;
		}
	} while( *line == '#' );

	return( line );
}

/* compatibility with U-Mich off by one bug */
#define LDIF_KLUDGE 1

void
ldif_sput(
	char **out,
	int type,
	LDAP_CONST char *name,
	LDAP_CONST char *val,
	ber_len_t vlen )
{
	const unsigned char *byte, *stop;
	unsigned char	buf[3];
	unsigned long	bits;
	char		*save;
	int		pad;
	int		namelen = 0;

	ber_len_t savelen;
	ber_len_t len=0;
	ber_len_t i;

	/* prefix */
	switch( type ) {
	case LDIF_PUT_COMMENT:
		*(*out)++ = '#';
		len++;

		if( vlen ) {
			*(*out)++ = ' ';
			len++;
		}

		break;

	case LDIF_PUT_SEP:
		*(*out)++ = '\n';
		return;
	}

	/* name (attribute type) */
	if( name != NULL ) {
		/* put the name + ":" */
		namelen = strlen(name);
		strcpy(*out, name);
		*out += namelen;
		len += namelen;

		if( type != LDIF_PUT_COMMENT ) {
			*(*out)++ = ':';
			len++;
		}

	}
#ifdef LDAP_DEBUG
	else {
		assert( type == LDIF_PUT_COMMENT );
	}
#endif

	if( vlen == 0 ) {
		*(*out)++ = '\n';
		return;
	}

	switch( type ) {
	case LDIF_PUT_NOVALUE:
		*(*out)++ = '\n';
		return;

	case LDIF_PUT_URL: /* url value */
		*(*out)++ = '<';
		len++;
		break;

	case LDIF_PUT_B64: /* base64 value */
		*(*out)++ = ':';
		len++;
		break;
	}

	switch( type ) {
	case LDIF_PUT_TEXT:
	case LDIF_PUT_URL:
	case LDIF_PUT_B64:
		*(*out)++ = ' ';
		len++;
		/* fall-thru */

	case LDIF_PUT_COMMENT:
		/* pre-encoded names */
		for ( i=0; i < vlen; i++ ) {
			if ( len > LDIF_LINE_WIDTH ) {
				*(*out)++ = '\n';
				*(*out)++ = ' ';
				len = 1;
			}

			*(*out)++ = val[i];
			len++;
		}
		*(*out)++ = '\n';
		return;
	}

	save = *out;
	savelen = len;

	*(*out)++ = ' ';
	len++;

	stop = (const unsigned char *) (val + vlen);

	if ( type == LDIF_PUT_VALUE
		&& isgraph( (unsigned char) val[0] ) && val[0] != ':' && val[0] != '<'
		&& isgraph( (unsigned char) val[vlen-1] )
#ifndef LDAP_BINARY_DEBUG
		&& strstr( name, ";binary" ) == NULL
#endif
#ifndef LDAP_PASSWD_DEBUG
		&& (namelen != (sizeof("userPassword")-1)
		|| strcasecmp( name, "userPassword" ) != 0)	/* encode userPassword */
		&& (namelen != (sizeof("2.5.4.35")-1) 
		|| strcasecmp( name, "2.5.4.35" ) != 0)		/* encode userPassword */
#endif
	) {
		int b64 = 0;

		for ( byte = (const unsigned char *) val; byte < stop;
		    byte++, len++ )
		{
			if ( !isascii( *byte ) || !isprint( *byte ) ) {
				b64 = 1;
				break;
			}
			if ( len > LDIF_LINE_WIDTH+LDIF_KLUDGE ) {
				*(*out)++ = '\n';
				*(*out)++ = ' ';
				len = 1;
			}
			*(*out)++ = *byte;
		}

		if( !b64 ) {
			*(*out)++ = '\n';
			return;
		}
	}

	*out = save;
	*(*out)++ = ':';
	*(*out)++ = ' ';
	len = savelen + 2;

	/* convert to base 64 (3 bytes => 4 base 64 digits) */
	for ( byte = (const unsigned char *) val;
		byte < stop - 2;
	    byte += 3 )
	{
		bits = (byte[0] & 0xff) << 16;
		bits |= (byte[1] & 0xff) << 8;
		bits |= (byte[2] & 0xff);

		for ( i = 0; i < 4; i++, len++, bits <<= 6 ) {
			if ( len > LDIF_LINE_WIDTH+LDIF_KLUDGE ) {
				*(*out)++ = '\n';
				*(*out)++ = ' ';
				len = 1;
			}

			/* get b64 digit from high order 6 bits */
			*(*out)++ = nib2b64[ (bits & 0xfc0000L) >> 18 ];
		}
	}

	/* add padding if necessary */
	if ( byte < stop ) {
		for ( i = 0; byte + i < stop; i++ ) {
			buf[i] = byte[i];
		}
		for ( pad = 0; i < 3; i++, pad++ ) {
			buf[i] = '\0';
		}
		byte = buf;
		bits = (byte[0] & 0xff) << 16;
		bits |= (byte[1] & 0xff) << 8;
		bits |= (byte[2] & 0xff);

		for ( i = 0; i < 4; i++, len++, bits <<= 6 ) {
			if ( len > LDIF_LINE_WIDTH+LDIF_KLUDGE ) {
				*(*out)++ = '\n';
				*(*out)++ = ' ';
				len = 1;
			}

			if( i + pad < 4 ) {
				/* get b64 digit from low order 6 bits */
				*(*out)++ = nib2b64[ (bits & 0xfc0000L) >> 18 ];
			} else {
				*(*out)++ = '=';
			}
		}
	}
	*(*out)++ = '\n';
}


/*
 * ldif_type_and_value return BER malloc'd, zero-terminated LDIF line
 */
char *
ldif_put(
	int type,
	LDAP_CONST char *name,
	LDAP_CONST char *val,
	ber_len_t vlen )
{
    char	*buf, *p;
    ber_len_t nlen;

    nlen = ( name != NULL ) ? strlen( name ) : 0;

	buf = (char *) ber_memalloc( LDIF_SIZE_NEEDED( nlen, vlen ) + 1 );

    if ( buf == NULL ) {
		ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
			_("ldif_type_and_value: malloc failed!"));
		return NULL;
    }

    p = buf;
    ldif_sput( &p, type, name, val, vlen );
    *p = '\0';

    return( buf );
}

int ldif_is_not_printable(
	LDAP_CONST char *val,
	ber_len_t vlen )
{
	if( vlen == 0 || val == NULL  ) {
		return -1;
	}

	if( isgraph( (unsigned char) val[0] ) && val[0] != ':' && val[0] != '<' &&
		isgraph( (unsigned char) val[vlen-1] ) )
	{
		ber_len_t i;

		for ( i = 0; val[i]; i++ ) {
			if ( !isascii( val[i] ) || !isprint( val[i] ) ) {
				return 1;
			}
		}

		return 0;
	}

	return 1;
}

/*
 * slap_read_ldif - read an ldif record.  Return 1 for success, 0 for EOF.
 */
int
ldif_read_record(
	FILE        *fp,
	int         *lno,		/* ptr to line number counter              */
	char        **bufp,     /* ptr to malloced output buffer           */
	int         *buflenp )  /* ptr to length of *bufp                  */
{
	char        linebuf[BUFSIZ], *line, *nbufp;
	ber_len_t   lcur = 0, len, linesize;
	int         last_ch = '\n', found_entry = 0, stop, top_comment = 0;

	line     = linebuf;
	linesize = sizeof( linebuf );

	for ( stop = feof( fp );  !stop;  last_ch = line[len-1] ) {
		if ( fgets( line, linesize, fp ) == NULL ) {
			stop = 1;
			/* Add \n in case the file does not end with newline */
			line = "\n";
		}
		len = strlen( line );

		if ( last_ch == '\n' ) {
			(*lno)++;

			if ( line[0] == '\n' ) {
				if ( !found_entry ) {
					lcur = 0;
					top_comment = 0;
					continue;
				}
				break;
			}

			if ( !found_entry ) {
				if ( line[0] == '#' ) {
					top_comment = 1;
				} else if ( ! ( top_comment && line[0] == ' ' ) ) {
					/* Found a new entry */
					found_entry = 1;

					if ( isdigit( (unsigned char) line[0] ) ) {
						/* skip index */
						continue;
					}
				}
			}			
		}

		if ( *buflenp - lcur <= len ) {
			*buflenp += len + BUFSIZ;
			nbufp = ber_memrealloc( *bufp, *buflenp );
			if( nbufp == NULL ) {
				return 0;
			}
			*bufp = nbufp;
		}
		strcpy( *bufp + lcur, line );
		lcur += len;
	}

	return( found_entry );
}
