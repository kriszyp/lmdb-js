/* line64.c - routines for dealing with the slapd line format */

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
#define CONTINUED_LINE_MARKER	'\001'

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
    char	**type,
    char	**value,
    int		*vlen
)
{
	char	*p, *s, *d, *byte, *stop;
	char	nib;
	int	i, b64;

	/* skip any leading space */
	while ( isspace( (unsigned char) *line ) ) {
		line++;
	}
	*type = line;

	for ( s = line; *s && *s != ':'; s++ )
		;	/* NULL */
	if ( *s == '\0' ) {
		ber_pvt_log_printf( LDAP_DEBUG_PARSE, ldif_debug,
			"ldif_parse_line missing ':'\n");
		return( -1 );
	}

	/* trim any space between type and : */
	for ( p = s - 1; p > line && isspace( (unsigned char) *p ); p-- ) {
		*p = '\0';
	}
	*s++ = '\0';

	/* check for double : - indicates base 64 encoded value */
	if ( *s == ':' ) {
		s++;
		b64 = 1;

	/* single : - normally encoded value */
	} else {
		b64 = 0;
	}

	/* skip space between : and value */
	while ( isspace( (unsigned char) *s ) ) {
		s++;
	}

	/* if no value is present, error out */
	if ( *s == '\0' ) {
		ber_pvt_log_printf( LDAP_DEBUG_PARSE, ldif_debug,
			"ldif_parse_line missing value\n");
		return( -1 );
	}

	/* check for continued line markers that should be deleted */
	for ( p = s, d = s; *p; p++ ) {
		if ( *p != CONTINUED_LINE_MARKER )
			*d++ = *p;
	}
	*d = '\0';

	*value = s;
	if ( b64 ) {
		stop = strchr( s, '\0' );
		byte = s;
		for ( p = s, *vlen = 0; p < stop; p += 4, *vlen += 3 ) {
			for ( i = 0; i < 4; i++ ) {
				if ( p[i] != '=' && (p[i] & 0x80 ||
				    b642nib[ p[i] & 0x7f ] > 0x3f) ) {
					ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
"ldif_parse_line: invalid base 64 encoding char (%c) 0x%x\n",
					    p[i], p[i] );
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
				*vlen += 1;
				break;
			}
			nib = b642nib[ p[2] & 0x7f ];
			byte[1] |= nib >> 2;
			byte[2] = (nib & RIGHT2) << 6;
			/* fourth digit */
			if ( p[3] == '=' ) {
				*vlen += 2;
				break;
			}
			nib = b642nib[ p[3] & 0x7f ];
			byte[2] |= nib;

			byte += 3;
		}
		s[ *vlen ] = '\0';
	} else {
		*vlen = (int) (d - s);
	}

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
 * str_parse_line() routine above.
 *
 * it takes a pointer to a pointer to the buffer on the first call,
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
			unsigned char c = *(*next + 1);

			if ( !isspace( c ) || c == '\n' ) {
				*(*next)++ = '\0';
				break;
			}

			**next = CONTINUED_LINE_MARKER;
			*(*next+1) = CONTINUED_LINE_MARKER;
			(*next)++;
		}
	} while( *line == '#' );

	return( line );
}

void
ldif_put_type_and_value(
	char **out,
	LDAP_CONST char *t,
	LDAP_CONST char *val,
	int vlen )
{
	unsigned char	*byte, *p, *stop;
	unsigned char	buf[3];
	unsigned long	bits;
	char		*save;
	int		i, b64, pad, len, savelen;
	len = 0;

	/* put the type + ": " */
	for ( p = (unsigned char *) t; *p; p++, len++ ) {
		*(*out)++ = *p;
	}
	*(*out)++ = ':';
	len++;
	save = *out;
	savelen = len;
	*(*out)++ = ' ';
	b64 = 0;

	stop = (unsigned char *) (val + vlen);
	if ( isascii( val[0] ) && (isspace( val[0] ) || val[0] == ':') ) {
		b64 = 1;
	} else {
		for ( byte = (unsigned char *) val; byte < stop;
		    byte++, len++ ) {
			if ( !isascii( *byte ) || !isprint( *byte ) ) {
				b64 = 1;
				break;
			}
			if ( len > LDIF_LINE_WIDTH ) {
				*(*out)++ = '\n';
				*(*out)++ = ' ';
				len = 1;
			}
			*(*out)++ = *byte;
		}
	}
	if ( b64 ) {
		*out = save;
		*(*out)++ = ':';
		*(*out)++ = ' ';
		len = savelen + 2;
		/* convert to base 64 (3 bytes => 4 base 64 digits) */
		for ( byte = (unsigned char *) val; byte < stop - 2;
		    byte += 3 ) {
			bits = (byte[0] & 0xff) << 16;
			bits |= (byte[1] & 0xff) << 8;
			bits |= (byte[2] & 0xff);

			for ( i = 0; i < 4; i++, len++, bits <<= 6 ) {
				if ( len > LDIF_LINE_WIDTH ) {
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
				if ( len > LDIF_LINE_WIDTH ) {
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
	}
	*(*out)++ = '\n';
}


char *
ldif_type_and_value( LDAP_CONST char *type, LDAP_CONST char *val, int vlen )
/*
 * return BER malloc'd, zero-terminated LDIF line
 */
{
    char	*buf, *p;
    int		tlen;

    tlen = strlen( type );
    if (( buf = (char *) ber_memalloc( LDIF_SIZE_NEEDED( tlen, vlen ) + 1 ))
		== NULL )
	{
		ber_pvt_log_printf( LDAP_DEBUG_ANY, ldif_debug,
			"ldif_type_and_value: malloc failed!" );
		return NULL;
    }

    p = buf;
    ldif_put_type_and_value( &p, type, val, vlen );
    *p = '\0';

    return( buf );
}
