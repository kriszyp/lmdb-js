#include "portable.h"

#include <ldap_pvt_uc.h>
#include <ac/ctype.h>

int ucstrncmp(
	const ldap_unicode_t *u1,
	const ldap_unicode_t *u2,
	ber_len_t n )
{
	for(; 0 < n; ++u1, ++u2, --n ) {
		if( *u1 != *u2 ) {
			return *u1 < *u2 ? -1 : +1;
		}
		if ( *u1 == 0 ) {
			return 0;
		}
	}
	return 0;
}

int ucstrncasecmp(
	const ldap_unicode_t *u1,
	const ldap_unicode_t *u2,
	ber_len_t n )
{
	for(; 0 < n; ++u1, ++u2, --n ) {
		ldap_unicode_t uu1 = uctoupper( *u1 );
		ldap_unicode_t uu2 = uctoupper( *u2 );

		if( uu1 != uu2 ) {
			return uu1 < uu2 ? -1 : +1;
		}
		if ( uu1 == 0 ) {
			return 0;
		}
	}
	return 0;
}

ldap_unicode_t * ucstrnchr(
	const ldap_unicode_t *u,
	ber_len_t n,
	ldap_unicode_t c )
{
	for(; 0 < n; ++u, --n ) {
		if( *u == c ) {
			return (ldap_unicode_t *) u;
		}
	}

	return NULL;
}

ldap_unicode_t * ucstrncasechr(
	const ldap_unicode_t *u,
	ber_len_t n,
	ldap_unicode_t c )
{
	c = uctoupper( c );
	for(; 0 < n; ++u, --n ) {
		if( uctoupper( *u ) == c ) {
			return (ldap_unicode_t *) u;
		}
	}

	return NULL;
}

void ucstr2upper(
	ldap_unicode_t *u,
	ber_len_t n )
{
	for(; 0 < n; ++u, --n ) {
		*u = uctoupper( *u );
	}
}

char * UTF8normalize(
	const char *s,
	char casefold )
{
	int i, j, len, clen, outpos, ucsoutlen, outsize, last;
	char *out;
	unsigned long *ucs, *p, *ucsout;

	static unsigned char mask[] = {
                0, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

	if ( s == NULL ) {
		return NULL;
	}
	
	len = strlen( s );

	if ( len == 0 ) {
		out = (char *) malloc( 1 );
		*out = '\0';
		return out;
	}
	
	outsize = len + 7;
	out = (char *) malloc( outsize );
	if ( out == NULL ) {
		return NULL;
	}

	outpos = 0;

	/* finish off everything up to character before first non-ascii */
	if ( LDAP_UTF8_ISASCII( s ) ) {
		for ( i = 1; (i < len) && LDAP_UTF8_ISASCII(s + i); i++ ) {
			out[outpos++] = casefold ? TOUPPER( s[i-1] ) : s[i-1];
		}
		if ( i == len ) {
			out[outpos++] = casefold ? TOUPPER( s[len - 1] ) : s[len - 1];
			out[outpos] = '\0';
			return out;
		}
	} else {
		i = 0;
	}

	p = ucs = (long *) malloc( len * sizeof(*ucs) );
	if ( ucs == NULL ) {
		free(out);
		return NULL;
	}

	/* convert character before first non-ascii to ucs-4 */
	if ( i > 0 ) {
		*p = casefold ? TOUPPER( s[i - 1] ) : s[i - 1];
		p++;
	}

	/* s[i] is now first non-ascii character */
	for (;;) {
		/* s[i] is non-ascii */
		/* convert everything up to next ascii to ucs-4 */
		while ( i < len ) {
			clen = LDAP_UTF8_CHARLEN( s + i );
			if ( clen == 0 ) {
				free( ucs );
				free( out );
				return NULL;
			}
			if ( clen == 1 ) {
				/* ascii */
				break;
			}
			*p = s[i] & mask[clen];
			i++;
			for( j = 1; j < clen; j++ ) {
				if ( (s[i] & 0xc0) != 0x80 ) {
					free( ucs );
					free( out );
					return NULL;
				}
				*p <<= 6;
				*p |= s[i] & 0x3f;
				i++;
			}
			if ( casefold ) {
				*p = uctoupper( *p );
			}
			p++;
                }
		/* normalize ucs of length p - ucs */
		uccanondecomp( ucs, p - ucs, &ucsout, &ucsoutlen );    
		ucsoutlen = uccanoncomp( ucsout, ucsoutlen );
		/* convert ucs to utf-8 and store in out */
		for ( j = 0; j < ucsoutlen; j++ ) {
			/* allocate more space if not enough room for
			   6 bytes and terminator */
			if ( outsize - outpos < 7 ) {
				outsize = ucsoutlen - j + outpos + 6;
				out = (char *) realloc( out, outsize );
				if ( out == NULL ) {
					free( ucs );
					return NULL;
				}
			}
			outpos += ldap_ucs4_to_utf8( ucsout[j], &out[outpos] );
		}
		
		if ( i == len ) {
			break;
		}

		last = i;

		/* s[i] is ascii */
		/* finish off everything up to char before next non-ascii */
		for ( i++; (i < len) && LDAP_UTF8_ISASCII(s + i); i++ ) {
			out[outpos++] = casefold ? TOUPPER( s[i-1] ) : s[i-1];
		}
		if ( i == len ) {
			out[outpos++] = casefold ? TOUPPER( s[len - 1] ) : s[len - 1];
			break;
		}

		/* convert character before next non-ascii to ucs-4 */
		*ucs = casefold ? TOUPPER( s[i - 1] ) : s[i - 1];
		p = ucs + 1;
	}		
	free( ucs );
	out[outpos] = '\0';
	return out;
}
