#include "portable.h"

#include <ldap_pvt_uc.h>

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


