/* ldapsync.c -- LDAP Content Sync Routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2005 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "lutil.h"
#include "slap.h"
#include "../../libraries/liblber/lber-int.h" /* get ber_strndup() */
#include "lutil_ldap.h"

#if 0
struct sync_cookie *slap_sync_cookie = NULL;
#else
struct slap_sync_cookie_s slap_sync_cookie =
	LDAP_STAILQ_HEAD_INITIALIZER( slap_sync_cookie );
#endif

void
slap_compose_sync_cookie(
	Operation *op,
	struct berval *cookie,
	struct berval *csn,
	int rid )
{
	char cookiestr[ LDAP_LUTIL_CSNSTR_BUFSIZE + 20 ];

	if ( csn->bv_val == NULL ) {
		if ( rid == -1 ) {
			cookiestr[0] = '\0';
		} else {
			snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
					"rid=%03d", rid );
		}
	} else {
		if ( rid == -1 ) {
			snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
					"csn=%s", csn->bv_val );
		} else {
			snprintf( cookiestr, LDAP_LUTIL_CSNSTR_BUFSIZE + 20,
					"csn=%s,rid=%03d", csn->bv_val, rid );
		}
	}
	ber_str2bv( cookiestr, strlen(cookiestr), 1, cookie );
}

void
slap_sync_cookie_free(
	struct sync_cookie *cookie,
	int free_cookie
)
{
	if ( cookie == NULL )
		return;

	if ( !BER_BVISNULL( &cookie->ctxcsn )) {
		ch_free( cookie->ctxcsn.bv_val );
		BER_BVZERO( &cookie->ctxcsn );
	}

	if ( !BER_BVISNULL( &cookie->octet_str )) {
		ch_free( cookie->octet_str.bv_val );
		BER_BVZERO( &cookie->octet_str );
	}

	if ( free_cookie ) {
		ch_free( cookie );
	}

	return;
}

int
slap_parse_sync_cookie(
	struct sync_cookie *cookie
)
{
	char *csn_ptr;
	char *csn_str;
	int csn_str_len;
	int valid = 0;
	char *rid_ptr;
	char *rid_str;
	char *cval;

	if ( cookie == NULL )
		return -1;

	while (( csn_ptr = strstr( cookie->octet_str.bv_val, "csn=" )) != NULL ) {
		AttributeDescription *ad = slap_schema.si_ad_modifyTimestamp;
		slap_syntax_validate_func *validate;
		struct berval stamp;

		csn_str = csn_ptr + STRLENOF("csn=");
		cval = strchr( csn_str, ',' );
		if ( cval )
			csn_str_len = cval - csn_str;
		else
			csn_str_len = 0;

		/* FIXME use csnValidate when it gets implemented */
		csn_ptr = strchr( csn_str, '#' );
		if ( !csn_ptr ) break;

		stamp.bv_val = csn_str;
		stamp.bv_len = csn_ptr - csn_str;
		validate = ad->ad_type->sat_syntax->ssyn_validate;
		if ( validate( ad->ad_type->sat_syntax, &stamp ) != LDAP_SUCCESS )
			break;
		valid = 1;
		break;
	}
	if ( valid ) {
		ber_str2bv( csn_str, csn_str_len, 1, &cookie->ctxcsn );
	} else {
		BER_BVZERO( &cookie->ctxcsn );
	}

	if (( rid_ptr = strstr( cookie->octet_str.bv_val, "rid=" )) != NULL ) {
		rid_str = SLAP_STRNDUP( rid_ptr,
							SLAP_SYNC_RID_SIZE + sizeof("rid=") - 1 );
		if ( (cval = strchr( rid_str, ',' )) != NULL ) {
			*cval = '\0';
		}
		cookie->rid = atoi( rid_str + sizeof("rid=") - 1 );
		ch_free( rid_str );
	} else {
		cookie->rid = -1;
	}
	return 0;
}

int
slap_init_sync_cookie_ctxcsn(
	struct sync_cookie *cookie
)
{
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE + 4 ];
	struct berval octet_str = BER_BVNULL;
	struct berval ctxcsn = BER_BVNULL;

	if ( cookie == NULL )
		return -1;

	octet_str.bv_len = snprintf( csnbuf, LDAP_LUTIL_CSNSTR_BUFSIZE + 4,
					"csn=%4d%02d%02d%02d%02d%02dZ#%06x#%02x#%06x",
					1900, 1, 1, 0, 0, 0, 0, 0, 0 );
	octet_str.bv_val = csnbuf;
	ch_free( cookie->octet_str.bv_val );
	ber_dupbv( &cookie->octet_str, &octet_str );

	ctxcsn.bv_val = octet_str.bv_val + 4;
	ctxcsn.bv_len = octet_str.bv_len - 4;
	ber_dupbv( &cookie->ctxcsn, &ctxcsn );

	return 0;
}

struct sync_cookie *
slap_dup_sync_cookie(
	struct sync_cookie *dst,
	struct sync_cookie *src
)
{
	int i;
	struct sync_cookie *new;
	struct berval tmp_bv;

	if ( src == NULL )
		return NULL;

	if ( dst ) {
		ch_free( dst->ctxcsn.bv_val );
		ch_free( dst->octet_str.bv_val );
		BER_BVZERO( &dst->ctxcsn );
		BER_BVZERO( &dst->octet_str );
		new = dst;
	} else {
		new = ( struct sync_cookie * )
				ch_calloc( 1, sizeof( struct sync_cookie ));
	}

	new->rid = src->rid;

	if ( !BER_BVISNULL( &src->ctxcsn )) {
		ber_dupbv( &new->ctxcsn, &src->ctxcsn );
	}

	if ( !BER_BVISNULL( &src->octet_str )) {
		ber_dupbv( &new->octet_str, &src->octet_str );
	}

	return new;
}

