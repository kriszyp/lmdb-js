/* $OpenLDAP$ */
/* 
 * Copyright 1999 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/*
 * LDAPv3 Extended Operation Request
 *	ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *		requestName      [0] LDAPOID,
 *		requestValue     [1] OCTET STRING OPTIONAL
 *	}
 *
 * LDAPv3 Extended Operation Response
 *	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *		COMPONENTS OF LDAPResult,
 *		responseName     [10] LDAPOID OPTIONAL,
 *		response         [11] OCTET STRING OPTIONAL
 *	}
 *
 */

#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"

#ifdef SLAPD_EXTERNAL_EXTENSIONS

typedef struct extensions_cookie_t {
    Connection	*conn;
    Operation	*op;
} extensions_cookie_t;

#define MAX_OID_LENGTH	128

typedef struct extensions_list_t {
	struct extensions_list_t *next;
	char *oid;
	int (*ext_main)(int (*)(), void *, char *reqoid, struct berval *reqdata, char **rspoid, struct berval *rspdata, char **text);
} extensions_list_t;

extensions_list_t *supp_ext_list = NULL;

#define MAX_SUPP_EXT_TRACKED	64
int supp_ext_count = 0;
char *supportedExtensions[MAX_SUPP_EXT_TRACKED] = { NULL };

extensions_list_t *find_extension (extensions_list_t *list, char *oid);
int extensions_callback (extensions_cookie_t *cookie, int msg, int arg, void *argp);
#else

char *supportedExtensions[] = {
	NULL
};
#endif


int
do_extended(
    Connection	*conn,
    Operation	*op
)
{
	int rc = LDAP_SUCCESS;
	char* reqoid ;
	struct berval reqdata;
	ber_tag_t tag;
	ber_len_t len;
#ifdef SLAPD_EXTERNAL_EXTENSIONS
	extensions_list_t *ext;
	char *rspoid, *text;
	struct berval rspdata;
	extensions_cookie_t cookie;
#endif

	Debug( LDAP_DEBUG_TRACE, "do_extended\n", 0, 0, 0 );

	reqoid = NULL;
	reqdata.bv_val = NULL;

	if( op->o_protocol < LDAP_VERSION3 ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: protocol version (%d) too low\n",
			op->o_protocol, 0 ,0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "requires LDAPv3" );
		rc = -1;
		goto done;
	}

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &reqoid ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto done;
	}

#ifdef SLAPD_EXTERNAL_EXTENSIONS
	if( !(ext = find_extension(supp_ext_list, reqoid)) )
#else
	if( !charray_inlist( supportedExtensions, reqoid ) )
#endif
	{
		Debug( LDAP_DEBUG_ANY, "do_extended: unsupported operation \"%s\"\n",
			reqoid, 0 ,0 );
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "unsuppored extended operation", NULL, NULL );
		goto done;
	}

	tag = ber_peek_tag( op->o_ber, &len );
	
	if( ber_peek_tag( op->o_ber, &len ) == LDAP_TAG_EXOP_REQ_VALUE ) {
		if( ber_scanf( op->o_ber, "o", &reqdata ) == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = -1;
			goto done;
		}
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: get_ctrls failed\n", 0, 0 ,0 );
		return rc;
	} 

	Debug( LDAP_DEBUG_ARGS, "do_extended: oid \"%s\"\n", reqoid, 0 ,0 );

#ifdef SLAPD_EXTERNAL_EXTENSIONS
	cookie.conn = conn;
	cookie.op = op;
	rspoid = NULL;
	rspdata.bv_len = 0;
	rspdata.bv_val = NULL;
	text = NULL;
	rc = (ext->ext_main)(extensions_callback, &cookie, reqoid, &reqdata, &rspoid, &rspdata, &text);

	send_ldap_extended(conn, op, rc, NULL, text, rspoid, rspdata.bv_val ? &rspdata : NULL);

	if (rspoid != NULL)
		free(rspoid);
	if ( rspdata.bv_val != NULL )
		free(rspdata.bv_val);
	if ( text != NULL )
		free(text);

#else
	send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
		NULL, "unsupported extended operation", NULL, NULL );

#endif

done:
	if ( reqoid != NULL ) {
		free( reqoid );
	}
	if ( reqdata.bv_val != NULL ) {
		free( reqdata.bv_val );
	}

	return rc;
}

#ifdef SLAPD_EXTERNAL_EXTENSIONS

int
load_extension (
	const void *module,
	const char *file_name
)
{
	extensions_list_t *ext;
	int (*ext_getoid)(int index, char *oid, int blen);
	int rc;

	ext = ch_calloc(1, sizeof(extensions_list_t));
	if (ext == NULL)
		return(-1);

	ext->oid = ch_malloc(MAX_OID_LENGTH);
	if (ext->oid == NULL) {
		free(ext);
		return(-1);
	}

	ext->ext_main = module_resolve(module, "ext_main");
	if (ext->ext_main == NULL) {
		free(ext->oid);
		free(ext);
		return(-1);
	}

	ext_getoid = module_resolve(module, "ext_getoid");
	if (ext_getoid == NULL) {
		free(ext->oid);
		free(ext);
		return(-1);
	}
	rc = (ext_getoid)(0, ext->oid, MAX_OID_LENGTH);
	if (rc != 0) {
		free(ext->oid);
		free(ext);
		return(rc);
	}
	if (*ext->oid == 0) {
		free(ext->oid);
		free(ext);
		return(-1);
	}

	/* supportedExtensions must be maintained for the root DSE.
	 * Unfortunately, this global var is declared extern char *[],
	 * which means it cannot grow dynamically.  So, for now it is
	 * a char *[n], and only (n-1) oids are tracked.  In the off
	 * chance that this is too few, the extensions will still be
	 * loaded, but not reported in root DSE info.  To increase
	 * the maximum, change MAX_SUPP_EXT_TRACKED and recompile or
	 * fix root_dse.c to use something other than a static array.
	 */
	if (supp_ext_count < (MAX_SUPP_EXT_TRACKED - 1)) {
		supportedExtensions[supp_ext_count++] = ch_strdup(ext->oid);
		supportedExtensions[supp_ext_count] = NULL;
	}

	ext->next = supp_ext_list;
	supp_ext_list = ext;
	return(0);
}

extensions_list_t *
find_extension (extensions_list_t *list, char *oid)
{
	extensions_list_t *ext;

	for (ext = list; ext; ext = ext->next) {
		if (strcmp(ext->oid, oid) == 0)
			return(ext);
	}
	return(NULL);
}

int
extensions_callback (extensions_cookie_t *cookie, int msg, int arg, void *argp)
{
	if (cookie == NULL)
		return(-1);

	if (argp == NULL)
		return(-1);

	switch (msg) {
	case 0:		/* SLAPD_EXT_GETVERSION */
		*(int *)argp = 1;
		return(0);

	case 1:		/* SLAPD_EXT_GETPROTO */
		*(int *)argp = cookie->op->o_protocol;
		return(0);
	
	case 2:		/* SLAPD_EXT_GETAUTH */
		*(int *)argp = cookie->op->o_authtype;
		return(0);
	
	case 3:		/* SLAPD_EXT_GETDN */
		*(char **)argp = cookie->op->o_dn;
		return(0);
	
	case 4:		/* SLAPD_EXT_GETCLIENT */
		if (cookie->conn->c_peer_domain != NULL && *cookie->conn->c_peer_domain != 0) {
			*(char **)argp = cookie->conn->c_peer_domain;
			return(0);
		}
		if (cookie->conn->c_peer_name != NULL && *cookie->conn->c_peer_name != 0) {
			*(char **)argp = cookie->conn->c_peer_name;
			return(0);
		}
		break;
	
	default:
		break;
	}
	return(-1);
}

#endif

