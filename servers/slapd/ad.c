/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ad.c - routines for dealing with attribute descriptions */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_pvt.h"
#include "slap.h"

#ifdef SLAPD_SCHEMA_NOT_COMPAT
void
ad_free( AttributeDescription *ad, int freeit )
{
	if( ad == NULL ) return;

	ber_bvfree( ad->ad_cname );
	free( ad->ad_lang );

	if( freeit ) free( ad );
}

static int ad_keystring(
	struct berval *bv )
{
	ber_len_t i;

	if( !AD_CHAR( bv->bv_val[0] ) ) {
		return 1;
	}

	for( i=1; i<bv->bv_len; i++ ) {
		if( !AD_CHAR( bv->bv_val[i] ) ) {
			return 1;
		}
	}
	return 0;
}

int slap_str2ad(
	const char *str,
	AttributeDescription **ad,
	char **text )
{
	struct berval bv;
	bv.bv_val = (char *) str;
	bv.bv_len = strlen( str );

	return slap_bv2ad( &bv, ad, text );
}

int slap_bv2ad(
	struct berval *bv,
	AttributeDescription **ad,
	char **text )
{
	int rtn = LDAP_UNDEFINED_TYPE;
	int i;
	AttributeDescription desc;
	char **tokens;

	assert( *ad != NULL );
	assert( *text != NULL );

	if( bv == NULL || bv->bv_len == 0 ) {
		*text = "empty attribute description";
		return LDAP_UNDEFINED_TYPE;
	}

	/* make sure description is IA5 */
	if( ad_keystring( bv ) ) {
		*text = "attribute description contains inappropriate characters";
		return LDAP_UNDEFINED_TYPE;
	}

	tokens = str2charray( bv->bv_val, ";");

	if( tokens == NULL || *tokens == NULL ) {
		*text = "no attribute type";
		goto done;
	}

	desc.ad_type = at_find( *tokens );

	if( desc.ad_type == NULL ) {
		*text = "attribute type undefined";
		goto done;
	}

	desc.ad_flags = SLAP_DESC_NONE;
	desc.ad_lang = NULL;

	for( i=1; tokens[i] != NULL; i++ ) {
		if( strcasecmp( tokens[i], "binary" ) == 0 ) {
			if( desc.ad_flags & SLAP_DESC_BINARY ) {
				*text = "option \"binary\" specified multiple times";
				goto done;
			}

			if(!( desc.ad_type->sat_syntax->ssyn_flags
				& SLAP_SYNTAX_BINARY ))
			{
				/* not stored in binary, disallow option */
				*text = "option \"binary\" with type not supported";
				goto done;
			}

			desc.ad_flags |= SLAP_DESC_BINARY;

		} else if ( strncasecmp( tokens[i], "lang-",
			sizeof("lang-")-1 ) == 0 && tokens[i][sizeof("lang-")-1] )
		{
			if( desc.ad_lang != NULL ) {
				*text = "multiple language tag options specified";
				goto done;
			}
			desc.ad_lang = tokens[i];

			/* normalize to all lower case, it's easy */
			ldap_pvt_str2lower( desc.ad_lang );

		} else {
			*text = "unrecognized option";
			goto done;
		}
	}

	desc.ad_cname = ch_malloc( sizeof( struct berval ) );

	desc.ad_cname->bv_len = strlen( desc.ad_type->sat_cname );
	if( desc.ad_flags & SLAP_DESC_BINARY ) {
		desc.ad_cname->bv_len += sizeof("binary");
	}
	if( desc.ad_lang != NULL ) {
		desc.ad_cname->bv_len += strlen( desc.ad_lang );
	}

	desc.ad_cname = ch_malloc( desc.ad_cname->bv_len + 1 );

	strcpy( desc.ad_cname->bv_val, desc.ad_type->sat_cname );
	strcat( desc.ad_cname->bv_val, ";binary" );
	if( desc.ad_flags & SLAP_DESC_BINARY ) {
		strcat( desc.ad_cname->bv_val, ";binary" );
	}

	if( desc.ad_lang != NULL ) {
		strcat( desc.ad_cname->bv_val, ";" );
		strcat( desc.ad_cname->bv_val, desc.ad_lang );
	}

	if( *ad == NULL ) {
		*ad = ch_malloc( sizeof( AttributeDescription ) );
	}

	**ad = desc;

	rtn = LDAP_SUCCESS;

done:
	charray_free( tokens );
	return rtn;
}

int ad_inlist(
	AttributeDescription *desc,
	char **attrs )
{
	int i;
	for( i=0; attrs[i] != NULL; i++ ) {
		AttributeDescription *ad = NULL;
		char *text;
		int rc = slap_str2ad( attrs[i], &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			goto cont;
		}

		if( !is_at_subtype( desc->ad_type, ad->ad_type ) ) {
			goto cont;
		}

		if( ad->ad_flags && ( ad->ad_flags == desc->ad_flags )) {
			goto cont;
		}

		if( ad->ad_lang != NULL && ( desc->ad_lang == NULL
			|| strcasecmp( ad->ad_lang, desc->ad_lang )))
		{
			goto cont;
		}

		ad_free( ad, 1 );
		return 1;

cont:
		ad_free( ad, 1 );
	}

	return 0;
}

#endif

