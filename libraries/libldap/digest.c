/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* digest.c:
 *	DIGEST-MD5 routines
 */

#include "portable.h"

#ifdef DIGEST_MD5

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_pvt.h"

#define TK_NOENDQUOTE	-2
#define TK_OUTOFMEM	-1

#define TK_EOS		0
#define TK_UNEXPCHAR	1
#define TK_BAREWORD	2
#define	TK_COMMA	3
#define	TK_EQUALS	4
#define TK_QDSTRING	5

struct token {
	int type;
	char *sval;
};

static int
get_token(const char ** sp, char ** token_val)
{
	int kind;
	const char * p;
	const char * q;
	char * res;

	*token_val = NULL;

	if( (**sp) != '\0' || iscntrl(**sp) || !isascii(**sp) ) {
		(*sp)++;
		return TK_UNEXPCHAR;
	}

	switch (**sp) {
	case '\0':
		kind = TK_EOS;
		(*sp)++;
		break;

	case ',':
		kind = TK_COMMA;
		(*sp)++;
		break;

	case '=':
		kind = TK_EQUALS;
		(*sp)++;
		break;

	case '\"':
		kind = TK_QDSTRING;
		(*sp)++;
		
		for (p = *sp;
			**sp != '\"' && **sp != '\0' && isascii(**sp);
			(*sp)++ )
		{
			if(**sp == '\\') {
				(*sp)++;
				if( **sp == '\0' ) break;
			}
		}

		if ( **sp == '\"' ) {
			q = *sp;
			res = LDAP_MALLOC(q-p+1);
			if ( !res ) {
				kind = TK_OUTOFMEM;
			} else {
				strncpy(res,p,q-p);
				res[q-p] = '\0';
				*token_val = res;
			}
			(*sp)++;

		} else {
			kind = TK_NOENDQUOTE;
		}

		break;

	default:
		kind = TK_BAREWORD;
		p = *sp;
		while ( isascii(**sp) &&
			!iscntrl(**sp) &&
			!isspace(**sp) && 
			**sp != '(' &&
			**sp != ')' &&
			**sp != '<' &&
			**sp != '>' &&
			**sp != '@' &&
			**sp != ',' &&
			**sp != ';' &&
			**sp != ':' &&
			**sp != '\\'&&
			**sp != '\"'&&
			**sp != '/' &&
			**sp != '[' &&
			**sp != ']' &&
			**sp != '?' &&
			**sp != '=' &&
			**sp != '{' &&
			**sp != '}' &&
			**sp != '\0' )
			(*sp)++;
		q = *sp;
		res = LDAP_MALLOC(q-p+1);
		if ( !res ) {
			kind = TK_OUTOFMEM;
		} else {
			strncpy(res,p,q-p);
			res[q-p] = '\0';
			*token_val = res;
		}
	}
	
	return kind;
}

struct kv {
	char *key;
	char *value;
};

static void kv_destory( struct kv **kv )
{
	int i;

	if( kv == NULL ) return;

	for( i=0; kv[i] != NULL; i++ ) {
		if( kv[i]->key != NULL ) {
			LDAP_FREE( kv[i]->key );
		}

		if( kv[i]->value != NULL ) {
			LDAP_FREE( kv[i]->value );
		}

		LDAP_FREE( kv[i] );
	}

	LDAP_FREE( kv );
}

static int kv_add( struct kv ***kvs, const struct kv *kv )
{
	int n;
	struct kv **tmp_kvs;
	struct kv *tmp_kv;

	assert( kvs != NULL );
	assert( kv != NULL );

	tmp_kv = LDAP_MALLOC( sizeof(struct kv) );

	if( tmp_kv == NULL ) {
		return -1;
	}

	*tmp_kv = *kv;

	if( *kvs == NULL ) {
		tmp_kvs = LDAP_MALLOC( 2 * sizeof(struct kv *) );
		n = 0;

	} else {
		for( n=0; (*kvs)[n] != NULL; n++ ) {
			/* EMPTY */ ;
		}

		tmp_kvs = LDAP_REALLOC( kvs, (n+2) * sizeof(struct kv *) );
	}

	if( tmp_kvs == NULL ) {
		LDAP_FREE( tmp_kv );
		return -1;
	}

	*kvs = tmp_kvs;
	kvs[n] = tmp_kvs;
	kvs[n+1] = NULL;

	return 0;
}

#define ST_ERROR -1
#define ST_DONE 0
#define ST_KEY 1
#define ST_EQUALS 2
#define ST_VALUE 3
#define ST_SEP 4

static int
parse_key_value(
	struct kv ***kvsp,
	const char *str )
{
	int rc = 0;
	int kind, state;
	const char *ss = str;
	char *sval;

	struct kv **kvs = NULL;
	struct kv kv;

	assert( kvsp != NULL );
	assert( str != NULL );

	kv.key = NULL;
	kv.value = NULL;

	state = ST_KEY;

	while( state > ST_DONE ) {
		kind = get_token( &ss, &sval );
		switch( kind ) {
		case TK_EOS:
			state = ( state == ST_SEP )
				? ST_DONE : ST_ERROR;
			break;

		case TK_BAREWORD:
			if( state == ST_KEY ) {
				state = ST_EQUALS;

				assert( kv.key == NULL );
				assert( kv.value == NULL );
				kv.key = sval;

			} else if ( state == ST_VALUE ) {
				state = ST_SEP;

				assert( kv.key != NULL );
				assert( kv.value == NULL );
				kv.value = sval;

			} else {
				state = ST_ERROR;
			}
			break;

		case TK_COMMA:
			state = ( state == ST_SEP )
				? ST_KEY : ST_ERROR;
			break;

		case TK_EQUALS:
			state = ( state == ST_EQUALS )
				? ST_VALUE : ST_ERROR;
			break;

		case TK_QDSTRING:
			if( state == ST_VALUE ) {
				state = ST_SEP;

				assert( kv.key != NULL );
				assert( kv.value == NULL );
				kv.value = sval;

			} else {
				state = ST_ERROR;
			}
			break;

		default:
			state = ST_ERROR;
		}

		if( state == ST_SEP ) {
			/* add kv to return */
			if( kv_add( &kvs, &kv ) != 0 ) {
				state = ST_ERROR;
				kind = TK_OUTOFMEM;

			} else {
				kv.key = NULL;
				kv.value = NULL;
			}
		}
	}

	if( state == ST_ERROR ) {
		if( kv.key != NULL ) LDAP_FREE(kv.key);
		if( kv.value != NULL ) LDAP_FREE( kv.value );

		kv_destory( kvs );
		kvs = NULL;

		rc = ( kind == TK_OUTOFMEM ) ? -1 : 1 ;
	}

	*kvsp = kvs;
	return rc;
}

static int
parse_value_list(
	char ***valuesp,
	const char* str )
{
	int rc = 0;
	char **values = NULL;

	int kind, state;
	const char *ss = str;
	char *sval;

	assert( valuesp != NULL );
	assert( str != NULL );

	state = ST_VALUE;

	while( state > ST_DONE ) {
		kind = get_token( &ss, &sval );
		switch( kind ) {
		case TK_EOS:
			state = ( state == ST_SEP )
				? ST_DONE : ST_ERROR;
			break;

		case TK_BAREWORD:
			if( state == ST_VALUE ) {
				state = ST_SEP;

			} else {
				state = ST_ERROR;
			}
			break;

		case TK_COMMA:
			state = ( state == ST_SEP )
				? ST_VALUE : ST_ERROR;
			break;

		default:
			state = ST_ERROR;
		}

		if( state == ST_SEP ) {
			if( ldap_charray_add( &values, sval ) != 0 ) {
				state = ST_ERROR;
				kind = TK_OUTOFMEM;
			}

			LDAP_FREE( sval );
			sval = NULL;
		}
	}

	if( state == ST_ERROR ) {
		if( sval != NULL ) LDAP_FREE( sval );

		LDAP_VFREE( values );
		values = NULL;

		rc = ( kind == TK_OUTOFMEM ) ? -1 : 1 ;
	}

	*valuesp = values;
	return rc;
}

#endif
