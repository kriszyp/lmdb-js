/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2004 The OpenLDAP Foundation.
 * Portions Copyright 1997,2002-2003 IBM Corporation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by IBM Corporation for use in
 * IBM products and subsequently ported to OpenLDAP Software by
 * Steve Omrani.  Additional significant contributors include:
 *   Luke Howard
 */

#include "portable.h"

#include <ac/string.h>
#include <ac/stdarg.h>
#include <ac/ctype.h>
#include <ac/unistd.h>
#include <ldap_pvt.h>

#include <slap.h>
#include <slapi.h>

#include <netdb.h>

/*
 * server start time (should we use a struct timeval also in slapd?
 */
static struct			timeval base_time;
ldap_pvt_thread_mutex_t		slapi_hn_mutex;
ldap_pvt_thread_mutex_t		slapi_time_mutex;

struct slapi_mutex {
	ldap_pvt_thread_mutex_t mutex;
};

struct slapi_condvar {
	ldap_pvt_thread_cond_t cond;
	ldap_pvt_thread_mutex_t mutex;
};

/*
 * This function converts an array of pointers to berval objects to
 * an array of berval objects.
 */

int
bvptr2obj(
	struct berval	**bvptr, 
	BerVarray	*bvobj )
{
	int		rc = LDAP_SUCCESS;
	int		i;
	BerVarray	tmpberval;

	if ( bvptr == NULL || *bvptr == NULL ) {
		return LDAP_OTHER;
	}

	for ( i = 0; bvptr != NULL && bvptr[i] != NULL; i++ ) {
		; /* EMPTY */
	}

	tmpberval = (BerVarray)slapi_ch_malloc( (i + 1)*sizeof(struct berval));
	if ( tmpberval == NULL ) {
		return LDAP_NO_MEMORY;
	} 

	for ( i = 0; bvptr[i] != NULL; i++ ) {
		tmpberval[i].bv_val = bvptr[i]->bv_val;
		tmpberval[i].bv_len = bvptr[i]->bv_len;
	}
	tmpberval[i].bv_val = NULL;
	tmpberval[i].bv_len = 0;

	if ( rc == LDAP_SUCCESS ) {
		*bvobj = tmpberval;
	}

	return rc;
}

Slapi_Entry *
slapi_str2entry(
	char		*s, 
	int		check_dup )
{
#ifdef LDAP_SLAPI
	Slapi_Entry	*e = NULL;
	char		*pTmpS;

	pTmpS = slapi_ch_strdup( s );
	if ( pTmpS != NULL ) {
		e = str2entry( pTmpS ); 
		slapi_ch_free( (void **)&pTmpS );
	}

	return e;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_entry2str(
	Slapi_Entry	*e, 
	int		*len ) 
{
#ifdef LDAP_SLAPI
	char		*ret;

	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	ret = entry2str( e, len );
	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );

	return ret;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_entry_get_dn( Slapi_Entry *e ) 
{
#ifdef LDAP_SLAPI
	return e->e_name.bv_val;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

int
slapi_x_entry_get_id( Slapi_Entry *e )
{
#ifdef LDAP_SLAPI
	return e->e_id;
#else
	return NOID;
#endif /* LDAP_SLAPI */
}

void 
slapi_entry_set_dn(
	Slapi_Entry	*e, 
	char		*ldn )
{
#ifdef LDAP_SLAPI
	struct berval	dn = { 0, NULL };

	dn.bv_val = ldn;
	dn.bv_len = strlen( ldn );

	dnPrettyNormal( NULL, &dn, &e->e_name, &e->e_nname, NULL );
#endif /* LDAP_SLAPI */
}

Slapi_Entry *
slapi_entry_dup( Slapi_Entry *e ) 
{
#ifdef LDAP_SLAPI
	return entry_dup( e );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

int 
slapi_entry_attr_delete(
	Slapi_Entry	*e, 		
	char		*type ) 
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	const char		*text;

	if ( slap_str2ad( type, &ad, &text ) != LDAP_SUCCESS ) {
		return 1;	/* LDAP_NO_SUCH_ATTRIBUTE */
	}

	if ( attr_delete( &e->e_attrs, ad ) == LDAP_SUCCESS ) {
		return 0;	/* attribute is deleted */
	} else {
		return -1;	/* something went wrong */
	}
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_Entry *
slapi_entry_alloc( void ) 
{
#ifdef LDAP_SLAPI
	return (Slapi_Entry *)slapi_ch_calloc( 1, sizeof(Slapi_Entry) );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_entry_free( Slapi_Entry *e ) 
{
#ifdef LDAP_SLAPI
	entry_free( e );
#endif /* LDAP_SLAPI */
}

int 
slapi_entry_attr_merge(
	Slapi_Entry	*e, 
	char		*type, 
	struct berval	**vals ) 
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	const char		*text;
	BerVarray		bv;
	int			rc;

	rc = bvptr2obj( vals, &bv );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}
	
	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}
	
	rc = attr_merge_normalize_one( e, ad, bv, NULL );
	ch_free( bv );

	return rc;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_attr_find(
	Slapi_Entry	*e, 
	char		*type, 
	Slapi_Attr	**attr ) 
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	const char		*text;
	int			rc;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}

	*attr = attr_find( e->e_attrs, ad );
	if ( *attr == NULL ) {
		return -1;
	}

	return 0;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

char *
slapi_entry_attr_get_charptr( const Slapi_Entry *e, const char *type )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return NULL;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return NULL;
	}

	if ( attr->a_vals != NULL && attr->a_vals[0].bv_len != 0 ) {
		return slapi_ch_strdup( attr->a_vals[0].bv_val );
	}

	return NULL;
#else
	return -1;
#endif
}

int
slapi_entry_attr_get_int( const Slapi_Entry *e, const char *type )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return 0;
	}

	return slapi_value_get_int( attr->a_vals );
#else
	return 0;
#endif
}

int
slapi_entry_attr_get_long( const Slapi_Entry *e, const char *type )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return 0;
	}

	return slapi_value_get_long( attr->a_vals );
#else
	return 0;
#endif
}

int
slapi_entry_attr_get_uint( const Slapi_Entry *e, const char *type )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return 0;
	}

	return slapi_value_get_uint( attr->a_vals );
#else
	return 0;
#endif
}

int
slapi_entry_attr_get_ulong( const Slapi_Entry *e, const char *type )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return 0;
	}

	return slapi_value_get_ulong( attr->a_vals );
#else
	return 0;
#endif
}

int
slapi_entry_attr_hasvalue( Slapi_Entry *e, const char *type, const char *value )
{
#ifdef LDAP_SLAPI
	struct berval bv;
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	Attribute *attr;
	
	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr = attr_find( e->e_attrs, ad );
	if ( attr == NULL ) {
		return 0;
	}

	bv.bv_val = (char *)value;
	bv.bv_len = strlen( value );

	return ( slapi_attr_value_find( attr, &bv ) != -1 );
#else
	return 0;
#endif
}

void
slapi_entry_attr_set_charptr(Slapi_Entry* e, const char *type, const char *value)
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	const char		*text;
	int			rc;
	struct berval		bv;
	
	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return;
	}
	
	attr_delete ( &e->e_attrs, ad );
	if ( value != NULL ) {
		bv.bv_val = (char *)value;
		bv.bv_len = strlen(value);
		attr_merge_normalize_one( e, ad, &bv, NULL );
	}
#endif /* LDAP_SLAPI */
}

void
slapi_entry_attr_set_int( Slapi_Entry* e, const char *type, int l)
{
#ifdef LDAP_SLAPI
	char buf[64];

	snprintf( buf, sizeof( buf ), "%d", l );
	slapi_entry_attr_set_charptr( e, type, buf );
#endif /* LDAP_SLAPI */
}

void
slapi_entry_attr_set_uint( Slapi_Entry* e, const char *type, unsigned int l)
{
#ifdef LDAP_SLAPI
	char buf[64];

	snprintf( buf, sizeof( buf ), "%u", l );
	slapi_entry_attr_set_charptr( e, type, buf );
#endif /* LDAP_SLAPI */
}

void
slapi_entry_attr_set_long(Slapi_Entry* e, const char *type, long l)
{
#ifdef LDAP_SLAPI
	char buf[64];

	snprintf( buf, sizeof( buf ), "%ld", l );
	slapi_entry_attr_set_charptr( e, type, buf );
#endif /* LDAP_SLAPI */
}

void
slapi_entry_attr_set_ulong(Slapi_Entry* e, const char *type, unsigned long l)
{
#ifdef LDAP_SLAPI
	char buf[64];

	snprintf( buf, sizeof( buf ), "%lu", l );
	slapi_entry_attr_set_charptr( e, type, buf );
#endif /* LDAP_SLAPI */
}

int
slapi_is_rootdse( const char *dn )
{
#ifdef LDAP_SLAPI
	return ( dn == NULL || dn[0] == '\0' );
#else
	return 0;
#endif
}

/*
 * Add values to entry.
 *
 * Returns:
 *	LDAP_SUCCESS			Values added to entry
 *	LDAP_TYPE_OR_VALUE_EXISTS	One or more values exist in entry already
 *	LDAP_CONSTRAINT_VIOLATION	Any other error (odd, but it's the spec)
 */
int
slapi_entry_add_values( Slapi_Entry *e, const char *type, struct berval **vals )
{
#ifdef LDAP_SLAPI
	Modification		mod;
	const char		*text;
	int			rc;
	char			textbuf[SLAP_TEXT_BUFLEN];

	mod.sm_op = LDAP_MOD_ADD;
	mod.sm_desc = NULL;
	mod.sm_type.bv_val = (char *)type;
	mod.sm_type.bv_len = strlen( type );

	rc = slap_str2ad( type, &mod.sm_desc, &text );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( vals == NULL ) {
		/* Apparently vals can be NULL
		 * FIXME: sm_bvalues = NULL ? */
		mod.sm_bvalues = (BerVarray)ch_malloc( sizeof(struct berval) );
		mod.sm_bvalues->bv_val = NULL;

	} else {
		rc = bvptr2obj( vals, &mod.sm_bvalues );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_CONSTRAINT_VIOLATION;
		}
	}
	mod.sm_nvalues = NULL;

	rc = modify_add_values( e, &mod, 0, &text, textbuf, sizeof(textbuf) );

	ch_free( mod.sm_bvalues );

	return (rc == LDAP_SUCCESS) ? LDAP_SUCCESS : LDAP_CONSTRAINT_VIOLATION;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_add_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals )
{
#ifdef LDAP_SLAPI
	return slapi_entry_add_values( e, type, vals );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_add_valueset(Slapi_Entry *e, const char *type, Slapi_ValueSet *vs)
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	const char		*text;
	int			rc;
	
	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}

	return attr_merge_normalize( e, ad, *vs, NULL );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_delete_values( Slapi_Entry *e, const char *type, struct berval **vals )
{
#ifdef LDAP_SLAPI
	Modification		mod;
	const char		*text;
	int			rc;
	char			textbuf[SLAP_TEXT_BUFLEN];

	mod.sm_op = LDAP_MOD_DELETE;
	mod.sm_desc = NULL;
	mod.sm_type.bv_val = (char *)type;
	mod.sm_type.bv_len = strlen( type );

	if ( vals == NULL ) {
		/* If vals is NULL, this is a NOOP. */
		return LDAP_SUCCESS;
	}
	
	rc = slap_str2ad( type, &mod.sm_desc, &text );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( vals[0] == NULL ) {
		/* SLAPI doco says LDAP_OPERATIONS_ERROR but LDAP_OTHER is better */
		return attr_delete( &e->e_attrs, mod.sm_desc ) ? LDAP_OTHER : LDAP_SUCCESS;
	}

	rc = bvptr2obj( vals, &mod.sm_bvalues );
	if ( rc != LDAP_SUCCESS ) {
		return LDAP_CONSTRAINT_VIOLATION;
	}
	mod.sm_nvalues = NULL;

	rc = modify_delete_values( e, &mod, 0, &text, textbuf, sizeof(textbuf) );

	ch_free( mod.sm_bvalues );

	return rc;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_delete_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals )
{
#ifdef LDAP_SLAPI
	return slapi_entry_delete_values( e, type, vals );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_merge_values_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals )
{
#ifdef LDAP_SLAPI
	return slapi_entry_attr_merge( e, (char *)type, vals );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_add_value(Slapi_Entry *e, const char *type, const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	AttributeDescription	*ad = NULL;
	int 			rc;
	const char		*text;

	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}

	rc = attr_merge_normalize_one( e, ad, (Slapi_Value *)value, NULL );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_add_string(Slapi_Entry *e, const char *type, const char *value)
{
#ifdef LDAP_SLAPI
	Slapi_Value val;

	val.bv_val = (char *)value;
	val.bv_len = strlen( value );

	return slapi_entry_add_value( e, type, &val );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_entry_delete_string(Slapi_Entry *e, const char *type, const char *value)
{
#ifdef LDAP_SLAPI
	Slapi_Value *vals[2];
	Slapi_Value val;

	val.bv_val = (char *)value;
	val.bv_len = strlen( value );
	vals[0] = &val;
	vals[1] = NULL;

	return slapi_entry_delete_values_sv( e, type, vals );	
#else
	return -1;
#endif /* LDAP_SLAPI */
}


int
slapi_entry_attr_merge_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals )
{
#ifdef LDAP_SLAPI
	return slapi_entry_attr_merge( e, (char *)type, vals );
#else
	return -1;
#endif
}

int
slapi_entry_first_attr( const Slapi_Entry *e, Slapi_Attr **attr )
{
#ifdef LDAP_SLAPI
	if ( e == NULL ) {
		return -1;
	}

	*attr = e->e_attrs;

	return ( *attr != NULL ) ? 0 : -1;
#else
	return -1;
#endif
}

int
slapi_entry_next_attr( const Slapi_Entry *e, Slapi_Attr *prevattr, Slapi_Attr **attr )
{
#ifdef LDAP_SLAPI
	if ( e == NULL ) {
		return -1;
	}

	if ( prevattr == NULL ) {
		return -1;
	}

	*attr = prevattr->a_next;

	return ( *attr != NULL ) ? 0 : -1;
#else
	return -1;
#endif
}

int
slapi_entry_attr_replace_sv( Slapi_Entry *e, const char *type, Slapi_Value **vals )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	BerVarray bv;
	
	rc = slap_str2ad( type, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	attr_delete( &e->e_attrs, ad );

	rc = bvptr2obj( vals, &bv );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}
	
	rc = attr_merge_normalize( e, ad, bv, NULL );
	slapi_ch_free( (void **)&bv );
	if ( rc != LDAP_SUCCESS ) {
		return -1;
	}
	
	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/* 
 * FIXME -- The caller must free the allocated memory. 
 * In Netscape they do not have to.
 */
int 
slapi_attr_get_values(
	Slapi_Attr	*attr, 
	struct berval	***vals ) 
{
#ifdef LDAP_SLAPI
	int		i, j;
	struct berval	**bv;

	if ( attr == NULL ) {
		return 1;
	}

	for ( i = 0; attr->a_vals[i].bv_val != NULL; i++ ) {
		; /* EMPTY */
	}

	bv = (struct berval **)ch_malloc( (i + 1) * sizeof(struct berval *) );
	for ( j = 0; j < i; j++ ) {
		bv[j] = ber_dupbv( NULL, &attr->a_vals[j] );
	}
	bv[j] = NULL;
	
	*vals = (struct berval **)bv;

	return 0;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

char *
slapi_dn_normalize( char *dn ) 
{
#ifdef LDAP_SLAPI
	struct berval	bdn;
	struct berval	pdn;

	assert( dn != NULL );
	
	bdn.bv_val = dn;
	bdn.bv_len = strlen( dn );

	if ( dnPretty( NULL, &bdn, &pdn, NULL ) != LDAP_SUCCESS ) {
		return NULL;
	}

	return pdn.bv_val;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_dn_normalize_case( char *dn ) 
{
#ifdef LDAP_SLAPI
	struct berval	bdn;
	struct berval	ndn;

	assert( dn != NULL );
	
	bdn.bv_val = dn;
	bdn.bv_len = strlen( dn );

	if ( dnNormalize( 0, NULL, NULL, &bdn, &ndn, NULL ) != LDAP_SUCCESS ) {
		return NULL;
	}

	return ndn.bv_val;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

int 
slapi_dn_issuffix(
	char		*dn, 
	char		*suffix )
{
#ifdef LDAP_SLAPI
	struct berval	bdn, ndn;
	struct berval	bsuffix, nsuffix;
	int rc;

	assert( dn != NULL );
	assert( suffix != NULL );

	bdn.bv_val = dn;
	bdn.bv_len = strlen( dn );

	bsuffix.bv_val = suffix;
	bsuffix.bv_len = strlen( suffix );

	if ( dnNormalize( 0, NULL, NULL, &bdn, &ndn, NULL ) != LDAP_SUCCESS ) {
		return 0;
	}

	if ( dnNormalize( 0, NULL, NULL, &bsuffix, &nsuffix, NULL )
		!= LDAP_SUCCESS )
	{
		slapi_ch_free( (void **)&ndn.bv_val );
		return 0;
	}

	rc = dnIsSuffix( &ndn, &nsuffix );

	slapi_ch_free( (void **)&ndn.bv_val );
	slapi_ch_free( (void **)&nsuffix.bv_val );

	return rc;
#else /* LDAP_SLAPI */
	return 0;
#endif /* LDAP_SLAPI */
}

int
slapi_dn_isparent(
	const char	*parentdn,
	const char	*childdn )
{
#ifdef LDAP_SLAPI
	struct berval	assertedParentDN, normalizedAssertedParentDN;
	struct berval	childDN, normalizedChildDN;
	struct berval	normalizedParentDN;
	int		match;

	assert( parentdn != NULL );
	assert( childdn != NULL );

	assertedParentDN.bv_val = (char *)parentdn;
	assertedParentDN.bv_len = strlen( parentdn );

	if ( dnNormalize( 0, NULL, NULL, &assertedParentDN,
		&normalizedAssertedParentDN, NULL ) != LDAP_SUCCESS )
	{
		return 0;
	}

	childDN.bv_val = (char *)childdn;
	childDN.bv_len = strlen( childdn );

	if ( dnNormalize( 0, NULL, NULL, &childDN,
		&normalizedChildDN, NULL ) != LDAP_SUCCESS )
	{
		slapi_ch_free( (void **)&normalizedAssertedParentDN.bv_val );
		return 0;
	}

	dnParent( &normalizedChildDN, &normalizedParentDN );

	if ( dnMatch( &match, 0, slap_schema.si_syn_distinguishedName, NULL,
		&normalizedParentDN, (void *)&normalizedAssertedParentDN ) != LDAP_SUCCESS )
	{
		match = -1;
	}

	slapi_ch_free( (void **)&normalizedAssertedParentDN.bv_val );
	slapi_ch_free( (void **)&normalizedChildDN.bv_val );

	return ( match == 0 );
#else
	return 0;
#endif /* LDAP_SLAPI */
}

/*
 * Returns DN of the parent entry, or NULL if the DN is
 * an empty string or NULL, or has no parent.
 */
char *
slapi_dn_parent( const char *_dn )
{
#ifdef LDAP_SLAPI
	struct berval	dn, prettyDN;
	struct berval	parentDN;

	if ( _dn == NULL ) {
		return NULL;
	}

	dn.bv_val = (char *)_dn;
	dn.bv_len = strlen( _dn );

	if ( dn.bv_len == 0 ) {
		return NULL;
	}

	if ( dnPretty( NULL, &dn, &prettyDN, NULL ) != LDAP_SUCCESS ) {
		return NULL;
	}

	dnParent( &prettyDN, &parentDN ); /* in-place */

	slapi_ch_free( (void **)&prettyDN.bv_val );

	if ( parentDN.bv_len == 0 ) {
		return NULL;
	}

	return slapi_ch_strdup( parentDN.bv_val );
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

/*
 * Returns DN of the parent entry; or NULL if the DN is
 * an empty string, if the DN has no parent, or if the
 * DN is the suffix of the backend database
 */
char *slapi_dn_beparent( Slapi_PBlock *pb, const char *_dn )
{
#ifdef LDAP_SLAPI
	Backend 	*be;
	struct berval	dn, prettyDN;
	struct berval	normalizedDN, parentDN;

	if ( slapi_pblock_get( pb, SLAPI_BACKEND, (void **)&be ) != 0 )
		be = NULL;

	dn.bv_val = (char *)_dn;
	dn.bv_len = strlen( _dn );

	if ( dnPrettyNormal( NULL, &dn, &prettyDN, &normalizedDN, NULL ) != LDAP_SUCCESS ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, &normalizedDN ) ) {
		slapi_ch_free( (void **)&prettyDN.bv_val );
		slapi_ch_free( (void **)&normalizedDN.bv_val );
		return NULL;
	}

	dnParent( &prettyDN, &parentDN );

	slapi_ch_free( (void **)&prettyDN.bv_val );
	slapi_ch_free( (void **)&normalizedDN.bv_val );

	if ( parentDN.bv_len == 0 ) {
		return NULL;
	}

	return slapi_ch_strdup( parentDN.bv_val );
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_dn_ignore_case( char *dn )
{       
#ifdef LDAP_SLAPI
	return slapi_dn_normalize_case( dn );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_ch_malloc( unsigned long size ) 
{
#ifdef LDAP_SLAPI
	return ch_malloc( size );	
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_ch_free( void **ptr ) 
{
#ifdef LDAP_SLAPI
	ch_free( *ptr );
	*ptr = NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_ch_free_string( char **ptr ) 
{
#ifdef LDAP_SLAPI
	slapi_ch_free( (void **)ptr );
#endif /* LDAP_SLAPI */
}

void
slapi_ch_array_free( char **arrayp )
{
#ifdef LDAP_SLAPI
	char **p;

	if ( arrayp != NULL ) {
		for ( p = arrayp; *p != NULL; p++ ) {
			slapi_ch_free( (void **)p );
		}
		slapi_ch_free( (void **)&arrayp );
	}
#endif
}

struct berval *
slapi_ch_bvdup(const struct berval *v)
{
#ifdef LDAP_SLAPI
	struct berval *bv;

	bv = (struct berval *) slapi_ch_malloc( sizeof(struct berval) );
	bv->bv_len = v->bv_len;
	bv->bv_val = slapi_ch_malloc( bv->bv_len );
	AC_MEMCPY( bv->bv_val, v->bv_val, bv->bv_len );

	return bv;
#else
	return NULL;
#endif
}

struct berval **
slapi_ch_bvecdup(const struct berval **v)
{
#ifdef LDAP_SLAPI
	int i;
	struct berval **rv;

	if ( v == NULL ) {
		return NULL;
	}

	for ( i = 0; v[i] != NULL; i++ )
		;

	rv = (struct berval **) slapi_ch_malloc( (i + 1) * sizeof(struct berval *) );

	for ( i = 0; v[i] != NULL; i++ ) {
		rv[i] = slapi_ch_bvdup( v[i] );
	}
	rv[i] = NULL;

	return rv;
#else
	return NULL;
#endif
}

char *
slapi_ch_calloc(
	unsigned long nelem, 
	unsigned long size ) 
{
#ifdef LDAP_SLAPI
	return ch_calloc( nelem, size );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_ch_realloc(
	char *block, 
	unsigned long size ) 
{
#ifdef LDAP_SLAPI
	return ch_realloc( block, size );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char *
slapi_ch_strdup( char *s ) 
{
#ifdef LDAP_SLAPI
	return ch_strdup( (const char *)s );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

size_t
slapi_ch_stlen( char *s ) 
{
#ifdef LDAP_SLAPI
	return strlen( (const char *)s );
#else /* LDAP_SLAPI */
	return 0;
#endif /* LDAP_SLAPI */
}

int 
slapi_control_present(
	LDAPControl	**controls, 
	char		*oid, 
	struct berval	**val, 
	int		*iscritical ) 
{
#ifdef LDAP_SLAPI
	int		i;
	int		rc = 0;

	if ( val ) {
		*val = NULL;
	}
	
	if ( iscritical ) {
		*iscritical = 0;
	}
	
	for ( i = 0; controls != NULL && controls[i] != NULL; i++ ) {
		if ( strcmp( controls[i]->ldctl_oid, oid ) != 0 ) {
			continue;
		}

		rc = 1;
		if ( controls[i]->ldctl_value.bv_len != 0 ) {
			/*
			 * FIXME: according to 6.1 specification,
			 *    "The val output parameter is set
			 *    to point into the controls array.
			 *    A copy of the control value is
			 *    not made."
			 */
#if 0
			struct berval	*pTmpBval;

			pTmpBval = (struct berval *)slapi_ch_malloc( sizeof(struct berval));
			if ( pTmpBval == NULL ) {
				rc = 0;
			} else {
				pTmpBval->bv_len = controls[i]->ldctl_value.bv_len;
				pTmpBval->bv_val = controls[i]->ldctl_value.bv_val;
				if ( val ) {
					*val = pTmpBval;
				} else {
					slapi_ch_free( (void **)&pTmpBval );
					rc = 0;
				}
			}
#endif /* 0 */
			if ( val ) {
				*val = &controls[i]->ldctl_value;
			}
		}

		if ( iscritical ) {
			*iscritical = controls[i]->ldctl_iscritical;
		}

		break;
	}

	return rc;
#else /* LDAP_SLAPI */
	return 0;
#endif /* LDAP_SLAPI */
}

#ifdef LDAP_SLAPI
static void
slapControlMask2SlapiControlOp(slap_mask_t slap_mask,
	unsigned long *slapi_mask)
{
	*slapi_mask = SLAPI_OPERATION_NONE;

	if ( slap_mask & SLAP_CTRL_ABANDON ) 
		*slapi_mask |= SLAPI_OPERATION_ABANDON;

	if ( slap_mask & SLAP_CTRL_ADD )
		*slapi_mask |= SLAPI_OPERATION_ADD;

	if ( slap_mask & SLAP_CTRL_BIND )
		*slapi_mask |= SLAPI_OPERATION_BIND;

	if ( slap_mask & SLAP_CTRL_COMPARE )
		*slapi_mask |= SLAPI_OPERATION_COMPARE;

	if ( slap_mask & SLAP_CTRL_DELETE )
		*slapi_mask |= SLAPI_OPERATION_DELETE;

	if ( slap_mask & SLAP_CTRL_MODIFY )
		*slapi_mask |= SLAPI_OPERATION_MODIFY;

	if ( slap_mask & SLAP_CTRL_RENAME )
		*slapi_mask |= SLAPI_OPERATION_MODDN;

	if ( slap_mask & SLAP_CTRL_SEARCH )
		*slapi_mask |= SLAPI_OPERATION_SEARCH;

	if ( slap_mask & SLAP_CTRL_UNBIND )
		*slapi_mask |= SLAPI_OPERATION_UNBIND;
}

static void
slapiControlOp2SlapControlMask(unsigned long slapi_mask,
	slap_mask_t *slap_mask)
{
	*slap_mask = 0;

	if ( slapi_mask & SLAPI_OPERATION_BIND )
		*slap_mask |= SLAP_CTRL_BIND;

	if ( slapi_mask & SLAPI_OPERATION_UNBIND )
		*slap_mask |= SLAP_CTRL_UNBIND;

	if ( slapi_mask & SLAPI_OPERATION_SEARCH )
		*slap_mask |= SLAP_CTRL_SEARCH;

	if ( slapi_mask & SLAPI_OPERATION_MODIFY )
		*slap_mask |= SLAP_CTRL_MODIFY;

	if ( slapi_mask & SLAPI_OPERATION_ADD )
		*slap_mask |= SLAP_CTRL_ADD;

	if ( slapi_mask & SLAPI_OPERATION_DELETE )
		*slap_mask |= SLAP_CTRL_DELETE;

	if ( slapi_mask & SLAPI_OPERATION_MODDN )
		*slap_mask |= SLAP_CTRL_RENAME;

	if ( slapi_mask & SLAPI_OPERATION_COMPARE )
		*slap_mask |= SLAP_CTRL_COMPARE;

	if ( slapi_mask & SLAPI_OPERATION_ABANDON )
		*slap_mask |= SLAP_CTRL_ABANDON;

	*slap_mask |= SLAP_CTRL_FRONTEND;
}

static int
slapi_int_parse_control(
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	/* Plugins must deal with controls themselves. */

	return LDAP_SUCCESS;
}
#endif /* LDAP_SLAPI */

void 
slapi_register_supported_control(
	char		*controloid, 
	unsigned long	controlops )
{
#ifdef LDAP_SLAPI
	slap_mask_t controlmask;

	slapiControlOp2SlapControlMask( controlops, &controlmask );

	register_supported_control( controloid, controlmask, NULL, slapi_int_parse_control );
#endif /* LDAP_SLAPI */
}

int 
slapi_get_supported_controls(
	char		***ctrloidsp, 
	unsigned long	**ctrlopsp ) 
{
#ifdef LDAP_SLAPI
	int i, rc;

	rc = get_supported_controls( ctrloidsp, (slap_mask_t **)ctrlopsp );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	for ( i = 0; (*ctrloidsp)[i] != NULL; i++ ) {
		/* In place, naughty. */
		slapControlMask2SlapiControlOp( (*ctrlopsp)[i], &((*ctrlopsp)[i]) );
	}

	return LDAP_SUCCESS;
#else /* LDAP_SLAPI */
	return 1;
#endif /* LDAP_SLAPI */
}

LDAPControl *
slapi_dup_control( LDAPControl *ctrl )
{
#ifdef LDAP_SLAPI
	LDAPControl *ret;

	ret = (LDAPControl *)slapi_ch_malloc( sizeof(*ret) );
	ret->ldctl_oid = slapi_ch_strdup( ctrl->ldctl_oid );
	ber_dupbv( &ret->ldctl_value, &ctrl->ldctl_value );
	ret->ldctl_iscritical = ctrl->ldctl_iscritical;

	return ret;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_register_supported_saslmechanism( char *mechanism )
{
#ifdef LDAP_SLAPI
	/* FIXME -- can not add saslmechanism to OpenLDAP dynamically */
	slapi_log_error( SLAPI_LOG_FATAL, "slapi_register_supported_saslmechanism",
			"OpenLDAP does not support dynamic registration of SASL mechanisms\n" );
#endif /* LDAP_SLAPI */
}

char **
slapi_get_supported_saslmechanisms( void )
{
#ifdef LDAP_SLAPI
	/* FIXME -- can not get the saslmechanism without a connection. */
	slapi_log_error( SLAPI_LOG_FATAL, "slapi_get_supported_saslmechanisms",
			"can not get the SASL mechanism list "
			"without a connection\n" );
	return NULL;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

char **
slapi_get_supported_extended_ops( void )
{
#ifdef LDAP_SLAPI
	int		i, j, k;
	char		**ppExtOpOID = NULL;
	int		numExtOps = 0;

	for ( i = 0; get_supported_extop( i ) != NULL; i++ ) {
		;
	}
	
	for ( j = 0; slapi_int_get_supported_extop( j ) != NULL; j++ ) {
		;
	}

	numExtOps = i + j;
	if ( numExtOps == 0 ) {
		return NULL;
	}

	ppExtOpOID = (char **)slapi_ch_malloc( (numExtOps + 1) * sizeof(char *) );
	for ( k = 0; k < i; k++ ) {
		struct berval	*bv;

		bv = get_supported_extop( k );
		assert( bv != NULL );

		ppExtOpOID[ k ] = bv->bv_val;
	}
	
	for ( ; k < j; k++ ) {
		struct berval	*bv;

		bv = slapi_int_get_supported_extop( k );
		assert( bv != NULL );

		ppExtOpOID[ i + k ] = bv->bv_val;
	}
	ppExtOpOID[ i + k ] = NULL;

	return ppExtOpOID;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_send_ldap_result(
	Slapi_PBlock	*pb, 
	int		err, 
	char		*matched, 
	char		*text, 
	int		nentries, 
	struct berval	**urls ) 
{
#ifdef LDAP_SLAPI
	Operation	*op;
	struct berval	*s;
	char		*extOID = NULL;
	struct berval	*extValue = NULL;
	int		rc;
	SlapReply	rs = { REP_RESULT };

	slapi_pblock_get( pb, SLAPI_OPERATION, &op );

	rs.sr_err = err;
	rs.sr_matched = matched;
	rs.sr_text = text;
	rs.sr_ref = NULL;
	rs.sr_ctrls = NULL;

	slapi_pblock_get( pb, SLAPI_RESCONTROLS, &rs.sr_ctrls );

	if ( err == LDAP_SASL_BIND_IN_PROGRESS ) {
		slapi_pblock_get( pb, SLAPI_BIND_RET_SASLCREDS, (void *) &rs.sr_sasldata );
		send_ldap_sasl( op, &rs );
		return;
	}

	slapi_pblock_get( pb, SLAPI_EXT_OP_RET_OID, &extOID );
	if ( extOID != NULL ) {
		rs.sr_rspoid = extOID;
		slapi_pblock_get( pb, SLAPI_EXT_OP_RET_VALUE, &rs.sr_rspdata );
		send_ldap_extended( op, &rs );
		return;
	}

	if (op->o_tag == LDAP_REQ_SEARCH)
		rs.sr_nentries = nentries;

	send_ldap_result( op, &rs );
#endif /* LDAP_SLAPI */
}

int 
slapi_send_ldap_search_entry(
	Slapi_PBlock	*pb, 
	Slapi_Entry	*e, 
	LDAPControl	**ectrls, 
	char		**attrs, 
	int		attrsonly )
{
#ifdef LDAP_SLAPI
	Operation	*pOp;
	SlapReply	rs = { REP_RESULT };
	int		i;
	AttributeName	*an = NULL;
	const char	*text;

	if ( attrs != NULL ) {
		for ( i = 0; attrs[ i ] != NULL; i++ ) {
			; /* empty */
		}
	} else {
		i = 0;
	}

	if ( i > 0 ) {
		an = (AttributeName *) ch_malloc( (i+1) * sizeof(AttributeName) );
		for ( i = 0; attrs[i] != NULL; i++ ) {
			an[i].an_name.bv_val = ch_strdup( attrs[i] );
			an[i].an_name.bv_len = strlen( attrs[i] );
			an[i].an_desc = NULL;
			if( slap_bv2ad( &an[i].an_name, &an[i].an_desc, &text ) != LDAP_SUCCESS)
				return -1;
		}
		an[i].an_name.bv_len = 0;
		an[i].an_name.bv_val = NULL;
	}

	rs.sr_err = LDAP_SUCCESS;
	rs.sr_matched = NULL;
	rs.sr_text = NULL;
	rs.sr_ref = NULL;
	rs.sr_ctrls = ectrls;
	rs.sr_attrs = an;
	rs.sr_entry = e;
	rs.sr_v2ref = NULL;

	if ( slapi_pblock_get( pb, SLAPI_OPERATION, (void *)&pOp ) != 0 ) {
		return LDAP_OTHER;
	}

	return send_search_entry( pOp, &rs );
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

int 
slapi_send_ldap_search_reference(
	Slapi_PBlock	*pb,
	Slapi_Entry	*e,
	struct berval	**references,
	LDAPControl	**ectrls, 
	struct berval	**v2refs
	)
{
#ifdef LDAP_SLAPI
	Operation	*pOp;
	SlapReply	rs = { REP_SEARCHREF };
	int		rc;

	rs.sr_err = LDAP_SUCCESS;
	rs.sr_matched = NULL;
	rs.sr_text = NULL;

	rc = bvptr2obj( references, &rs.sr_ref );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rs.sr_ctrls = ectrls;
	rs.sr_attrs = NULL;
	rs.sr_entry = e;

	if ( v2refs != NULL ) {
		rc = bvptr2obj( v2refs, &rs.sr_v2ref );
		if ( rc != LDAP_SUCCESS ) {
			slapi_ch_free( (void **)&rs.sr_ref );
			return rc;
		}
	} else {
		rs.sr_v2ref = NULL;
	}

	if ( slapi_pblock_get( pb, SLAPI_OPERATION, (void *)&pOp ) != 0 ) {
		return LDAP_OTHER;
	}

	rc = send_search_reference( pOp, &rs );

	if ( rs.sr_ref != NULL )
		slapi_ch_free( (void **)&rs.sr_ref );

	if ( rs.sr_v2ref != NULL )
		slapi_ch_free( (void **)&rs.sr_v2ref );

	return rc;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_Filter *
slapi_str2filter( char *str ) 
{
#ifdef LDAP_SLAPI
	return str2filter( str );
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

void 
slapi_filter_free(
	Slapi_Filter	*f, 
	int		recurse ) 
{
#ifdef LDAP_SLAPI
	filter_free( f );
#endif /* LDAP_SLAPI */
}

Slapi_Filter *
slapi_filter_dup( Slapi_Filter *filter )
{
#ifdef LDAP_SLAPI
	Filter *f;

	f = (Filter *) slapi_ch_malloc( sizeof(Filter) );
	f->f_next = NULL;
	f->f_choice = filter->f_choice;

	switch ( f->f_choice ) {
	case LDAP_FILTER_AND:
	case LDAP_FILTER_NOT:
	case LDAP_FILTER_OR: {
		Filter *pFilter, **ppF;

		for ( pFilter = filter->f_list, ppF = &f->f_list;
		      pFilter != NULL;
		      pFilter = pFilter->f_next, ppF = &f->f_next )
		{
			*ppF = slapi_filter_dup( pFilter );
			if ( *ppF == NULL )
				break;
		}
		break;
	}
	case LDAP_FILTER_PRESENT:
		f->f_desc = filter->f_desc;
		break;
	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_APPROX:
		f->f_ava = (AttributeAssertion *)slapi_ch_malloc( sizeof(AttributeAssertion) );
		f->f_ava->aa_desc = filter->f_ava->aa_desc;
		ber_dupbv( &f->f_ava->aa_value, &filter->f_ava->aa_value );
		break;
	case LDAP_FILTER_EXT:
		f->f_mra = (MatchingRuleAssertion *)slapi_ch_malloc( sizeof(MatchingRuleAssertion) );
		f->f_mra->ma_rule = filter->f_mra->ma_rule;
		f->f_mra->ma_rule_text = filter->f_mra->ma_rule_text; /* struct copy */
		f->f_mra->ma_desc = filter->f_mra->ma_desc;
		f->f_mra->ma_dnattrs = filter->f_mra->ma_dnattrs;
		ber_dupbv( &f->f_mra->ma_value, &filter->f_mra->ma_value );
		break;
	case LDAP_FILTER_SUBSTRINGS: {
		int i;

		f->f_sub = (SubstringsAssertion *)slapi_ch_malloc( sizeof(SubstringsAssertion) );
		f->f_sub->sa_desc = filter->f_sub->sa_desc;
		ber_dupbv( &f->f_sub_initial, &filter->f_sub_initial );
		if ( filter->f_sub_any != NULL ) {
			for ( i = 0; filter->f_sub_any[i].bv_val != NULL; i++ )
				;
			f->f_sub_any = (BerVarray)slapi_ch_malloc( (i + 1) * (sizeof(struct berval)) );
			for ( i = 0; filter->f_sub_any[i].bv_val != NULL; i++ ) {
				ber_dupbv( &f->f_sub_any[i], &filter->f_sub_any[i] );
			}
			f->f_sub_any[i].bv_val = NULL;
		} else {
			f->f_sub_any = NULL;
		}
		ber_dupbv( &f->f_sub_final, &filter->f_sub_final );
		break;
	}
	case SLAPD_FILTER_COMPUTED:
		f->f_result = filter->f_result;
		break;
	default:
		slapi_ch_free( (void **)&f );
		f = NULL;
		break;
	}

	return f;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

int 
slapi_filter_get_choice( Slapi_Filter *f )
{
#ifdef LDAP_SLAPI
	int		rc;

	if ( f != NULL ) {
		rc = f->f_choice;
	} else {
		rc = 0;
	}

	return rc;
#else /* LDAP_SLAPI */
	return -1;		/* invalid filter type */
#endif /* LDAP_SLAPI */
}

int 
slapi_filter_get_ava(
	Slapi_Filter	*f, 
	char		**type, 
	struct berval	**bval )
{
#ifdef LDAP_SLAPI
	int		ftype;
	int		rc = LDAP_SUCCESS;

	assert( type != NULL );
	assert( bval != NULL );

	*type = NULL;
	*bval = NULL;

	ftype = f->f_choice;
	if ( ftype == LDAP_FILTER_EQUALITY 
			|| ftype ==  LDAP_FILTER_GE 
			|| ftype == LDAP_FILTER_LE 
			|| ftype == LDAP_FILTER_APPROX ) {
		/*
		 * According to the SLAPI Reference Manual these are
		 * not duplicated.
		 */
		*type = f->f_un.f_un_ava->aa_desc->ad_cname.bv_val;
		*bval = &f->f_un.f_un_ava->aa_value;
	} else { /* filter type not supported */
		rc = -1;
	}

	return rc;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_Filter *
slapi_filter_list_first( Slapi_Filter *f )
{
#ifdef LDAP_SLAPI
	int		ftype;

	if ( f == NULL ) {
		return NULL;
	}

	ftype = f->f_choice;
	if ( ftype == LDAP_FILTER_AND
			|| ftype == LDAP_FILTER_OR
			|| ftype == LDAP_FILTER_NOT ) {
		return (Slapi_Filter *)f->f_list;
	} else {
		return NULL;
	}
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

Slapi_Filter *
slapi_filter_list_next(
	Slapi_Filter	*f, 
	Slapi_Filter	*fprev )
{
#ifdef LDAP_SLAPI
	int		ftype;

	if ( f == NULL ) {
		return NULL;
	}

	ftype = f->f_choice;
	if ( ftype == LDAP_FILTER_AND
			|| ftype == LDAP_FILTER_OR
			|| ftype == LDAP_FILTER_NOT )
	{
		return fprev->f_next;
	}

	return NULL;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

int
slapi_filter_get_attribute_type( Slapi_Filter *f, char **type )
{
#ifdef LDAP_SLAPI
	if ( f == NULL ) {
		return -1;
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_APPROX:
		*type = f->f_av_desc->ad_cname.bv_val;
		break;
	case LDAP_FILTER_SUBSTRINGS:
		*type = f->f_sub_desc->ad_cname.bv_val;
		break;
	case LDAP_FILTER_PRESENT:
		*type = f->f_desc->ad_cname.bv_val;
		break;
	case LDAP_FILTER_EXT:
		*type = f->f_mr_desc->ad_cname.bv_val;
		break;
	default:
		/* Complex filters need not apply. */
		*type = NULL;
		return -1;
	}

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_filter_get_subfilt( Slapi_Filter *f, char **type, char **initial,
	char ***any, char **final )
{
#ifdef LDAP_SLAPI
	int i;

	if ( f->f_choice != LDAP_FILTER_SUBSTRINGS ) {
		return -1;
	}

	/*
	 * The caller shouldn't free but we can't return an
	 * array of char *s from an array of bervals without
	 * allocating memory, so we may as well be consistent.
	 * XXX
	 */
	*type = f->f_sub_desc->ad_cname.bv_val;
	*initial = f->f_sub_initial.bv_val ? slapi_ch_strdup(f->f_sub_initial.bv_val) : NULL;
	if ( f->f_sub_any != NULL ) {
		for ( i = 0; f->f_sub_any[i].bv_val != NULL; i++ )
			;
		*any = (char **)slapi_ch_malloc( (i + 1) * sizeof(char *) );
		for ( i = 0; f->f_sub_any[i].bv_val != NULL; i++ ) {
			(*any)[i] = slapi_ch_strdup(f->f_sub_any[i].bv_val);
		}
		(*any)[i] = NULL;
	} else {
		*any = NULL;
	}
	*final = f->f_sub_final.bv_val ? slapi_ch_strdup(f->f_sub_final.bv_val) : NULL;

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_Filter *
slapi_filter_join( int ftype, Slapi_Filter *f1, Slapi_Filter *f2 )
{
#ifdef LDAP_SLAPI
	Slapi_Filter *f = NULL;

	if ( ftype == LDAP_FILTER_AND ||
	     ftype == LDAP_FILTER_OR ||
	     ftype == LDAP_FILTER_NOT )
	{
		f = (Slapi_Filter *)slapi_ch_malloc( sizeof(*f) );
		f->f_choice = ftype;
		f->f_list = f1;
		f->f_list->f_next = f2;
		f->f_next = NULL;
	}

	return f;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

int
slapi_x_filter_append( int ftype,
	Slapi_Filter **pContainingFilter, /* NULL on first call */
	Slapi_Filter **pNextFilter,
	Slapi_Filter *filterToAppend )
{
#ifdef LDAP_SLAPI
	if ( ftype == LDAP_FILTER_AND ||
	     ftype == LDAP_FILTER_OR ||
	     ftype == LDAP_FILTER_NOT )
	{
		if ( *pContainingFilter == NULL ) {
			*pContainingFilter = (Slapi_Filter *)slapi_ch_malloc( sizeof(Slapi_Filter) );
			(*pContainingFilter)->f_choice = ftype;
			(*pContainingFilter)->f_list = filterToAppend;
			(*pContainingFilter)->f_next = NULL;
		} else {
			if ( (*pContainingFilter)->f_choice != ftype ) {
				/* Sanity check */
				return -1;
			}
			(*pNextFilter)->f_next = filterToAppend;
		}
		*pNextFilter = filterToAppend;

		return 0;
	}
#endif /* LDAP_SLAPI */
	return -1;
}

int
slapi_filter_test( Slapi_PBlock *pb, Slapi_Entry *e, Slapi_Filter *f,
	int verify_access )
{
#ifdef LDAP_SLAPI
	Operation *op;
	int rc;

	if ( f == NULL ) {
		/* spec says return zero if no filter. */
		return 0;
	}

	if ( verify_access ) {
		rc = slapi_pblock_get(pb, SLAPI_OPERATION, (void *)&op);
		if ( rc != 0 ) {
			return LDAP_PARAM_ERROR;
		}
	} else {
		op = NULL;
	}
	/*
	 * According to acl.c it is safe to call test_filter() with
	 * NULL arguments...
	 */
	rc = test_filter( op, e, f );
	switch (rc) {
	case LDAP_COMPARE_TRUE:
		rc = 0;
		break;
	case LDAP_COMPARE_FALSE:
		break;
	case SLAPD_COMPARE_UNDEFINED:
		rc = LDAP_OTHER;
		break;
	case LDAP_PROTOCOL_ERROR:
		/* filter type unknown: spec says return -1 */
		rc = -1;
		break;
	}

	return rc;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_filter_test_simple( Slapi_Entry *e, Slapi_Filter *f)
{
#ifdef LDAP_SLAPI
	return slapi_filter_test( NULL, e, f, 0 );
#else
	return -1;
#endif
}

int
slapi_filter_apply( Slapi_Filter *f, FILTER_APPLY_FN fn, void *arg, int *error_code )
{
#ifdef LDAP_SLAPI
	switch ( f->f_choice ) {
	case LDAP_FILTER_AND:
	case LDAP_FILTER_NOT:
	case LDAP_FILTER_OR: {
		int rc;

		/*
		 * FIXME: altering f; should we use a temporary?
		 */
		for ( f = f->f_list; f != NULL; f = f->f_next ) {
			rc = slapi_filter_apply( f, fn, arg, error_code );
			if ( rc != 0 ) {
				return rc;
			}
			if ( *error_code == SLAPI_FILTER_SCAN_NOMORE ) {
				break;
			}
		}
		break;
	}
	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_SUBSTRINGS:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_PRESENT:
	case LDAP_FILTER_APPROX:
	case LDAP_FILTER_EXT:
		*error_code = fn( f, arg );
		break;
	default:
		*error_code = SLAPI_FILTER_UNKNOWN_FILTER_TYPE;
	}

	if ( *error_code == SLAPI_FILTER_SCAN_NOMORE ||
	     *error_code == SLAPI_FILTER_SCAN_CONTINUE ) {
		return 0;
	}

	return -1;
#else
	*error_code = SLAPI_FILTER_UNKNOWN_FILTER_TYPE;
	return -1;
#endif /* LDAP_SLAPI */
}

int 
slapi_send_ldap_extended_response(
	Connection	*conn, 
	Operation	*op,
	int		errornum, 
	char		*respName,
	struct berval	*response )
{
#ifdef LDAP_SLAPI
	SlapReply	rs;

	rs.sr_err = errornum;
	rs.sr_matched = NULL;
	rs.sr_text = NULL;
	rs.sr_ref = NULL;
	rs.sr_ctrls = NULL;
	rs.sr_rspoid = respName;
	rs.sr_rspdata = response;

	send_ldap_extended( op, &rs );

	return LDAP_SUCCESS;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}

int 
slapi_pw_find(
	struct berval	**vals, 
	struct berval	*v ) 
{
#ifdef LDAP_SLAPI
	/*
	 * FIXME: what's the point?
	 */
	return 1;
#else /* LDAP_SLAPI */
	return 1;
#endif /* LDAP_SLAPI */
}

#define MAX_HOSTNAME 512

char *
slapi_get_hostname( void ) 
{
#ifdef LDAP_SLAPI
	char		*hn = NULL;
	static int	been_here = 0;   
	static char	*static_hn = NULL;

	ldap_pvt_thread_mutex_lock( &slapi_hn_mutex );
	if ( !been_here ) {
		static_hn = (char *)slapi_ch_malloc( MAX_HOSTNAME );
		if ( static_hn == NULL) {
			slapi_log_error( SLAPI_LOG_FATAL, "slapi_get_hostname",
					"Cannot allocate memory for hostname\n" );
			static_hn = NULL;
			ldap_pvt_thread_mutex_unlock( &slapi_hn_mutex );

			return hn;
			
		} else { 
			if ( gethostname( static_hn, MAX_HOSTNAME ) != 0 ) {
				slapi_log_error( SLAPI_LOG_FATAL,
						"SLAPI",
						"can't get hostname\n" );
				slapi_ch_free( (void **)&static_hn );
				static_hn = NULL;
				ldap_pvt_thread_mutex_unlock( &slapi_hn_mutex );

				return hn;

			} else {
				been_here = 1;
			}
		}
	}
	ldap_pvt_thread_mutex_unlock( &slapi_hn_mutex );
	
	hn = ch_strdup( static_hn );

	return hn;
#else /* LDAP_SLAPI */
	return NULL;
#endif /* LDAP_SLAPI */
}

/*
 * FIXME: this should go in an appropriate header ...
 */
extern int slapi_int_log_error( int level, char *subsystem, char *fmt, va_list arglist );

int 
slapi_log_error(
	int		severity, 
	char		*subsystem, 
	char		*fmt, 
	... ) 
{
#ifdef LDAP_SLAPI
	int		rc = LDAP_SUCCESS;
	va_list		arglist;

	va_start( arglist, fmt );
	rc = slapi_int_log_error( severity, subsystem, fmt, arglist );
	va_end( arglist );

	return rc;
#else /* LDAP_SLAPI */
	return -1;
#endif /* LDAP_SLAPI */
}


unsigned long
slapi_timer_current_time( void ) 
{
#ifdef LDAP_SLAPI
	static int	first_time = 1;
#if !defined (_WIN32)
	struct timeval	now;
	unsigned long	ret;

	ldap_pvt_thread_mutex_lock( &slapi_time_mutex );
	if (first_time) {
		first_time = 0;
		gettimeofday( &base_time, NULL );
	}
	gettimeofday( &now, NULL );
	ret = ( now.tv_sec  - base_time.tv_sec ) * 1000000 + 
			(now.tv_usec - base_time.tv_usec);
	ldap_pvt_thread_mutex_unlock( &slapi_time_mutex );

	return ret;

	/*
	 * Ain't it better?
	return (slap_get_time() - starttime) * 1000000;
	 */
#else /* _WIN32 */
	LARGE_INTEGER now;

	if ( first_time ) {
		first_time = 0;
		performance_counter_present = QueryPerformanceCounter( &base_time );
		QueryPerformanceFrequency( &performance_freq );
	}

	if ( !performance_counter_present )
	     return 0;

	QueryPerformanceCounter( &now );
	return (1000000*(now.QuadPart-base_time.QuadPart))/performance_freq.QuadPart;
#endif /* _WIN32 */
#else /* LDAP_SLAPI */
	return 0;
#endif /* LDAP_SLAPI */
}

/*
 * FIXME ?
 */
unsigned long
slapi_timer_get_time( char *label ) 
{
#ifdef LDAP_SLAPI
	unsigned long start = slapi_timer_current_time();
	printf("%10ld %10ld usec %s\n", start, 0, label);
	return start;
#else /* LDAP_SLAPI */
	return 0;
#endif /* LDAP_SLAPI */
}

/*
 * FIXME ?
 */
void
slapi_timer_elapsed_time(
	char *label,
	unsigned long start ) 
{
#ifdef LDAP_SLAPI
	unsigned long stop = slapi_timer_current_time();
	printf ("%10ld %10ld usec %s\n", stop, stop - start, label);
#endif /* LDAP_SLAPI */
}

void
slapi_free_search_results_internal( Slapi_PBlock *pb ) 
{
#ifdef LDAP_SLAPI
	Slapi_Entry	**entries;
	int		k = 0, nEnt = 0;

	slapi_pblock_get( pb, SLAPI_NENTRIES, &nEnt );
	slapi_pblock_get( pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries );
	if ( nEnt == 0 ) {
		return;
	}
	
	if ( entries == NULL ) {
		return;
	}
	
	for ( k = 0; k < nEnt; k++ ) {
		slapi_entry_free( entries[k] );
	}
	
	slapi_ch_free( (void **)&entries );
#endif /* LDAP_SLAPI */
}

#ifdef LDAP_SLAPI
/*
 * Internal API to prime a Slapi_PBlock with a Backend.
 */
static int slapi_int_pblock_set_backend( Slapi_PBlock *pb, Backend *be )
{
	int rc;
	
	rc = slapi_pblock_set( pb, SLAPI_BACKEND, (void *)be );
	if ( rc != LDAP_SUCCESS )
		return rc;
	
	if ( be != NULL ) {
		rc = slapi_pblock_set( pb, SLAPI_BE_TYPE, (void *)be->bd_info->bi_type );
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	return LDAP_SUCCESS;
}

/*
 * If oldStyle is TRUE, then a value suitable for setting to
 * the deprecated SLAPI_CONN_AUTHTYPE value is returned 
 * (pointer to static storage).
 *
 * If oldStyle is FALSE, then a value suitable for setting to
 * the new SLAPI_CONN_AUTHMETHOD will be returned, which is
 * a pointer to allocated memory and will include the SASL
 * mechanism (if any).
 */
static char *Authorization2AuthType( AuthorizationInformation *authz, int is_tls, int oldStyle )
{
	size_t len;
	char *authType;

	switch ( authz->sai_method ) {
	case LDAP_AUTH_SASL:
		if ( oldStyle ) {
			authType = SLAPD_AUTH_SASL;
		} else {
			len = sizeof(SLAPD_AUTH_SASL) + authz->sai_mech.bv_len;
			authType = slapi_ch_malloc( len );
			snprintf( authType, len, "%s%s", SLAPD_AUTH_SASL, authz->sai_mech.bv_val );
		}
		break;
	case LDAP_AUTH_SIMPLE:
		authType = oldStyle ? SLAPD_AUTH_SIMPLE : slapi_ch_strdup( SLAPD_AUTH_SIMPLE );
		break;
	case LDAP_AUTH_NONE:
		authType = oldStyle ? SLAPD_AUTH_NONE : slapi_ch_strdup( SLAPD_AUTH_NONE );
		break;
	default:
		authType = NULL;
		break;
	}
	if ( is_tls && authType == NULL ) {
		authType = oldStyle ? SLAPD_AUTH_SSL : slapi_ch_strdup( SLAPD_AUTH_SSL );
	}

	return authType;
}

/*
 * Internal API to prime a Slapi_PBlock with a Connection.
 */
static int slapi_int_pblock_set_connection( Slapi_PBlock *pb, Connection *conn )
{
	char *connAuthType;
	int rc;

	rc = slapi_pblock_set( pb, SLAPI_CONNECTION, (void *)conn );
	if ( rc != LDAP_SUCCESS )
		return rc;

	if ( strncmp( conn->c_peer_name.bv_val, "IP=", 3 ) == 0 ) {
		rc = slapi_pblock_set( pb, SLAPI_CONN_CLIENTIP, (void *)&conn->c_peer_name.bv_val[3] );
		if ( rc != LDAP_SUCCESS )
			return rc;
	} else if ( strncmp( conn->c_peer_name.bv_val, "PATH=", 5 ) == 0 ) {
		rc = slapi_pblock_set( pb, SLAPI_X_CONN_CLIENTPATH, (void *)&conn->c_peer_name.bv_val[5] );
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	if ( strncmp( conn->c_sock_name.bv_val, "IP=", 3 ) == 0 ) {
		rc = slapi_pblock_set( pb, SLAPI_CONN_SERVERIP, (void *)&conn->c_sock_name.bv_val[3] );
		if ( rc != LDAP_SUCCESS )
			return rc;
	} else if ( strncmp( conn->c_sock_name.bv_val, "PATH=", 5 ) == 0 ) {
		rc = slapi_pblock_set( pb, SLAPI_X_CONN_SERVERPATH, (void *)&conn->c_sock_name.bv_val[5] );
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

#ifdef LDAP_CONNECTIONLESS
	rc = slapi_pblock_set( pb, SLAPI_X_CONN_IS_UDP, (void *)conn->c_is_udp );
	if ( rc != LDAP_SUCCESS )
		return rc;
#endif

	rc = slapi_pblock_set( pb, SLAPI_CONN_ID, (void *)conn->c_connid );
	if ( rc != LDAP_SUCCESS )
		return rc;

	/* Returns pointer to static string */
	connAuthType = Authorization2AuthType( &conn->c_authz,
#ifdef HAVE_TLS
		conn->c_is_tls,
#else
		0,
#endif
		1 );
	if ( connAuthType != NULL ) {
		rc = slapi_pblock_set(pb, SLAPI_CONN_AUTHTYPE, (void *)connAuthType);
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	/* Returns pointer to allocated string */
	connAuthType = Authorization2AuthType( &conn->c_authz,
#ifdef HAVE_TLS
		conn->c_is_tls,
#else
		0,
#endif
		0 );
	if ( connAuthType != NULL ) {
		rc = slapi_pblock_set(pb, SLAPI_CONN_AUTHMETHOD, (void *)connAuthType);
		/* slapi_pblock_set dups this itself */
		slapi_ch_free( (void **)&connAuthType );
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	if ( conn->c_authz.sai_dn.bv_val != NULL ) {
		/* slapi_pblock_set dups this itself */
		rc = slapi_pblock_set(pb, SLAPI_CONN_DN, (void *)conn->c_authz.sai_dn.bv_val);
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	rc = slapi_pblock_set(pb, SLAPI_X_CONN_SSF, (void *)conn->c_ssf);
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_X_CONN_SASL_CONTEXT,
		( conn->c_sasl_authctx != NULL ? conn->c_sasl_authctx :
						 conn->c_sasl_sockctx ) );
	if ( rc != LDAP_SUCCESS )
		return rc;

	return rc;
}
#endif /* LDAP_SLAPI */

/*
 * Internal API to prime a Slapi_PBlock with an Operation.
 */
int slapi_int_pblock_set_operation( Slapi_PBlock *pb, Operation *op )
{
#ifdef LDAP_SLAPI
	int isRoot = 0;
	int isUpdateDn = 0;
	int rc;
	char *opAuthType;

	if ( op->o_bd != NULL ) {
		isRoot = be_isroot( op->o_bd, &op->o_ndn );
		isUpdateDn = be_isupdate( op->o_bd, &op->o_ndn );
	}

	rc = slapi_int_pblock_set_backend( pb, op->o_bd );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_int_pblock_set_connection( pb, op->o_conn );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_OPERATION, (void *)op );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_OPINITIATED_TIME, (void *)op->o_time );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_OPERATION_ID, (void *)op->o_opid );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_OPERATION_TYPE, (void *)op->o_tag );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_REQUESTOR_ISROOT, (void *)isRoot );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_REQUESTOR_ISUPDATEDN, (void *)isUpdateDn );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)op->o_ctrls );
	if ( rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set( pb, SLAPI_REQUESTOR_DN, (void *)op->o_ndn.bv_val );
	if ( rc != LDAP_SUCCESS )
		return rc;

	rc = slapi_pblock_get( pb, SLAPI_CONN_AUTHMETHOD, (void *)&opAuthType );
	if ( rc == LDAP_SUCCESS && opAuthType != NULL ) {
		/* Not quite sure what the point of this is. */
		rc = slapi_pblock_set( pb, SLAPI_OPERATION_AUTHTYPE, (void *)opAuthType );
		if ( rc != LDAP_SUCCESS )
			return rc;
	}

	return LDAP_SUCCESS;
#else
	return -1;
#endif
}

int slapi_is_connection_ssl( Slapi_PBlock *pb, int *isSSL )
{
#ifdef LDAP_SLAPI
	Connection *conn;

	slapi_pblock_get( pb, SLAPI_CONNECTION, &conn );
#ifdef HAVE_TLS
	*isSSL = conn->c_is_tls;
#else
	*isSSL = 0;
#endif

	return LDAP_SUCCESS;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/*
 * DS 5.x compatability API follow
 */

int slapi_attr_get_flags( const Slapi_Attr *attr, unsigned long *flags )
{
#ifdef LDAP_SLAPI
	AttributeType *at;

	if ( attr == NULL )
		return LDAP_PARAM_ERROR;

	at = attr->a_desc->ad_type;

	*flags = SLAPI_ATTR_FLAG_STD_ATTR;

	if ( is_at_single_value( at ) )
		*flags |= SLAPI_ATTR_FLAG_SINGLE;
	if ( is_at_operational( at ) )
		*flags |= SLAPI_ATTR_FLAG_OPATTR;
	if ( is_at_obsolete( at ) )
		*flags |= SLAPI_ATTR_FLAG_OBSOLETE;
	if ( is_at_collective( at ) )
		*flags |= SLAPI_ATTR_FLAG_COLLECTIVE;
	if ( is_at_no_user_mod( at ) )
		*flags |= SLAPI_ATTR_FLAG_NOUSERMOD;

	return LDAP_SUCCESS;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int slapi_attr_flag_is_set( const Slapi_Attr *attr, unsigned long flag )
{
#ifdef LDAP_SLAPI
	unsigned long flags;

	if ( slapi_attr_get_flags( attr, &flags ) != 0 )
		return 0;
	return (flags & flag) ? 1 : 0;
#else
	return 0;
#endif /* LDAP_SLAPI */
}

Slapi_Attr *slapi_attr_new( void )
{
#ifdef LDAP_SLAPI
	Attribute *ad;

	ad = (Attribute  *)slapi_ch_calloc( 1, sizeof(*ad) );

	return ad;
#else
	return NULL;
#endif
}

Slapi_Attr *slapi_attr_init( Slapi_Attr *a, const char *type )
{
#ifdef LDAP_SLAPI
	const char *text;
	AttributeDescription *ad = NULL;

	if( slap_str2ad( type, &ad, &text ) != LDAP_SUCCESS ) {
		return NULL;
	}

	a->a_desc = ad;
	a->a_vals = NULL;
	a->a_nvals = NULL;
	a->a_next = NULL;
	a->a_flags = 0;

	return a;
#else
	return NULL;
#endif
}

void slapi_attr_free( Slapi_Attr **a )
{
#ifdef LDAP_SLAPI
	attr_free( *a );
	*a = NULL;
#endif
}

Slapi_Attr *slapi_attr_dup( const Slapi_Attr *attr )
{
#ifdef LDAP_SLAPI
	return attr_dup( (Slapi_Attr *)attr );
#else
	return NULL;
#endif
}

int slapi_attr_add_value( Slapi_Attr *a, const Slapi_Value *v )
{
#ifdef LDAP_SLAPI
	/*
	 * FIXME: here we may lose alignment between a_vals/a_nvals
	 */
	return value_add_one( &a->a_vals, (Slapi_Value *)v );
#else
	return -1;
#endif
}

int slapi_attr_type2plugin( const char *type, void **pi )
{
	*pi = NULL;

	return LDAP_OTHER;
}

int slapi_attr_get_type( const Slapi_Attr *attr, char **type )
{
#ifdef LDAP_SLAPI
	if ( attr == NULL ) {
		return LDAP_PARAM_ERROR;
	}

	*type = attr->a_desc->ad_cname.bv_val;

	return LDAP_SUCCESS;
#else
	return -1;
#endif
}

int slapi_attr_get_oid_copy( const Slapi_Attr *attr, char **oidp )
{
#ifdef LDAP_SLAPI
	if ( attr == NULL ) {
		return LDAP_PARAM_ERROR;
	}
	*oidp = attr->a_desc->ad_type->sat_oid;

	return LDAP_SUCCESS;
#else
	return -1;
#endif
}

int slapi_attr_value_cmp( const Slapi_Attr *a, const struct berval *v1, const struct berval *v2 )
{
#ifdef LDAP_SLAPI
	MatchingRule *mr;
	int ret;
	int rc;
	const char *text;

	mr = a->a_desc->ad_type->sat_equality;
	rc = value_match( &ret, a->a_desc, mr,
			SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
		(struct berval *)v1, (void *)v2, &text );
	if ( rc != LDAP_SUCCESS ) 
		return -1;

	return ( ret == 0 ) ? 0 : -1;
#else
	return -1;
#endif
}

int slapi_attr_value_find( const Slapi_Attr *a, struct berval *v )
{
#ifdef LDAP_SLAPI
	MatchingRule *mr;
	struct berval *bv;
	int j;
	const char *text;
	int rc;
	int ret;

	if ( a ->a_vals == NULL ) {
		return -1;
	}
	mr = a->a_desc->ad_type->sat_equality;
	for ( bv = a->a_vals, j = 0; bv->bv_val != NULL; bv++, j++ ) {
		rc = value_match( &ret, a->a_desc, mr,
			SLAP_MR_VALUE_OF_ASSERTION_SYNTAX, bv, v, &text );
		if ( rc != LDAP_SUCCESS ) {
			return -1;
		}
		if ( ret == 0 ) {
			return 0;
		}
	}
#endif /* LDAP_SLAPI */
	return -1;
}

int slapi_attr_type_cmp( const char *t1, const char *t2, int opt )
{
#ifdef LDAP_SLAPI
	AttributeDescription *a1 = NULL;
	AttributeDescription *a2 = NULL;
	const char *text;
	int ret;

	if ( slap_str2ad( t1, &a1, &text ) != LDAP_SUCCESS ) {
		return -1;
	}

	if ( slap_str2ad( t2, &a2, &text ) != LDAP_SUCCESS ) {
		return 1;
	}

#define ad_base_cmp(l,r) (((l)->ad_type->sat_cname.bv_len < (r)->ad_type->sat_cname.bv_len) \
	? -1 : (((l)->ad_type->sat_cname.bv_len > (r)->ad_type->sat_cname.bv_len) \
		? 1 : strcasecmp((l)->ad_type->sat_cname.bv_val, (r)->ad_type->sat_cname.bv_val )))

	switch ( opt ) {
	case SLAPI_TYPE_CMP_EXACT:
		ret = ad_cmp( a1, a2 );
		break;
	case SLAPI_TYPE_CMP_BASE:
		ret = ad_base_cmp( a1, a2 );
		break;
	case SLAPI_TYPE_CMP_SUBTYPE:
		ret = is_ad_subtype( a2, a2 );
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
#else
	return -1;
#endif
}

int slapi_attr_types_equivalent( const char *t1, const char *t2 )
{
#ifdef LDAP_SLAPI
	return slapi_attr_type_cmp( t1, t2, SLAPI_TYPE_CMP_EXACT );
#else
	return -1;
#endif
}

int slapi_attr_first_value( Slapi_Attr *a, Slapi_Value **v )
{
#ifdef LDAP_SLAPI
	return slapi_valueset_first_value( &a->a_vals, v );
#else
	return -1;
#endif
}

int slapi_attr_next_value( Slapi_Attr *a, int hint, Slapi_Value **v )
{
#ifdef LDAP_SLAPI
	return slapi_valueset_next_value( &a->a_vals, hint, v );
#else
	return -1;
#endif
}

int slapi_attr_get_numvalues( const Slapi_Attr *a, int *numValues )
{
#ifdef LDAP_SLAPI
	*numValues = slapi_valueset_count( &a->a_vals );

	return 0;
#else
	return -1;
#endif
}

int slapi_attr_get_valueset( const Slapi_Attr *a, Slapi_ValueSet **vs )
{
#ifdef LDAP_SLAPI
	*vs = &((Slapi_Attr *)a)->a_vals;

	return 0;
#else
	return -1;
#endif
}

int slapi_attr_get_bervals_copy( Slapi_Attr *a, struct berval ***vals )
{
#ifdef LDAP_SLAPI
	return slapi_attr_get_values( a, vals );
#else
	return -1;
#endif
}

char *slapi_attr_syntax_normalize( const char *s )
{
#ifdef LDAP_SLAPI
	AttributeDescription *ad = NULL;
	const char *text;

	if ( slap_str2ad( s, &ad, &text ) != LDAP_SUCCESS ) {
		return NULL;
	}

	return ad->ad_cname.bv_val;
#else
	return -1;
#endif
}

Slapi_Value *slapi_value_new( void )
{
#ifdef LDAP_SLAPI
	struct berval *bv;

	bv = (struct berval *)slapi_ch_malloc( sizeof(*bv) );

	return bv;
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_new_berval(const struct berval *bval)
{
#ifdef LDAP_SLAPI
	return ber_dupbv( NULL, (struct berval *)bval );
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_new_value(const Slapi_Value *v)
{
#ifdef LDAP_SLAPI
	return slapi_value_new_berval( v );
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_new_string(const char *s)
{
#ifdef LDAP_SLAPI
	struct berval bv;

	bv.bv_val = (char *)s;
	bv.bv_len = strlen( s );

	return slapi_value_new_berval( &bv );
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_init(Slapi_Value *val)
{
#ifdef LDAP_SLAPI
	val->bv_val = NULL;
	val->bv_len = 0;

	return val;
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_init_berval(Slapi_Value *v, struct berval *bval)
{
#ifdef LDAP_SLAPI
	return ber_dupbv( v, bval );
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_init_string(Slapi_Value *v, const char *s)
{
#ifdef LDAP_SLAPI
	v->bv_val = slapi_ch_strdup( (char *)s );
	v->bv_len = strlen( s );

	return v;
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_dup(const Slapi_Value *v)
{
#ifdef LDAP_SLAPI
	return slapi_value_new_value( v );
#else
	return NULL;
#endif
}

void slapi_value_free(Slapi_Value **value)
{
#ifdef LDAP_SLAPI	
	if ( value == NULL ) {
		return;
	}

	if ( (*value) != NULL ) {
		slapi_ch_free( (void **)&(*value)->bv_val );
		slapi_ch_free( (void **)value );
	}
#endif
}

const struct berval *slapi_value_get_berval( const Slapi_Value *value )
{
#ifdef LDAP_SLAPI
	return value;
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_set_berval( Slapi_Value *value, const struct berval *bval )
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) {
		return NULL;
	}
	if ( value->bv_val != NULL ) {
		slapi_ch_free( (void **)&value->bv_val );
	}
	slapi_value_init_berval( value, (struct berval *)bval );

	return value;
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_set_value( Slapi_Value *value, const Slapi_Value *vfrom)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) {
		return NULL;
	}
	return slapi_value_set_berval( value, vfrom );
#else
	return NULL;
#endif
}

Slapi_Value *slapi_value_set( Slapi_Value *value, void *val, unsigned long len)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) {
		return NULL;
	}
	if ( value->bv_val != NULL ) {
		slapi_ch_free( (void **)&value->bv_val );
	}
	value->bv_val = slapi_ch_malloc( len );
	value->bv_len = len;
	AC_MEMCPY( value->bv_val, val, len );

	return value;
#else
	return NULL;
#endif
}

int slapi_value_set_string(Slapi_Value *value, const char *strVal)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) {
		return -1;
	}
	slapi_value_set( value, (void *)strVal, strlen( strVal ) );
	return 0;
#else
	return NULL;
#endif
}

int slapi_value_set_int(Slapi_Value *value, int intVal)
{
#ifdef LDAP_SLAPI
	char buf[64];

	snprintf( buf, sizeof( buf ), "%d", intVal );

	return slapi_value_set_string( value, buf );
#else
	return -1;
#endif
}

const char *slapi_value_get_string(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) {
		return NULL;
	}
	return value->bv_val;
#else
	return NULL;
#endif
}

#ifdef LDAP_SLAPI
static int checkBVString(const struct berval *bv)
{
	int i;

	for ( i = 0; i < bv->bv_len; i++ ) {
		if ( bv->bv_val[i] == '\0' )
			return 0;
	}
	if ( bv->bv_val[i] != '\0' )
		return 0;

	return 1;
}
#endif /* LDAP_SLAPI */

int slapi_value_get_int(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) return 0;
	if ( value->bv_val == NULL ) return 0;
	if ( !checkBVString( value ) ) return 0;

	return (int)strtol( value->bv_val, NULL, 10 );
#else
	return NULL;
#endif
}

unsigned int slapi_value_get_uint(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) return 0;
	if ( value->bv_val == NULL ) return 0;
	if ( !checkBVString( value ) ) return 0;

	return (unsigned int)strtoul( value->bv_val, NULL, 10 );
#else
	return NULL;
#endif
}

long slapi_value_get_long(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) return 0;
	if ( value->bv_val == NULL ) return 0;
	if ( !checkBVString( value ) ) return 0;

	return strtol( value->bv_val, NULL, 10 );
#else
	return NULL;
#endif
}

unsigned long slapi_value_get_ulong(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL ) return 0;
	if ( value->bv_val == NULL ) return 0;
	if ( !checkBVString( value ) ) return 0;

	return strtoul( value->bv_val, NULL, 10 );
#else
	return NULL;
#endif
}

size_t slapi_value_get_length(const Slapi_Value *value)
{
#ifdef LDAP_SLAPI
	if ( value == NULL )
		return 0;

	return (size_t) value->bv_len;
#else
	return 0;
#endif
}

int slapi_value_compare(const Slapi_Attr *a, const Slapi_Value *v1, const Slapi_Value *v2)
{
#ifdef LDAP_SLAPI
	return slapi_attr_value_cmp( a, v1, v2 );
#else
	return -1;
#endif
}

/* A ValueSet is a container for a BerVarray. */
Slapi_ValueSet *slapi_valueset_new( void )
{
#ifdef LDAP_SLAPI
	Slapi_ValueSet *vs;

	vs = (Slapi_ValueSet *)slapi_ch_malloc( sizeof( *vs ) );
	*vs = NULL;

	return vs;
#else
	return NULL;
#endif
}

void slapi_valueset_free(Slapi_ValueSet *vs)
{
#ifdef LDAP_SLAPI
	if ( vs != NULL ) {
		BerVarray vp = *vs;

		ber_bvarray_free( vp );
		slapi_ch_free( (void **)&vp );

		*vs = NULL;
	}
#endif
}

void slapi_valueset_init(Slapi_ValueSet *vs)
{
#ifdef LDAP_SLAPI
	if ( vs != NULL && *vs == NULL ) {
		*vs = (Slapi_ValueSet)slapi_ch_calloc( 1, sizeof(struct berval) );
		(*vs)->bv_val = NULL;
		(*vs)->bv_len = 0;
	}
#endif
}

void slapi_valueset_done(Slapi_ValueSet *vs)
{
#ifdef LDAP_SLAPI
	BerVarray vp;

	if ( vs == NULL )
		return;

	for ( vp = *vs; vp->bv_val != NULL; vp++ ) {
		vp->bv_len = 0;
		slapi_ch_free( (void **)&vp->bv_val );
	}
	/* but don't free *vs or vs */
#endif
}

void slapi_valueset_add_value(Slapi_ValueSet *vs, const Slapi_Value *addval)
{
#ifdef LDAP_SLAPI
	struct berval bv;

	ber_dupbv( &bv, (Slapi_Value *)addval );
	ber_bvarray_add( vs, &bv );
#endif
}

int slapi_valueset_first_value( Slapi_ValueSet *vs, Slapi_Value **v )
{
#ifdef LDAP_SLAPI
	return slapi_valueset_next_value( vs, 0, v );
#else
	return -1;
#endif
}

int slapi_valueset_next_value( Slapi_ValueSet *vs, int index, Slapi_Value **v)
{
#ifdef LDAP_SLAPI
	int i;
	BerVarray vp;

	if ( vs == NULL )
		return -1;

	vp = *vs;

	for ( i = 0; vp[i].bv_val != NULL; i++ ) {
		if ( i == index ) {
			*v = &vp[i];
			return index + 1;
		}
	}
#endif

	return -1;
}

int slapi_valueset_count( const Slapi_ValueSet *vs )
{
#ifdef LDAP_SLAPI
	int i;
	BerVarray vp;

	if ( vs == NULL )
		return 0;

	vp = *vs;

	for ( i = 0; vp[i].bv_val != NULL; i++ )
		;

	return i;
#else
	return 0;
#endif

}

void slapi_valueset_set_valueset(Slapi_ValueSet *vs1, const Slapi_ValueSet *vs2)
{
#ifdef LDAP_SLAPI
	BerVarray vp;

	for ( vp = *vs2; vp->bv_val != NULL; vp++ ) {
		slapi_valueset_add_value( vs1, vp );
	}
#endif
}

int slapi_access_allowed( Slapi_PBlock *pb, Slapi_Entry *e, char *attr,
	struct berval *val, int access )
{
#ifdef LDAP_SLAPI
	Backend *be;
	Connection *conn;
	Operation *op;
	int ret;
	slap_access_t slap_access;
	AttributeDescription *ad = NULL;
	const char *text;

	ret = slap_str2ad( attr, &ad, &text );
	if ( ret != LDAP_SUCCESS ) {
		return ret;
	}

	switch ( access & SLAPI_ACL_ALL ) {
	case SLAPI_ACL_COMPARE:
		slap_access = ACL_COMPARE;
		break;
	case SLAPI_ACL_SEARCH:
		slap_access = ACL_SEARCH;
		break;
	case SLAPI_ACL_READ:
		slap_access = ACL_READ;
		break;
	case SLAPI_ACL_WRITE:
	case SLAPI_ACL_DELETE:
	case SLAPI_ACL_ADD:
	case SLAPI_ACL_SELF:
		slap_access = ACL_WRITE;
		break;
	default:
		return LDAP_INSUFFICIENT_ACCESS;
		break;
	}

	if ( slapi_pblock_get( pb, SLAPI_BACKEND, (void *)&be ) != 0 ) {
		return LDAP_PARAM_ERROR;
	}

	if ( slapi_pblock_get( pb, SLAPI_CONNECTION, (void *)&conn ) != 0 ) {
		return LDAP_PARAM_ERROR;
	}

	if ( slapi_pblock_get( pb, SLAPI_OPERATION, (void *)&op ) != 0 ) {
		return LDAP_PARAM_ERROR;
	}

	ret = access_allowed( op, e, ad, val, slap_access, NULL );

	return ret ? LDAP_SUCCESS : LDAP_INSUFFICIENT_ACCESS;
#else
	return LDAP_UNWILLING_TO_PERFORM;
#endif
}

int slapi_acl_check_mods(Slapi_PBlock *pb, Slapi_Entry *e, LDAPMod **mods, char **errbuf)
{
#ifdef LDAP_SLAPI
	Operation *op;
	int rc = LDAP_SUCCESS;
	Modifications *ml, *mp;

	if ( slapi_pblock_get( pb, SLAPI_OPERATION, (void *)&op ) != 0 ) {
		return LDAP_PARAM_ERROR;
	}

	ml = slapi_int_ldapmods2modifications( mods );
	if ( ml == NULL ) {
		return LDAP_OTHER;
	}

	for ( mp = ml; mp != NULL; mp = mp->sml_next ) {
		rc = slap_bv2ad( &mp->sml_type, &mp->sml_desc, (const char **)errbuf );
		if ( rc != LDAP_SUCCESS ) {
			break;
		}
	}

	if ( rc == LDAP_SUCCESS ) {
		rc = acl_check_modlist( op, e, ml ) ? LDAP_SUCCESS : LDAP_INSUFFICIENT_ACCESS;
	}

	/* Careful when freeing the modlist because it has pointers into the mods array. */
	for ( ; ml != NULL; ml = mp ) {
		mp = ml->sml_next;

		/* just free the containing array */
		slapi_ch_free( (void **)&ml->sml_bvalues );
		slapi_ch_free( (void **)&ml );
	}

	return rc;
#else
	return LDAP_UNWILLING_TO_PERFORM;
#endif
}

/*
 * Synthesise an LDAPMod array from a Modifications list to pass
 * to SLAPI. This synthesis is destructive and as such the 
 * Modifications list may not be used after calling this 
 * function.
 * 
 * This function must also be called before slap_mods_check().
 */
LDAPMod **slapi_int_modifications2ldapmods(Modifications **pmodlist)
{
#ifdef LDAP_SLAPI
	Modifications *ml, *modlist;
	LDAPMod **mods, *modp;
	int i, j;

	modlist = *pmodlist;

	for( i = 0, ml = modlist; ml != NULL; i++, ml = ml->sml_next )
		;

	mods = (LDAPMod **)ch_malloc( (i + 1) * sizeof(LDAPMod *) );

	for( i = 0, ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mods[i] = (LDAPMod *)ch_malloc( sizeof(LDAPMod) );
		modp = mods[i];
		modp->mod_op = ml->sml_op | LDAP_MOD_BVALUES;

		/* Take ownership of original type. */
		modp->mod_type = ml->sml_type.bv_val;
		ml->sml_type.bv_val = NULL;

		if ( ml->sml_bvalues != NULL ) {
			for( j = 0; ml->sml_bvalues[j].bv_val != NULL; j++ )
				;
			modp->mod_bvalues = (struct berval **)ch_malloc( (j + 1) *
				sizeof(struct berval *) );
			for( j = 0; ml->sml_bvalues[j].bv_val != NULL; j++ ) {
				/* Take ownership of original values. */
				modp->mod_bvalues[j] = (struct berval *)ch_malloc( sizeof(struct berval) );
				modp->mod_bvalues[j]->bv_len = ml->sml_bvalues[j].bv_len;
				modp->mod_bvalues[j]->bv_val = ml->sml_bvalues[j].bv_val;
				ml->sml_bvalues[j].bv_len = 0;
				ml->sml_bvalues[j].bv_val = NULL;
			}
			modp->mod_bvalues[j] = NULL;
		} else {
			modp->mod_bvalues = NULL;
		}
		i++;
	}

	mods[i] = NULL;

	slap_mods_free( modlist );
	*pmodlist = NULL;

	return mods;
#else
	return NULL;
#endif
}

/*
 * Convert a potentially modified array of LDAPMods back to a
 * Modification list. 
 * 
 * The returned Modification list contains pointers into the
 * LDAPMods array; the latter MUST be freed with
 * slapi_int_free_ldapmods() (see below).
 */
Modifications *slapi_int_ldapmods2modifications (LDAPMod **mods)
{
#ifdef LDAP_SLAPI
	Modifications *modlist = NULL, **modtail;
	LDAPMod **modp;

	modtail = &modlist;

	for( modp = mods; *modp != NULL; modp++ ) {
		Modifications *mod;
		int i;
		char **p;
		struct berval **bvp;

		mod = (Modifications *) ch_malloc( sizeof(Modifications) );
		mod->sml_op = (*modp)->mod_op & (~LDAP_MOD_BVALUES);
		mod->sml_type.bv_val = (*modp)->mod_type;
		mod->sml_type.bv_len = strlen( mod->sml_type.bv_val );
		mod->sml_desc = NULL;
		mod->sml_next = NULL;

		if ( (*modp)->mod_op & LDAP_MOD_BVALUES ) {
			for( i = 0, bvp = (*modp)->mod_bvalues; bvp != NULL && *bvp != NULL; bvp++, i++ )
				;
		} else {
			for( i = 0, p = (*modp)->mod_values; p != NULL && *p != NULL; p++, i++ )
				;
		}

		if ( i == 0 ) {
			mod->sml_bvalues = NULL;
		} else {
			mod->sml_bvalues = (BerVarray) ch_malloc( (i + 1) * sizeof(struct berval) );

			/* NB: This implicitly trusts a plugin to return valid modifications. */
			if ( (*modp)->mod_op & LDAP_MOD_BVALUES ) {
				for( i = 0, bvp = (*modp)->mod_bvalues; bvp != NULL && *bvp != NULL; bvp++, i++ ) {
					mod->sml_bvalues[i].bv_val = (*bvp)->bv_val;
					mod->sml_bvalues[i].bv_len = (*bvp)->bv_len;
				}
			} else {
				for( i = 0, p = (*modp)->mod_values; p != NULL && *p != NULL; p++, i++ ) {
					mod->sml_bvalues[i].bv_val = *p;
					mod->sml_bvalues[i].bv_len = strlen( *p );
				}
			}
			mod->sml_bvalues[i].bv_val = NULL;
			mod->sml_bvalues[i].bv_len = 0;
		}
		mod->sml_nvalues = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;
	}
	
	return modlist;
#else
	return NULL;
#endif 
}

/*
 * This function only frees the parts of the mods array that
 * are not shared with the Modification list that was created
 * by slapi_int_ldapmods2modifications(). 
 *
 */
void slapi_int_free_ldapmods (LDAPMod **mods)
{
#ifdef LDAP_SLAPI
	int i, j;

	if (mods == NULL)
		return;

	for ( i = 0; mods[i] != NULL; i++ ) {
		/*
		 * Don't free values themselves; they're owned by the
		 * Modification list. Do free the containing array.
		 */
		if ( mods[i]->mod_op & LDAP_MOD_BVALUES ) {
			for ( j = 0; mods[i]->mod_bvalues != NULL && mods[i]->mod_bvalues[j] != NULL; j++ ) {
				ch_free( mods[i]->mod_bvalues[j] );
			}
			ch_free( mods[i]->mod_bvalues );
		} else {
			ch_free( mods[i]->mod_values );
		}
		/* Don't free type, for same reasons. */
		ch_free( mods[i] );
	}
	ch_free( mods );
#endif /* LDAP_SLAPI */
}

/*
 * Sun ONE DS 5.x computed attribute support. Computed attributes
 * allow for dynamically generated operational attributes, a very
 * useful thing indeed.
 */

/*
 * Write the computed attribute to a BerElement. Complementary 
 * functions need to be defined for anything that replaces 
 * op->o_callback->sc_sendentry, if you wish to make computed
 * attributes available to it.
 */
int slapi_int_compute_output_ber(computed_attr_context *c, Slapi_Attr *a, Slapi_Entry *e)
{
#ifdef LDAP_SLAPI
	Operation *op = NULL;
	BerElement *ber;
	AttributeDescription *desc = NULL;
	int rc;
	int i;

	if ( c == NULL ) {
		return 1;
	}

	if ( a == NULL ) {
		return 1;
	}

	if ( e == NULL ) {
		return 1;
	}

	rc = slapi_pblock_get( c->cac_pb, SLAPI_OPERATION, (void *)&op );
	if ( rc != 0 || op == NULL ) {
		return rc;
	}

	ber = (BerElement *)c->cac_private;
	desc = a->a_desc;

	if ( c->cac_attrs == NULL ) {
		/* All attrs request, skip operational attributes */
		if ( is_at_operational( desc->ad_type ) ) {
			return 0;
		}
	} else {
		/* Specific attrs requested */
		if ( is_at_operational( desc->ad_type ) ) {
			if ( !c->cac_opattrs && !ad_inlist( desc, c->cac_attrs ) ) {
				return 0;
			}
		} else {
			if ( !c->cac_userattrs && !ad_inlist( desc, c->cac_attrs ) ) {
				return 0;
			}
		}
	}

	if ( !access_allowed( op, e, desc, NULL, ACL_READ, &c->cac_acl_state) ) {
		slapi_log_error( SLAPI_LOG_ACL, "slapi_int_compute_output_ber",
			"acl: access to attribute %s not allowed\n",
			desc->ad_cname.bv_val );
		return 0;
	}

	rc = ber_printf( ber, "{O[" /*]}*/ , &desc->ad_cname );
	if (rc == -1 ) {
		slapi_log_error( SLAPI_LOG_BER, "slapi_int_compute_output_ber",
			"ber_printf failed\n");
		return 1;
	}

	if ( !c->cac_attrsonly ) {
		for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			if ( !access_allowed( op, e,
				desc, &a->a_vals[i], ACL_READ, &c->cac_acl_state)) {
				slapi_log_error( SLAPI_LOG_ACL, "slapi_int_compute_output_ber",
					"conn %lu "
					"acl: access to %s, value %d not allowed\n",
					op->o_connid, desc->ad_cname.bv_val, i  );
				continue;
			}
	
			if (( rc = ber_printf( ber, "O", &a->a_vals[i] )) == -1 ) {
				slapi_log_error( SLAPI_LOG_BER, "slapi_int_compute_output_ber",
					"ber_printf failed\n");
				return 1;
			}
		}
	}

	if (( rc = ber_printf( ber, /*{[*/ "]N}" )) == -1 ) {
		slapi_log_error( SLAPI_LOG_BER, "slapi_int_compute_output_ber",
			"ber_printf failed\n" );
		return 1;
	}

	return 0;
#else
	return 1;
#endif
}

/*
 * For some reason Sun don't use the normal plugin mechanism
 * registration path to register an "evaluator" function (an
 * "evaluator" is responsible for adding computed attributes;
 * the nomenclature is somewhat confusing).
 *
 * As such slapi_compute_add_evaluator() registers the 
 * function directly.
 */
int slapi_compute_add_evaluator(slapi_compute_callback_t function)
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pPlugin = NULL;
	int rc;

	pPlugin = slapi_pblock_new();
	if ( pPlugin == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	rc = slapi_pblock_set( pPlugin, SLAPI_PLUGIN_TYPE, (void *)SLAPI_PLUGIN_OBJECT );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

	rc = slapi_pblock_set( pPlugin, SLAPI_PLUGIN_COMPUTE_EVALUATOR_FN, (void *)function );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

	rc = slapi_int_register_plugin( NULL, pPlugin );
	if ( rc != 0 ) {
		rc = LDAP_OTHER;
		goto done;
	}

done:
	if ( rc != LDAP_SUCCESS ) {
		if ( pPlugin != NULL ) {
			slapi_pblock_destroy( pPlugin );
		}
		return -1;
	}

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/*
 * See notes above regarding slapi_compute_add_evaluator().
 */
int slapi_compute_add_search_rewriter(slapi_search_rewrite_callback_t function)
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pPlugin = NULL;
	int rc;

	pPlugin = slapi_pblock_new();
	if ( pPlugin == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto done;
	}

	rc = slapi_pblock_set( pPlugin, SLAPI_PLUGIN_TYPE, (void *)SLAPI_PLUGIN_OBJECT );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

	rc = slapi_pblock_set( pPlugin, SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN, (void *)function );
	if ( rc != LDAP_SUCCESS ) {
		goto done;
	}

	rc = slapi_int_register_plugin( NULL, pPlugin );
	if ( rc != 0 ) {
		rc = LDAP_OTHER;
		goto done;
	}

done:
	if ( rc != LDAP_SUCCESS ) {
		if ( pPlugin != NULL ) {
			slapi_pblock_destroy( pPlugin );
		}
		return -1;
	}

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/*
 * Call compute evaluators
 */
int compute_evaluator(computed_attr_context *c, char *type, Slapi_Entry *e, slapi_compute_output_t outputfn)
{
#ifdef LDAP_SLAPI
	int rc = 0;
	slapi_compute_callback_t *pGetPlugin, *tmpPlugin;

	rc = slapi_int_get_plugins( NULL, SLAPI_PLUGIN_COMPUTE_EVALUATOR_FN, (SLAPI_FUNC **)&tmpPlugin );
	if ( rc != LDAP_SUCCESS || tmpPlugin == NULL ) {
		/* Nothing to do; front-end should ignore. */
		return 0;
	}

	for ( pGetPlugin = tmpPlugin; *pGetPlugin != NULL; pGetPlugin++ ) {
		/*
		 * -1: no attribute matched requested type
		 *  0: one attribute matched
		 * >0: error happened
		 */
		rc = (*pGetPlugin)( c, type, e, outputfn );
		if ( rc > 0 ) {
			break;
		}
	}

	slapi_ch_free( (void **)&tmpPlugin );

	return rc;
#else
	return 1;
#endif /* LDAP_SLAPI */
}

int compute_rewrite_search_filter(Slapi_PBlock *pb)
{
#ifdef LDAP_SLAPI
	Backend *be;
	int rc;

	rc = slapi_pblock_get( pb, SLAPI_BACKEND, (void *)&be );
	if ( rc != 0 ) {
		return rc;
	}

	return slapi_int_call_plugins( be, SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN, pb );
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/*
 * New API to provide the plugin with access to the search
 * pblock. Have informed Sun DS team.
 */
int slapi_x_compute_get_pblock(computed_attr_context *c, Slapi_PBlock **pb)
{
#ifdef LDAP_SLAPI
	if ( c == NULL )
		return -1;

	if ( c->cac_pb == NULL )
		return -1;

	*pb = c->cac_pb;

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_Mutex *slapi_new_mutex( void )
{
#ifdef LDAP_SLAPI
	Slapi_Mutex *m;

	m = (Slapi_Mutex *)slapi_ch_malloc( sizeof(*m) );
	if ( ldap_pvt_thread_mutex_init( &m->mutex ) != 0 ) {
		slapi_ch_free( (void **)&m );
		return NULL;
	}

	return m;
#else
	return NULL;
#endif
}

void slapi_destroy_mutex( Slapi_Mutex *mutex )
{
#ifdef LDAP_SLAPI
	if ( mutex != NULL ) {
		ldap_pvt_thread_mutex_destroy( &mutex->mutex );
		slapi_ch_free( (void **)&mutex);
	}
#endif
}

void slapi_lock_mutex( Slapi_Mutex *mutex )
{
#ifdef LDAP_SLAPI
	ldap_pvt_thread_mutex_lock( &mutex->mutex );
#endif
}

int slapi_unlock_mutex( Slapi_Mutex *mutex )
{
#ifdef LDAP_SLAPI
	return ldap_pvt_thread_mutex_unlock( &mutex->mutex );
#else
	return -1;
#endif
}

Slapi_CondVar *slapi_new_condvar( Slapi_Mutex *mutex )
{
#ifdef LDAP_SLAPI
	Slapi_CondVar *cv;

	if ( mutex == NULL ) {
		return NULL;
	}

	cv = (Slapi_CondVar *)slapi_ch_malloc( sizeof(*cv) );
	if ( ldap_pvt_thread_cond_init( &cv->cond ) != 0 ) {
		slapi_ch_free( (void **)&cv );
		return NULL;
	}

	/* XXX struct copy */
	cv->mutex = mutex->mutex;

	return cv;
#else	
	return NULL;
#endif
}

void slapi_destroy_condvar( Slapi_CondVar *cvar )
{
#ifdef LDAP_SLAPI
	if ( cvar != NULL ) {
		ldap_pvt_thread_cond_destroy( &cvar->cond );
		slapi_ch_free( (void **)&cvar );
	}
#endif
}

int slapi_wait_condvar( Slapi_CondVar *cvar, struct timeval *timeout )
{
#ifdef LDAP_SLAPI
	if ( cvar == NULL ) {
		return -1;
	}

	return ldap_pvt_thread_cond_wait( &cvar->cond, &cvar->mutex );
#else
	return -1;
#endif
}

int slapi_notify_condvar( Slapi_CondVar *cvar, int notify_all )
{
#ifdef LDAP_SLAPI
	if ( cvar == NULL ) {
		return -1;
	}

	if ( notify_all ) {
		return ldap_pvt_thread_cond_broadcast( &cvar->cond );
	}

	return ldap_pvt_thread_cond_signal( &cvar->cond );
#else
	return -1;
#endif
}

int slapi_int_access_allowed( Operation *op,
	Entry *entry,
	AttributeDescription *desc,
	struct berval *val,
	slap_access_t access,
	AccessControlState *state )
{
#ifdef LDAP_SLAPI
	int rc, slap_access = 0;
	slapi_acl_callback_t *pGetPlugin, *tmpPlugin;

	if ( op->o_pb == NULL ) {
		/* internal operation */
		return 1;
	}

	switch ( access ) {
	case ACL_WRITE:
		slap_access |= SLAPI_ACL_ADD | SLAPI_ACL_DELETE | SLAPI_ACL_WRITE;
		break;
	case ACL_READ:
		slap_access |= SLAPI_ACL_READ;
		break;
	case ACL_SEARCH:
		slap_access |= SLAPI_ACL_SEARCH;
		break;
	case ACL_COMPARE:
                slap_access = ACL_COMPARE;
		break;
	default:
		break;
        }

	rc = slapi_int_get_plugins( op->o_bd, SLAPI_PLUGIN_ACL_ALLOW_ACCESS, (SLAPI_FUNC **)&tmpPlugin );
	if ( rc != LDAP_SUCCESS || tmpPlugin == NULL ) {
		/* nothing to do; allowed access */
		return 1;
	}

	slapi_int_pblock_set_operation( op->o_pb, op );

	rc = 1; /* default allow policy */

	for ( pGetPlugin = tmpPlugin; *pGetPlugin != NULL; pGetPlugin++ ) {
		/*
		 * 0	access denied
		 * 1	access granted
		 */
		rc = (*pGetPlugin)( op->o_pb, entry, desc->ad_cname.bv_val,
					val, slap_access, (void *)state );
		if ( rc == 0 ) {
			break;
		}
	}

	slapi_ch_free( (void **)&tmpPlugin );

	return rc;
#else
	return 1;
#endif /* LDAP_SLAPI */
}

