/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#include "portable.h"
#include "slapi_common.h"

#include <slap.h>
#include <slapi.h>
#include <stdarg.h>
#include <ctype.h>
#include <slap.h>
#include <unistd.h>
#include <ldap_pvt.h>

struct berval *ns_get_supported_extop( int );

#ifdef _SPARC  
#include <sys/systeminfo.h>
#endif

#include <netdb.h>

/*
 * server start time (should we use a struct timeval also in slapd?
 */
static struct			timeval base_time;
ldap_pvt_thread_mutex_t		slapi_hn_mutex;
ldap_pvt_thread_mutex_t		slapi_time_mutex;

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
#if defined(LDAP_SLAPI)
	Slapi_Entry	*e = NULL;
	char		*pTmpS;

	pTmpS = slapi_ch_strdup( s );
	if ( pTmpS != NULL ) {
		e = str2entry( pTmpS ); 
		slapi_ch_free( pTmpS );
	}

	return e;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_entry2str(
	Slapi_Entry	*e, 
	int		*len ) 
{
#if defined(LDAP_SLAPI)
	char		*ret;

	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	ret = entry2str( e, len );
	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );

	return ret;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_entry_get_dn( Slapi_Entry *e ) 
{
#if defined(LDAP_SLAPI)
	return e->e_name.bv_val;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_entry_set_dn(
	Slapi_Entry	*e, 
	char		*ldn )
{
#if defined(LDAP_SLAPI)
	struct berval	dn = { 0, NULL };

	dn.bv_val = ldn;
	dn.bv_len = strlen( ldn );

	dnPrettyNormal( NULL, &dn, &e->e_name, &e->e_nname );
#endif /* defined(LDAP_SLAPI) */
}

Slapi_Entry *
slapi_entry_dup( Slapi_Entry *e ) 
{
#if defined(LDAP_SLAPI)
	char		*tmp = NULL;
	Slapi_Entry	*tmpEnt;
	int		len = 0;
	
	tmp = slapi_entry2str( e, &len );
	if ( tmp == NULL ) {
		return (Slapi_Entry *)NULL;
	}

	tmpEnt = (Slapi_Entry *)str2entry( tmp );
	if ( tmpEnt == NULL ) { 
		slapi_ch_free( tmp );
		return (Slapi_Entry *)NULL;
	}
	
	if (tmp != NULL) {
		slapi_ch_free( tmp );
	}

	return tmpEnt;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

int 
slapi_entry_attr_delete(
	Slapi_Entry	*e, 		
	char		*type ) 
{
#if defined(LDAP_SLAPI)
	AttributeDescription	*ad;
	const char		*text;

	if ( slap_str2ad( type, &ad, &text ) != LDAP_SUCCESS ) {
		return 1;	/* LDAP_NO_SUCH_ATTRIBUTE */
	}

	if ( attr_delete( &e->e_attrs, ad ) == LDAP_SUCCESS ) {
		return 0;	/* attribute is deleted */
	} else {
		return -1;	/* something went wrong */
	}
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}

Slapi_Entry *
slapi_entry_alloc( void ) 
{
#if defined(LDAP_SLAPI)
	return (Slapi_Entry *)slapi_ch_calloc( 1, sizeof(Slapi_Entry) );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_entry_free( Slapi_Entry *e ) 
{
#if defined(LDAP_SLAPI)
	entry_free( e );
#endif /* defined(LDAP_SLAPI) */
}

int 
slapi_entry_attr_merge(
	Slapi_Entry	*e, 
	char		*type, 
	struct berval	**vals ) 
{
#if defined(LDAP_SLAPI)
	AttributeDescription	*ad;
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
	
	rc = attr_merge( e, ad, bv );
	ch_free( bv );

	return rc;
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}

int
slapi_entry_attr_find(
	Slapi_Entry	*e, 
	char		*type, 
	Slapi_Attr	**attr ) 
{
#if defined(LDAP_SLAPI)
	AttributeDescription	*ad;
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
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
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
#if defined(LDAP_SLAPI)
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
		bv[j] = (struct berval *)ch_malloc( sizeof(struct berval) );
		bv[j]->bv_val = ch_strdup( attr->a_vals[j].bv_val );
		bv[j]->bv_len = attr->a_vals[j].bv_len;
	}
	bv[j] = NULL;
	
	*vals = (struct berval **)bv;

	return 0;
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_dn_normalize( char *dn ) 
{
#if defined(LDAP_SLAPI)
	struct berval	bdn;
	struct berval	ndn;

	assert( dn != NULL );
	
	bdn.bv_val = dn;
	bdn.bv_len = strlen( dn );

	dnNormalize2( NULL, &bdn, &ndn );

	/*
	 * FIXME: ain't it safe to set dn = ndn.bv_val ?
	 */
	dn = ch_strdup( ndn.bv_val );
	ch_free( ndn.bv_val );
	
	return dn;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

/*
 * FIXME: this function is dangerous and should be deprecated;
 * DN normalization is a lot more than lower-casing, and BTW
 * OpenLDAP's DN normalization for case insensitive attributes
 * is already lower case
 */
char *
slapi_dn_normalize_case( char *dn ) 
{
#if defined(LDAP_SLAPI)
	slapi_dn_normalize( dn );
	ldap_pvt_str2lower( dn );

	return dn;
#else /* defined(LDAP_SLAPI) */
	return NULL;
#endif /* defined(LDAP_SLAPI) */
}

int 
slapi_dn_issuffix(
	char		*dn, 
	char		*suffix )
{
#if defined(LDAP_SLAPI)
	struct berval	bdn, ndn;
	struct berval	bsuffix, nsuffix;

	assert( dn != NULL );
	assert( suffix != NULL );

	bdn.bv_val = dn;
	bdn.bv_len = strlen( dn );

	bsuffix.bv_val = suffix;
	bsuffix.bv_len = strlen( suffix );

	dnNormalize2( NULL, &bdn, &ndn );
	dnNormalize2( NULL, &bsuffix, &nsuffix );

	return dnIsSuffix( &ndn, &nsuffix );
#else /* !defined(LDAP_SLAPI) */
	return 0;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_dn_ignore_case( char *dn )
{       
#if defined(LDAP_SLAPI)
	return slapi_dn_normalize_case( dn );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_ch_malloc( unsigned long size ) 
{
#if defined(LDAP_SLAPI)
	return ch_malloc( size );	
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_ch_free( void *ptr ) 
{
#if defined(LDAP_SLAPI)
#if 0
	if ( ptr != NULL )	/* not required ... */
#endif /* 0 */
		ch_free( ptr );
#endif /* defined(LDAP_SLAPI) */
}

char *
slapi_ch_calloc(
	unsigned long nelem, 
	unsigned long size ) 
{
#if defined(LDAP_SLAPI)
	return ch_calloc( nelem, size );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_ch_realloc(
	char *block, 
	unsigned long size ) 
{
#if defined(LDAP_SLAPI)
	return ch_realloc( block, size );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

char *
slapi_ch_strdup( char *s ) 
{
#if defined(LDAP_SLAPI)
	return ch_strdup( (const char *)s );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

size_t
slapi_ch_stlen( char *s ) 
{
#if defined(LDAP_SLAPI)
	return strlen( (const char *)s );
#else /* !defined(LDAP_SLAPI) */
	return 0;
#endif /* !defined(LDAP_SLAPI) */
}

int 
slapi_control_present(
	LDAPControl	**controls, 
	char		*oid, 
	struct berval	**val, 
	int		*iscritical ) 
{
#if defined(LDAP_SLAPI)
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
					slapi_ch_free( pTmpBval );
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
#else /* !defined(LDAP_SLAPI) */
	return 0;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_register_supported_control(
	char		*controloid, 
	unsigned long	controlops )
{
#if defined(LDAP_SLAPI)
	/* FIXME -- can not add controls to openLDAP dynamically */
	slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_CONTROLS",
			"can not add controls to openLDAP dynamically\n" );
#endif /* defined(LDAP_SLAPI) */
}

int 
slapi_get_supported_controls(
	char		***ctrloidsp, 
	unsigned long	**ctrlopsp ) 
{
#if defined(LDAP_SLAPI)
	int		i, n;
	int		rc = 1;
	char		**oids = NULL;
	unsigned long	*masks = NULL;

	for (n = 0; get_supported_ctrl( n ) != NULL; n++) {
		; /* count them */
	}
	
	if ( n == 0 ) {
		/* no controls */
		*ctrloidsp = NULL;
		*ctrlopsp = NULL;
		return LDAP_SUCCESS;
	}


	oids = (char **)slapi_ch_malloc( (n + 1) * sizeof(char *) );
	if ( oids == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto error_return;
	}

	masks = (unsigned long *)slapi_ch_malloc( n * sizeof(int) );
	if ( masks == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto error_return;
	}

	for ( i = 0; i < n; i++ ) {
		/*
		 * FIXME: Netscape's specification says nothing about
		 * memory; should we copy the OIDs or return pointers
		 * to internal values? In OpenLDAP the latter is safe
		 * since we do not allow to register coltrols runtime
		 */
		oids[ i ] = ch_strdup( get_supported_ctrl( i ) );
		if ( oids[ i ] == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto error_return;
		}
		masks[ i ] = (unsigned long)get_supported_ctrl_mask( i );
	}

	*ctrloidsp = oids;
	*ctrlopsp = masks;
	return LDAP_SUCCESS;

error_return:
	if ( rc != LDAP_SUCCESS ) {
		for ( i = 0; oids != NULL && oids[ i ] != NULL; i++ ) {
			ch_free( oids[ i ] );
		}
		ch_free( oids );
		ch_free( masks );
	}

	return rc;
#else /* !defined(LDAP_SLAPI) */
	return 1;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_register_supported_saslmechanism( char *mechanism )
{
#if defined(LDAP_SLAPI)
	/* FIXME -- can not add saslmechanism to openLDAP dynamically */
	slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_SASL",
			"can not add saslmechanism to openLDAP dynamically\n" );
#endif /* defined(LDAP_SLAPI) */
}

char **
slapi_get_supported_saslmechanisms( void )
{
#if defined(LDAP_SLAPI)
	/* FIXME -- can not get the saslmechanism wihtout a connection. */
	slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_SASL",
			"can not get the saslmechanism "
			"wihtout a connection\n" );
	return NULL;
#else /* defined(LDAP_SLAPI) */
	return NULL;
#endif /* defined(LDAP_SLAPI) */
}

char **
slapi_get_supported_extended_ops( void )
{
#if defined(LDAP_SLAPI)
	int		i, j, k;
	char		**ppExtOpOID = NULL;
	int		numExtOps = 0;

	for ( i = 0; get_supported_extop( i ) != NULL; i++ ) {
		;
	}
	
	for ( j = 0; ns_get_supported_extop( j ) != NULL; j++ ) {
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

		bv = ns_get_supported_extop( k );
		assert( bv != NULL );

		ppExtOpOID[ i + k ] = bv->bv_val;
	}
	ppExtOpOID[ i + k ] = NULL;

	return ppExtOpOID;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
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
#if defined(LDAP_SLAPI)
	Connection	*conn;
	Operation	*op;
	struct berval	*s;
	char		*extOID = NULL;
	struct berval	*extValue = NULL;
	int		rc;

	slapi_pblock_get( pb, SLAPI_CONNECTION, &conn );
	slapi_pblock_get( pb, SLAPI_OPERATION, &op );
	if ( err == LDAP_SASL_BIND_IN_PROGRESS ) {
		slapi_pblock_get( pb, SLAPI_BIND_RET_SASLCREDS, &s );
		rc = LDAP_SASL_BIND_IN_PROGRESS;
		send_ldap_sasl( conn, op, rc, NULL, NULL, NULL, NULL, s );
		return;
	}

	slapi_pblock_get( pb, SLAPI_EXT_OP_RET_OID, &extOID );
	if ( extOID != NULL ) {
		slapi_pblock_get( pb, SLAPI_EXT_OP_RET_VALUE, &extValue );
		slapi_send_ldap_extended_response( conn, op, err, extOID,
				extValue );
		return;
	}

	send_ldap_result( conn, op, err, matched, text, NULL, NULL );
#endif /* defined(LDAP_SLAPI) */
}

int 
slapi_send_ldap_search_entry(
	Slapi_PBlock	*pb, 
	Slapi_Entry	*e, 
	LDAPControl	**ectrls, 
	char		**attrs, 
	int		attrsonly )
{
#if defined(LDAP_SLAPI)
	Backend		*be;
	Connection	*pConn;
	Operation	*pOp;
	int		rc;

	int		i;
	AttributeName	*an = NULL;
	const char	*text;

	for ( i = 0; attrs[ i ] != NULL; i++ ) {
		; /* empty */
	}

	if ( i > 0 ) {
		an = (AttributeName *) ch_malloc( i * sizeof(AttributeName) );
		for ( i = 0; attrs[i] != NULL; i++ ) {
			an[i].an_name.bv_val = ch_strdup( attrs[i] );
			an[i].an_name.bv_len = strlen( attrs[i] );
			an[i].an_desc = NULL;
			if( slap_bv2ad( &an[i].an_name, &an[i].an_desc, &text ) != LDAP_SUCCESS)
				return -1;
		}
	}

	if ( ( rc = slapi_pblock_get( pb, SLAPI_BACKEND, (void *)&be ) != 0 ) ||
			( rc = slapi_pblock_get( pb, SLAPI_CONNECTION, (void *)&pConn) != 0 ) ||
			( rc = slapi_pblock_get( pb, SLAPI_OPERATION, (void *)&pOp) != 0 ) ) {
		rc = LDAP_OTHER;
	} else {
		rc = send_search_entry( be, pConn, pOp, e, an, attrsonly, NULL );
	}

	return rc;

#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}


Slapi_Filter *
slapi_str2filter( char *str ) 
{
#if defined(LDAP_SLAPI)
	return str2filter( str );
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

void 
slapi_filter_free(
	Slapi_Filter	*f, 
	int		recurse ) 
{
#if defined(LDAP_SLAPI)
	filter_free( f );
#endif /* defined(LDAP_SLAPI) */
}

int 
slapi_filter_get_choice( Slapi_Filter *f )
{
#if defined(LDAP_SLAPI)
	int		rc;

	if ( f != NULL ) {
		rc = f->f_choice;
	} else {
		rc = 0;
	}

	return rc;
#else /* !defined(LDAP_SLAPI) */
	return -1;		/* invalid filter type */
#endif /* !defined(LDAP_SLAPI) */
}

int 
slapi_filter_get_ava(
	Slapi_Filter	*f, 
	char		**type, 
	struct berval	**bval )
{
#if defined(LDAP_SLAPI)
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
		*type = slapi_ch_strdup( f->f_un.f_un_ava->aa_desc->ad_cname.bv_val );
		if ( *type == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto done;
		}

		*bval = (struct berval *)slapi_ch_malloc( sizeof(struct berval) );
		if ( *bval == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto done;
		}

		(*bval)->bv_len = f->f_un.f_un_ava->aa_value.bv_len;
		(*bval)->bv_val = slapi_ch_strdup( f->f_un.f_un_ava->aa_value.bv_val );
		if ( (*bval)->bv_val == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto done;
		}
	} else { /* filter type not supported */
		rc = -1;
	}

done:
	if ( rc != LDAP_SUCCESS ) {
		if ( *bval ) {
			ch_free( *bval );
			*bval = NULL;
		}

		if ( *type ) {
			ch_free( *type );
			*type = NULL;
		}
	}

	return rc;
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}

Slapi_Filter *
slapi_filter_list_first( Slapi_Filter *f )
{
#if defined(LDAP_SLAPI)
	int		ftype;

	if ( f == NULL ) {
		return NULL;
	}

	ftype = f->f_choice;
	if ( ftype == LDAP_FILTER_AND
			|| ftype == LDAP_FILTER_OR
			|| ftype == LDAP_FILTER_NOT ) {
		return (Slapi_Filter *)f->f_and;
	} else {
		return NULL;
	}
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

Slapi_Filter *
slapi_filter_list_next(
	Slapi_Filter	*f, 
	Slapi_Filter	*fprev )
{
#if defined(LDAP_SLAPI)
	int		ftype;

	if ( f == NULL ) {
		return NULL;
	}

	ftype = f->f_choice;
	if ( ftype == LDAP_FILTER_AND
			|| ftype == LDAP_FILTER_OR
			|| ftype == LDAP_FILTER_NOT ) {
		if ( f->f_and == fprev ) {
			return f->f_and->f_next;
		}
	}

	return NULL;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

int 
slapi_send_ldap_extended_response(
	Connection	*conn, 
	Operation	*op,
	int		errornum, 
	char		*respName,
	struct berval	*response )
{
#if defined(LDAP_SLAPI)
	send_ldap_extended( conn,op, errornum, NULL, NULL, NULL,
			respName,response, NULL );
	return LDAP_SUCCESS;
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}

int 
slapi_pw_find(
	struct berval	**vals, 
	struct berval	*v ) 
{
#if defined(LDAP_SLAPI)
	/*
	 * FIXME: what's the point?
	 */
	return 1;
#else /* !defined(LDAP_SLAPI) */
	return 1;
#endif /* !defined(LDAP_SLAPI) */
}
             
char *
slapi_get_hostname( void ) 
{
#if defined(LDAP_SLAPI)
	char		*hn = NULL;

	/*
	 * FIXME: I'd prefer a different check ...
	 */
#if defined _SPARC 
	hn = (char *)slapi_ch_malloc( MAX_HOSTNAME );
	if ( hn == NULL) {
		slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_SYSINFO",
				"can't malloc memory for hostname\n" );
		hn = NULL;
		
	} else if ( sysinfo( SI_HOSTNAME, hn, MAX_HOSTNAME ) < 0 ) {
		slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_SYSINFO",
				"can't get hostname\n" );
		slapi_ch_free( hn );
		hn = NULL;
	}
#else /* !_SPARC */
	static int	been_here = 0;   
	static char	*static_hn = NULL;

	ldap_pvt_thread_mutex_lock( &slapi_hn_mutex );
	if ( !been_here ) {
		static_hn = (char *)slapi_ch_malloc( MAX_HOSTNAME );
		if ( static_hn == NULL) {
			slapi_log_error( SLAPI_LOG_FATAL, "SLAPI_SYSINFO",
					"can't malloc memory for hostname\n" );
			static_hn = NULL;
			ldap_pvt_thread_mutex_unlock( &slapi_hn_mutex );

			return hn;
			
		} else { 
			if ( gethostname( static_hn, MAX_HOSTNAME ) != 0 ) {
				slapi_log_error( SLAPI_LOG_FATAL,
						"SLAPI_SYSINFO",
						"can't get hostname\n" );
				slapi_ch_free( static_hn );
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
#endif /* !_SPARC */

	return hn;
#else /* !defined(LDAP_SLAPI) */
	return NULL;
#endif /* !defined(LDAP_SLAPI) */
}

/*
 * FIXME: this should go in an appropriate header ...
 */
extern int vLogError( int level, char *subsystem, char *fmt, va_list arglist );

int 
slapi_log_error(
	int		severity, 
	char		*subsystem, 
	char		*fmt, 
	... ) 
{
#if defined(LDAP_SLAPI)
	int		rc = LDAP_SUCCESS;
	va_list		arglist;

	va_start( arglist, fmt );
	rc = vLogError( severity, subsystem, fmt, arglist );
	va_end( arglist );

	return rc;
#else /* !defined(LDAP_SLAPI) */
	return -1;
#endif /* !defined(LDAP_SLAPI) */
}


unsigned long
slapi_timer_current_time( void ) 
{
#if defined(LDAP_SLAPI)
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
#else /* !defined(LDAP_SLAPI) */
	return 0;
#endif /* !defined(LDAP_SLAPI) */
}

/*
 * FIXME ?
 */
unsigned long
slapi_timer_get_time( char *label ) 
{
#if defined(LDAP_SLAPI)
	unsigned long start = slapi_timer_current_time();
	printf("%10ld %10ld usec %s\n", start, 0, label);
	return start;
#else /* !defined(LDAP_SLAPI) */
	return 0;
#endif /* !defined(LDAP_SLAPI) */
}

/*
 * FIXME ?
 */
void
slapi_timer_elapsed_time(
	char *label,
	unsigned long start ) 
{
#if defined(LDAP_SLAPI)
	unsigned long stop = slapi_timer_current_time();
	printf ("%10ld %10ld usec %s\n", stop, stop - start, label);
#endif /* defined(LDAP_SLAPI) */
}

void
slapi_free_search_results_internal( Slapi_PBlock *pb ) 
{
#if defined(LDAP_SLAPI)
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
	
	slapi_ch_free( entries );
#endif /* defined(LDAP_SLAPI) */
}

/*
 * Internal API to prime a Slapi_PBlock with a Backend.
 */
int slapi_backend_set_pb( Slapi_PBlock *pb, Backend *be )
{
#if defined(LDAP_SLAPI)
	int rc;

	rc = slapi_pblock_set(pb, SLAPI_BACKEND, (void *)be);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_BE_TYPE, (void *)be->bd_info->bi_type);
	if (rc != LDAP_SUCCESS)
		return rc;
#else
	return -1;
#endif /* defined(LDAP_SLAPI) */
}

/*
 * Internal API to prime a Slapi_PBlock with a Connection.
 */
int slapi_connection_set_pb( Slapi_PBlock *pb, Connection *conn )
{
#if defined(LDAP_SLAPI)
	char *connAuthType;
	size_t len;
	int rc;

	rc = slapi_pblock_set(pb, SLAPI_CONNECTION, (void *)conn);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_CONN_ID, (void *)conn->c_connid);
	if (rc != LDAP_SUCCESS)
		return rc;

	switch (conn->c_authz.sai_method) {
	case LDAP_AUTH_SASL: 
		len = sizeof(SLAPD_AUTH_SASL) + conn->c_authz.sai_mech.bv_len;
		connAuthType = slapi_ch_malloc(len);
		snprintf(connAuthType, len, "%s%s", SLAPD_AUTH_SASL, conn->c_authz.sai_mech.bv_val);
		break;
	case LDAP_AUTH_SIMPLE:
		connAuthType = slapi_ch_strdup(SLAPD_AUTH_SIMPLE);
		break;
	case LDAP_AUTH_NONE:
		connAuthType = slapi_ch_strdup(SLAPD_AUTH_NONE);
		break;
	default:
		connAuthType = NULL;
		break;
	}
	if (conn->c_is_tls && connAuthType == NULL) {
		connAuthType = slapi_ch_strdup(SLAPD_AUTH_SSL);
	}
	if (connAuthType != NULL) {
		rc = slapi_pblock_set(pb, SLAPI_CONN_AUTHTYPE, (void *)connAuthType);
		if (rc != LDAP_SUCCESS)
			return rc;
	}
	if (conn->c_authz.sai_dn.bv_val != NULL) {
		char *connDn = slapi_ch_strdup(conn->c_authz.sai_dn.bv_val);
		rc = slapi_pblock_set(pb, SLAPI_CONN_DN, (void *)connDn);
		if (rc != LDAP_SUCCESS)
			return rc;
	}
	return LDAP_SUCCESS;
#else
	return -1;
#endif /* defined(LDAP_SLAPI) */
}

/*
 * Internal API to prime a Slapi_PBlock with an Operation.
 */
int slapi_operation_set_pb( Slapi_PBlock *pb, Operation *op )
{
#if defined(LDAP_SLAPI)
	int isRoot = 0;
	int isUpdateDn = 0;
	int rc;
	Backend *be;

	if (slapi_pblock_get(pb, SLAPI_BACKEND, (void *)&be) != 0) {
		be = NULL;
	}
	if (be != NULL) {
		isRoot = be_isroot(be, &op->o_ndn);
		isUpdateDn = be_isupdate(be, &op->o_ndn);
	}
		
	rc = slapi_pblock_set(pb, SLAPI_OPERATION, (void *)op);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_OPINITIATED_TIME, (void *)op->o_time);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, (void *)isRoot);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_REQUESTOR_ISUPDATEDN, (void *)isUpdateDn);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_REQCONTROLS, (void *)op->o_ctrls);
	if (rc != LDAP_SUCCESS)
		return rc;

	rc = slapi_pblock_set(pb, SLAPI_REQUESTOR_DN, (void *)op->o_ndn.bv_val);

	return rc;
#else
	return -1;
#endif
}

int slapi_is_connection_ssl( Slapi_PBlock *pb, int *isSSL )
{
#if defined( LDAP_SLAPI )
	Connection *conn;

	slapi_pblock_get( pb, SLAPI_CONNECTION, &conn );
	*isSSL = conn->c_is_tls;

	return LDAP_SUCCESS;
#else
	return -1;
#endif /* defined(LDAP_SLAPI) */
}
