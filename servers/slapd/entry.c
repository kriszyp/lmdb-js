/* entry.c - routines for dealing with entries */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "ldif.h"

static char		*ebuf;	/* buf returned by entry2str		 */
static char		*ecur;	/* pointer to end of currently used ebuf */
static int		emaxsize;/* max size of ebuf			 */

/*
 * Empty root entry
 */
const Entry slap_entry_root = {
	NOID, { 0, "" }, { 0, "" }, NULL, 0, { 0, "" }, NULL
};

static const struct berval dn_bv = BER_BVC("dn");

int entry_destroy(void)
{
	if ( ebuf ) free( ebuf );
	ebuf = NULL;
	ecur = NULL;
	emaxsize = 0;
	return 0;
}


Entry *
str2entry( char *s )
{
	return str2entry2( s, 1 );
}

Entry *
str2entry2( char *s, int checkvals )
{
	int rc;
	Entry		*e;
	struct berval	*type, *vals, *nvals;
	char 	*freeval;
	AttributeDescription *ad, *ad_prev;
	const char *text;
	char	*next;
	int		attr_cnt;
	int		i, lines;
	Attribute	ahead, *atail;

	/*
	 * LDIF is used as the string format.
	 * An entry looks like this:
	 *
	 *	dn: <dn>\n
	 *	[<attr>:[:] <value>\n]
	 *	[<tab><continuedvalue>\n]*
	 *	...
	 *
	 * If a double colon is used after a type, it means the
	 * following value is encoded as a base 64 string.  This
	 * happens if the value contains a non-printing character
	 * or newline.
	 */

	Debug( LDAP_DEBUG_TRACE, "=> str2entry: \"%s\"\n",
		s ? s : "NULL", 0, 0 );

	/* initialize reader/writer lock */
	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= str2entry NULL (entry allocation failed)\n",
			0, 0, 0 );
		return( NULL );
	}

	/* initialize entry */
	e->e_id = NOID;

	/* dn + attributes */
	atail = &ahead;
	ahead.a_next = NULL;
	ad = NULL;
	ad_prev = NULL;
	attr_cnt = 0;
	next = s;

	lines = ldif_countlines( s );
	type = ch_calloc( 1, (lines+1)*3*sizeof(struct berval)+lines );
	vals = type+lines+1;
	nvals = vals+lines+1;
	freeval = (char *)(nvals+lines+1);
	i = -1;

	/* parse into individual values, record DN */
	while ( (s = ldif_getline( &next )) != NULL ) {
		int freev;
		if ( *s == '\n' || *s == '\0' ) {
			break;
		}
		i++;
		if (i >= lines) {
			Debug( LDAP_DEBUG_TRACE,
				"<= str2entry ran past end of entry\n", 0, 0, 0 );
			goto fail;
		}

		rc = ldif_parse_line2( s, type+i, vals+i, &freev );
		freeval[i] = freev;
		if ( rc ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= str2entry NULL (parse_line)\n", 0, 0, 0 );
			continue;
		}

		if ( type[i].bv_len == dn_bv.bv_len &&
			strcasecmp( type[i].bv_val, dn_bv.bv_val ) == 0 ) {

			if ( e->e_dn != NULL ) {
				Debug( LDAP_DEBUG_ANY, "str2entry: "
					"entry %ld has multiple DNs \"%s\" and \"%s\"\n",
					(long) e->e_id, e->e_dn, vals[i].bv_val );
				goto fail;
			}

			rc = dnPrettyNormal( NULL, &vals[i], &e->e_name, &e->e_nname, NULL );
			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "str2entry: "
					"entry %ld has invalid DN \"%s\"\n",
					(long) e->e_id, vals[i].bv_val, 0 );
				goto fail;
			}
			if ( freeval[i] ) free( vals[i].bv_val );
			vals[i].bv_val = NULL;
			i--;
			continue;
		}
	}
	lines = i+1;

	/* check to make sure there was a dn: line */
	if ( BER_BVISNULL( &e->e_name )) {
		Debug( LDAP_DEBUG_ANY, "str2entry: entry %ld has no dn\n",
			(long) e->e_id, 0, 0 );
		goto fail;
	}

#define bvcasematch(bv1, bv2)	( ((bv1)->bv_len == (bv2)->bv_len) && (strncasecmp((bv1)->bv_val, (bv2)->bv_val, (bv1)->bv_len) == 0) )

	/* Make sure all attributes with multiple values are contiguous */
	if ( checkvals ) {
		int j, k;
		struct berval bv;
		int fv;

		for (i=0; i<lines; i++) {
			for ( j=i+1; j<lines; j++ ) {
				if ( bvcasematch( type+i, type+j )) {
					/* out of order, move intervening attributes down */
					if ( j != i+1 ) {
						bv = vals[j];
						fv = freeval[j];
						for ( k=j; k>i; k-- ) {
							type[k] = type[k-1];
							vals[k] = vals[k-1];
							freeval[k] = freeval[k-1];
						}
						k++;
						type[k] = type[i];
						vals[k] = bv;
						freeval[k] = fv;
					}
					i++;
				}
			}
		}
	}

	for ( i=0; i<=lines; i++ ) {
		ad_prev = ad;
		if ( !ad || ( i<lines && !bvcasematch( type+i, &ad->ad_cname ))) {
			ad = NULL;
			rc = slap_bv2ad( type+i, &ad, &text );

			if( rc != LDAP_SUCCESS ) {
				Debug( slapMode & SLAP_TOOL_MODE
					? LDAP_DEBUG_ANY : LDAP_DEBUG_TRACE,
					"<= str2entry: str2ad(%s): %s\n", type[i].bv_val, text, 0 );
				if( slapMode & SLAP_TOOL_MODE ) {
					goto fail;
				}

				rc = slap_bv2undef_ad( type+i, &ad, &text, 0 );
				if( rc != LDAP_SUCCESS ) {
					Debug( LDAP_DEBUG_ANY,
						"<= str2entry: slap_str2undef_ad(%s): %s\n",
							type[i].bv_val, text, 0 );
					goto fail;
				}
			}

			/* require ';binary' when appropriate (ITS#5071) */
			if ( slap_syntax_is_binary( ad->ad_type->sat_syntax ) && !slap_ad_is_binary( ad ) ) {
				Debug( LDAP_DEBUG_ANY,
					"str2entry: attributeType %s #%d: "
					"needs ';binary' transfer as per syntax %s\n", 
					ad->ad_cname.bv_val, 0,
					ad->ad_type->sat_syntax->ssyn_oid );
				goto fail;
			}
		}

		if (( ad_prev && ad != ad_prev ) || ( i == lines )) {
			int j, k;
			atail->a_next = (Attribute *) ch_malloc( sizeof(Attribute) );
			atail = atail->a_next;
			atail->a_flags = 0;
			atail->a_desc = ad_prev;
			atail->a_vals = ch_malloc( (attr_cnt + 1) * sizeof(struct berval));
			if( ad_prev->ad_type->sat_equality &&
				ad_prev->ad_type->sat_equality->smr_normalize )
				atail->a_nvals = ch_malloc( (attr_cnt + 1) * sizeof(struct berval));
			else
				atail->a_nvals = NULL;
			k = i - attr_cnt;
			for ( j=0; j<attr_cnt; j++ ) {
				if ( freeval[k] )
					atail->a_vals[j] = vals[k];
				else
					ber_dupbv( atail->a_vals+j, &vals[k] );
				vals[k].bv_val = NULL;
				if ( atail->a_nvals ) {
					atail->a_nvals[j] = nvals[k];
					nvals[k].bv_val = NULL;
				}
				k++;
			}
			BER_BVZERO( &atail->a_vals[j] );
			if ( atail->a_nvals ) {
				BER_BVZERO( &atail->a_nvals[j] );
			} else {
				atail->a_nvals = atail->a_vals;
			}
			attr_cnt = 0;
			if ( i == lines ) break;
		}

		if ( BER_BVISNULL( &vals[i] ) ) {
 			Debug( LDAP_DEBUG_ANY,
 				"str2entry: attributeType %s #%d: "
 				"no values\n", 
 				ad->ad_cname.bv_val, attr_cnt, 0 );
 			goto fail;
		}

		if( slapMode & SLAP_TOOL_MODE ) {
			struct berval pval;
			slap_syntax_validate_func *validate =
				ad->ad_type->sat_syntax->ssyn_validate;
			slap_syntax_transform_func *pretty =
				ad->ad_type->sat_syntax->ssyn_pretty;

			if ( pretty ) {
#ifdef SLAP_ORDERED_PRETTYNORM
				rc = ordered_value_pretty( ad,
					&vals[i], &pval, NULL );
#else /* ! SLAP_ORDERED_PRETTYNORM */
				rc = pretty( ad->ad_type->sat_syntax,
					&vals[i], &pval, NULL );
#endif /* ! SLAP_ORDERED_PRETTYNORM */

			} else if ( validate ) {
				/*
			 	 * validate value per syntax
			 	 */
#ifdef SLAP_ORDERED_PRETTYNORM
				rc = ordered_value_validate( ad, &vals[i], LDAP_MOD_ADD );
#else /* ! SLAP_ORDERED_PRETTYNORM */
				rc = validate( ad->ad_type->sat_syntax, &vals[i] );
#endif /* ! SLAP_ORDERED_PRETTYNORM */

			} else {
				Debug( LDAP_DEBUG_ANY,
					"str2entry: attributeType %s #%d: "
					"no validator for syntax %s\n", 
					ad->ad_cname.bv_val, attr_cnt,
					ad->ad_type->sat_syntax->ssyn_oid );
				goto fail;
			}

			if( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"str2entry: invalid value "
					"for attributeType %s #%d (syntax %s)\n",
					ad->ad_cname.bv_val, attr_cnt,
					ad->ad_type->sat_syntax->ssyn_oid );
				goto fail;
			}

			if( pretty ) {
				if ( freeval[i] ) free( vals[i].bv_val );
				vals[i] = pval;
				freeval[i] = 1;
			}
		}

		if ( ad->ad_type->sat_equality &&
			ad->ad_type->sat_equality->smr_normalize )
		{
#ifdef SLAP_ORDERED_PRETTYNORM
			rc = ordered_value_normalize(
				SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
				ad,
				ad->ad_type->sat_equality,
				&vals[i], &nvals[i], NULL );
#else /* ! SLAP_ORDERED_PRETTYNORM */
			rc = ad->ad_type->sat_equality->smr_normalize(
				SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
				ad->ad_type->sat_syntax,
				ad->ad_type->sat_equality,
				&vals[i], &nvals[i], NULL );
#endif /* ! SLAP_ORDERED_PRETTYNORM */

			if ( rc ) {
				Debug( LDAP_DEBUG_ANY,
			   		"<= str2entry NULL (smr_normalize %d)\n", rc, 0, 0 );
				goto fail;
			}
		}

		attr_cnt++;
	}

	free( type );
	atail->a_next = NULL;
	e->e_attrs = ahead.a_next;

	Debug(LDAP_DEBUG_TRACE, "<= str2entry(%s) -> 0x%lx\n",
		e->e_dn, (unsigned long) e, 0 );
	return( e );

fail:
	for ( i=0; i<lines; i++ ) {
		if ( freeval[i] ) free( vals[i].bv_val );
		free( nvals[i].bv_val );
	}
	free( type );
	entry_free( e );
	return NULL;
}


#define GRABSIZE	BUFSIZ

#define MAKE_SPACE( n )	{ \
		while ( ecur + (n) > ebuf + emaxsize ) { \
			ptrdiff_t	offset; \
			offset = (int) (ecur - ebuf); \
			ebuf = ch_realloc( ebuf, \
				emaxsize + GRABSIZE ); \
			emaxsize += GRABSIZE; \
			ecur = ebuf + offset; \
		} \
	}

char *
entry2str(
	Entry	*e,
	int		*len )
{
	Attribute	*a;
	struct berval	*bv;
	int		i;
	ber_len_t tmplen;

	assert( e != NULL );

	/*
	 * In string format, an entry looks like this:
	 *	dn: <dn>\n
	 *	[<attr>: <value>\n]*
	 */

	ecur = ebuf;

	/* put the dn */
	if ( e->e_dn != NULL ) {
		/* put "dn: <dn>" */
		tmplen = e->e_name.bv_len;
		MAKE_SPACE( LDIF_SIZE_NEEDED( 2, tmplen ));
		ldif_sput( &ecur, LDIF_PUT_VALUE, "dn", e->e_dn, tmplen );
	}

	/* put the attributes */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		/* put "<type>:[:] <value>" line for each value */
		for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			bv = &a->a_vals[i];
			tmplen = a->a_desc->ad_cname.bv_len;
			MAKE_SPACE( LDIF_SIZE_NEEDED( tmplen, bv->bv_len ));
			ldif_sput( &ecur, LDIF_PUT_VALUE,
				a->a_desc->ad_cname.bv_val,
				bv->bv_val, bv->bv_len );
		}
	}
	MAKE_SPACE( 1 );
	*ecur = '\0';
	*len = ecur - ebuf;

	return( ebuf );
}

void
entry_clean( Entry *e )
{
	/* free an entry structure */
	assert( e != NULL );

	/* e_private must be freed by the caller */
	assert( e->e_private == NULL );
	e->e_private = NULL;

	/* free DNs */
	if ( !BER_BVISNULL( &e->e_name ) ) {
		free( e->e_name.bv_val );
		BER_BVZERO( &e->e_name );
	}
	if ( !BER_BVISNULL( &e->e_nname ) ) {
		free( e->e_nname.bv_val );
		BER_BVZERO( &e->e_nname );
	}

	if ( !BER_BVISNULL( &e->e_bv ) ) {
		free( e->e_bv.bv_val );
		BER_BVZERO( &e->e_bv );
	}

	/* free attributes */
	attrs_free( e->e_attrs );
	e->e_attrs = NULL;
}

void
entry_free( Entry *e )
{
	entry_clean( e );

	free( e );
}

/*
 * These routines are used only by Backend.
 *
 * the Entry has three entry points (ways to find things):
 *
 *	by entry	e.g., if you already have an entry from the cache
 *			and want to delete it. (really by entry ptr)
 *	by dn		e.g., when looking for the base object of a search
 *	by id		e.g., for search candidates
 *
 * these correspond to three different avl trees that are maintained.
 */

int
entry_cmp( Entry *e1, Entry *e2 )
{
	return SLAP_PTRCMP( e1, e2 );
}

int
entry_dn_cmp( const void *v_e1, const void *v_e2 )
{
	/* compare their normalized UPPERCASED dn's */
	const Entry *e1 = v_e1, *e2 = v_e2;

	return ber_bvcmp( &e1->e_nname, &e2->e_nname );
}

int
entry_id_cmp( const void *v_e1, const void *v_e2 )
{
	const Entry *e1 = v_e1, *e2 = v_e2;
	return( e1->e_id < e2->e_id ? -1 : (e1->e_id > e2->e_id ? 1 : 0) );
}

/* This is like a ber_len */
#define entry_lenlen(l)	(((l) < 0x80) ? 1 : ((l) < 0x100) ? 2 : \
	((l) < 0x10000) ? 3 : ((l) < 0x1000000) ? 4 : 5)

static void
entry_putlen(unsigned char **buf, ber_len_t len)
{
	ber_len_t lenlen = entry_lenlen(len);

	if (lenlen == 1) {
		**buf = (unsigned char) len;
	} else {
		int i;
		**buf = 0x80 | ((unsigned char) lenlen - 1);
		for (i=lenlen-1; i>0; i--) {
			(*buf)[i] = (unsigned char) len;
			len >>= 8;
		}
	}
	*buf += lenlen;
}

static ber_len_t
entry_getlen(unsigned char **buf)
{
	ber_len_t len;
	int i;

	len = *(*buf)++;
	if (len <= 0x7f)
		return len;
	i = len & 0x7f;
	len = 0;
	for (;i > 0; i--) {
		len <<= 8;
		len |= *(*buf)++;
	}
	return len;
}

/* Count up the sizes of the components of an entry */
void entry_partsize(Entry *e, ber_len_t *plen,
	int *pnattrs, int *pnvals, int norm)
{
	ber_len_t len, dnlen, ndnlen;
	int i, nat = 0, nval = 0;
	Attribute *a;

	dnlen = e->e_name.bv_len;
	len = dnlen + 1;	/* trailing NUL byte */
	len += entry_lenlen(dnlen);
	if (norm) {
		ndnlen = e->e_nname.bv_len;
		len += ndnlen + 1;
		len += entry_lenlen(ndnlen);
	}
	for (a=e->e_attrs; a; a=a->a_next) {
		/* For AttributeDesc, we only store the attr name */
		nat++;
		len += a->a_desc->ad_cname.bv_len+1;
		len += entry_lenlen(a->a_desc->ad_cname.bv_len);
		for (i=0; a->a_vals[i].bv_val; i++) {
			nval++;
			len += a->a_vals[i].bv_len + 1;
			len += entry_lenlen(a->a_vals[i].bv_len);
		}
		len += entry_lenlen(i);
		nval++;	/* empty berval at end */
		if (norm && a->a_nvals != a->a_vals) {
			for (i=0; a->a_nvals[i].bv_val; i++) {
				nval++;
				len += a->a_nvals[i].bv_len + 1;
				len += entry_lenlen(a->a_nvals[i].bv_len);
			}
			len += entry_lenlen(i);	/* i nvals */
			nval++;
		} else {
			len += entry_lenlen(0);	/* 0 nvals */
		}
	}
	len += entry_lenlen(nat);
	len += entry_lenlen(nval);
	*plen = len;
	*pnattrs = nat;
	*pnvals = nval;
}

/* Add up the size of the entry for a flattened buffer */
ber_len_t entry_flatsize(Entry *e, int norm)
{
	ber_len_t len;
	int nattrs, nvals;

	entry_partsize(e, &len, &nattrs, &nvals, norm);
	len += sizeof(Entry) + (nattrs * sizeof(Attribute)) +
		(nvals * sizeof(struct berval));
	return len;
}

/* Flatten an Entry into a buffer. The buffer is filled with just the
 * strings/bervals of all the entry components. Each field is preceded
 * by its length, encoded the way ber_put_len works. Every field is NUL
 * terminated.  The entire buffer size is precomputed so that a single
 * malloc can be performed. The entry size is also recorded,
 * to aid in entry_decode.
 */
int entry_encode(Entry *e, struct berval *bv)
{
	ber_len_t len, dnlen, ndnlen;
	int i, nattrs, nvals;
	Attribute *a;
	unsigned char *ptr;

	Debug( LDAP_DEBUG_TRACE, "=> entry_encode(0x%08lx): %s\n",
		(long) e->e_id, e->e_dn, 0 );
	dnlen = e->e_name.bv_len;
	ndnlen = e->e_nname.bv_len;

	entry_partsize( e, &len, &nattrs, &nvals, 1 );

	bv->bv_len = len;
	bv->bv_val = ch_malloc(len);
	ptr = (unsigned char *)bv->bv_val;
	entry_putlen(&ptr, nattrs);
	entry_putlen(&ptr, nvals);
	entry_putlen(&ptr, dnlen);
	AC_MEMCPY(ptr, e->e_dn, dnlen);
	ptr += dnlen;
	*ptr++ = '\0';
	entry_putlen(&ptr, ndnlen);
	AC_MEMCPY(ptr, e->e_ndn, ndnlen);
	ptr += ndnlen;
	*ptr++ = '\0';

	for (a=e->e_attrs; a; a=a->a_next) {
		entry_putlen(&ptr, a->a_desc->ad_cname.bv_len);
		AC_MEMCPY(ptr, a->a_desc->ad_cname.bv_val,
			a->a_desc->ad_cname.bv_len);
		ptr += a->a_desc->ad_cname.bv_len;
		*ptr++ = '\0';
		if (a->a_vals) {
			for (i=0; a->a_vals[i].bv_val; i++);
				entry_putlen(&ptr, i);
				for (i=0; a->a_vals[i].bv_val; i++) {
				entry_putlen(&ptr, a->a_vals[i].bv_len);
				AC_MEMCPY(ptr, a->a_vals[i].bv_val,
					a->a_vals[i].bv_len);
				ptr += a->a_vals[i].bv_len;
				*ptr++ = '\0';
			}
			if (a->a_nvals != a->a_vals) {
				entry_putlen(&ptr, i);
				for (i=0; a->a_nvals[i].bv_val; i++) {
					entry_putlen(&ptr, a->a_nvals[i].bv_len);
					AC_MEMCPY(ptr, a->a_nvals[i].bv_val,
					a->a_nvals[i].bv_len);
					ptr += a->a_nvals[i].bv_len;
					*ptr++ = '\0';
				}
			} else {
				entry_putlen(&ptr, 0);
			}
		}
	}
	return 0;
}

/* Retrieve an Entry that was stored using entry_encode above.
 * We malloc a single block with the size stored above for the Entry
 * and all of its Attributes. We also must lookup the stored
 * attribute names to get AttributeDescriptions. To detect if the
 * attributes of an Entry are later modified, we note that e->e_attr
 * is always a constant offset from (e).
 *
 * Note: everything is stored in a single contiguous block, so
 * you can not free individual attributes or names from this
 * structure. Attempting to do so will likely corrupt memory.
 */
#ifdef SLAP_ZONE_ALLOC
int entry_decode(struct berval *bv, Entry **e, void *ctx)
#else
int entry_decode(struct berval *bv, Entry **e)
#endif
{
	int i, j, count, nattrs, nvals;
	int rc;
	Attribute *a;
	Entry *x;
	const char *text;
	AttributeDescription *ad;
	unsigned char *ptr = (unsigned char *)bv->bv_val;
	BerVarray bptr;

	nattrs = entry_getlen(&ptr);
	if (!nattrs) {
		Debug( LDAP_DEBUG_ANY,
			"entry_decode: attribute count was zero\n", 0, 0, 0);
		return LDAP_OTHER;
	}
	nvals = entry_getlen(&ptr);
	if (!nvals) {
		Debug( LDAP_DEBUG_ANY,
			"entry_decode: value count was zero\n", 0, 0, 0);
		return LDAP_OTHER;
	}
	i = sizeof(Entry) + (nattrs * sizeof(Attribute)) +
		(nvals * sizeof(struct berval));
#ifdef SLAP_ZONE_ALLOC
	x = slap_zn_calloc(1, i + bv->bv_len, ctx);
	AC_MEMCPY((char*)x + i, bv->bv_val, bv->bv_len);
	bv->bv_val = (char*)x + i;
	ptr = (unsigned char *)bv->bv_val;
	/* pointer is reset, now advance past nattrs and nvals again */
	entry_getlen(&ptr);
	entry_getlen(&ptr);
#else
	x = ch_calloc(1, i);
#endif
	i = entry_getlen(&ptr);
	x->e_name.bv_val = (char *) ptr;
	x->e_name.bv_len = i;
	ptr += i+1;
	i = entry_getlen(&ptr);
	x->e_nname.bv_val = (char *) ptr;
	x->e_nname.bv_len = i;
	ptr += i+1;
	Debug( LDAP_DEBUG_TRACE,
		"entry_decode: \"%s\"\n",
		x->e_dn, 0, 0 );
	x->e_bv = *bv;

	/* A valid entry must have at least one attr, so this
	 * pointer can never be NULL
	 */
	x->e_attrs = (Attribute *)(x+1);
	bptr = (BerVarray)x->e_attrs;
	a = NULL;

	while ((i = entry_getlen(&ptr))) {
		struct berval bv;
		bv.bv_len = i;
		bv.bv_val = (char *) ptr;
		if (a) {
			a->a_next = (Attribute *)bptr;
		}
		a = (Attribute *)bptr;
		ad = NULL;
		rc = slap_bv2ad( &bv, &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= entry_decode: str2ad(%s): %s\n", ptr, text, 0 );
			rc = slap_bv2undef_ad( &bv, &ad, &text, 0 );

			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"<= entry_decode: slap_str2undef_ad(%s): %s\n",
						ptr, text, 0 );
				return rc;
			}
		}
		ptr += i + 1;
		a->a_desc = ad;
		bptr = (BerVarray)(a+1);
		a->a_vals = bptr;
		a->a_flags = 0;
#ifdef LDAP_COMP_MATCH
		a->a_comp_data = NULL;
#endif
		count = j = entry_getlen(&ptr);

		while (j) {
			i = entry_getlen(&ptr);
			bptr->bv_len = i;
			bptr->bv_val = (char *)ptr;
			ptr += i+1;
			bptr++;
			j--;
		}
		bptr->bv_val = NULL;
		bptr->bv_len = 0;
		bptr++;

		j = entry_getlen(&ptr);
		if (j) {
			a->a_nvals = bptr;
			while (j) {
				i = entry_getlen(&ptr);
				bptr->bv_len = i;
				bptr->bv_val = (char *)ptr;
				ptr += i+1;
				bptr++;
				j--;
			}
			bptr->bv_val = NULL;
			bptr->bv_len = 0;
			bptr++;
		} else {
			a->a_nvals = a->a_vals;
		}
		nattrs--;
		if ( !nattrs )
			break;
	}

	if (a) a->a_next = NULL;
	Debug(LDAP_DEBUG_TRACE, "<= entry_decode(%s)\n",
		x->e_dn, 0, 0 );
	*e = x;
	return 0;
}

Entry *entry_dup( Entry *e )
{
	Entry *ret;

	ret = (Entry *)ch_calloc( 1, sizeof(*ret) );

	ret->e_id = e->e_id;
	ber_dupbv( &ret->e_name, &e->e_name );
	ber_dupbv( &ret->e_nname, &e->e_nname );
	ret->e_attrs = attrs_dup( e->e_attrs );
	ret->e_ocflags = e->e_ocflags;
	ret->e_bv.bv_val = NULL;
	ret->e_bv.bv_len = 0;
	ret->e_private = NULL;

	return ret;
}

