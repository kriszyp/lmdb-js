/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

void ad_destroy( AttributeDescription *ad )
{
	AttributeDescription *n;

	for (; ad != NULL; ad = n) {
		n = ad->ad_next;
		ldap_memfree( ad );
	}
}

/* Is there an AttributeDescription for this type that uses this language? */
AttributeDescription * ad_find_lang(
	AttributeType *type,
	struct berval *lang )
{
	AttributeDescription *ad;

	ldap_pvt_thread_mutex_lock( &type->sat_ad_mutex );
	for (ad = type->sat_ad; ad; ad=ad->ad_next)
	{
		if (ad->ad_lang.bv_len == lang->bv_len &&
			!strcasecmp(ad->ad_lang.bv_val, lang->bv_val))
			break;
	}
	ldap_pvt_thread_mutex_unlock( &type->sat_ad_mutex );
	return ad;
}

int slap_str2ad(
	const char *str,
	AttributeDescription **ad,
	const char **text )
{
	struct berval bv;
	bv.bv_val = (char *) str;
	bv.bv_len = strlen( str );

	return slap_bv2ad( &bv, ad, text );
}

static char *strchrlen(
	const char *p, 
	const char ch, 
	int *len )
{
	int i;

	for( i=0; p[i]; i++ ) {
		if( p[i] == ch ) {
			*len = i;
			return (char *) &p[i];
		}
	}

	*len = i;
	return NULL;
}

int slap_bv2ad(
	struct berval *bv,
	AttributeDescription **ad,
	const char **text )
{
	int rtn = LDAP_UNDEFINED_TYPE;
	AttributeDescription desc, *d2;
	char *name, *options;
	char *opt, *next;
	int nlang;
	int langlen;

	/* hardcoded limits for speed */
#define MAX_LANG_OPTIONS 128
	struct berval langs[MAX_LANG_OPTIONS+1];
#define MAX_LANG_LEN 1024
	char langbuf[MAX_LANG_LEN];

	assert( ad != NULL );
	assert( *ad == NULL ); /* temporary */

	if( bv == NULL || bv->bv_len == 0 ) {
		*text = "empty attribute description";
		return rtn;
	}

	/* make sure description is IA5 */
	if( ad_keystring( bv ) ) {
		*text = "attribute description contains inappropriate characters";
		return rtn;
	}

	/* find valid base attribute type; parse in place */
	memset( &desc, 0, sizeof( desc ));
	desc.ad_cname = *bv;
	name = bv->bv_val;
	options = strchr(name, ';');
	if( options != NULL ) {
		desc.ad_cname.bv_len = options - name;
	}
	desc.ad_type = at_bvfind( &desc.ad_cname );
	if( desc.ad_type == NULL ) {
		*text = "attribute type undefined";
		return rtn;
	}

	if( is_at_operational( desc.ad_type ) && options != NULL ) {
		*text = "operational attribute with options undefined";
		return rtn;
	}

	/*
	 * parse options in place
	 */
	nlang = 0;
	memset( langs, 0, sizeof( langs ));
	langlen = 0;

	for( opt=options; opt != NULL; opt=next ) {
		int optlen;
		opt++; 
		next = strchrlen( opt, ';', &optlen );

		if( optlen == 0 ) {
			*text = "zero length option is invalid";
			return rtn;
		
		} else if ( optlen == sizeof("binary")-1 &&
			strncasecmp( opt, "binary", sizeof("binary")-1 ) == 0 )
		{
			/* binary option */
			if( slap_ad_is_binary( &desc ) ) {
				*text = "option \"binary\" specified multiple times";
				return rtn;
			}

			if( !slap_syntax_is_binary( desc.ad_type->sat_syntax )) {
				/* not stored in binary, disallow option */
				*text = "option \"binary\" not supported with type";
				return rtn;
			}

			desc.ad_flags |= SLAP_DESC_BINARY;
			continue;

		} else if ( optlen >= sizeof("lang-")-1 &&
			strncasecmp( opt, "lang-", sizeof("lang-")-1 ) == 0 )
		{
			int i;

			if( opt[optlen-1] == '-' ) {
				desc.ad_flags |= SLAP_DESC_LANG_RANGE;
			}

			if( nlang >= MAX_LANG_OPTIONS ) {
				*text = "too many language options";
				return rtn;
			}

			/*
			 * tags should be presented in sorted order,
			 * so run the array in reverse.
			 */
			for( i=nlang-1; i>=0; i-- ) {
				int rc;

				rc = strncasecmp( opt, langs[i].bv_val,
					(unsigned) optlen < langs[i].bv_len
						? optlen : langs[i].bv_len );

				if( rc == 0 && (unsigned)optlen == langs[i].bv_len ) {
					/* duplicate (ignore) */
					goto done;

				} else if ( rc > 0 ||
					( rc == 0 && (unsigned)optlen > langs[i].bv_len ))
				{
					AC_MEMCPY( &langs[i+1], &langs[i],
						(nlang-i)*sizeof(struct berval) );
					langs[i].bv_val = opt;
					langs[i].bv_len = optlen;
					goto done;
				}
			}

			if( nlang ) {
				AC_MEMCPY( &langs[1], &langs[0],
					nlang*sizeof(struct berval) );
			}
			langs[0].bv_val = opt;
			langs[0].bv_len = optlen;

done:;
			langlen += optlen + 1;
			nlang++;

		} else {
			*text = "unrecognized option";
			return rtn;
		}
	}

	if( nlang > 0 ) {
		int i;

		if( langlen > MAX_LANG_LEN ) {
			*text = "language options too long";
			return rtn;
		}

		desc.ad_lang.bv_val = langbuf;
		langlen = 0;

		for( i=0; i<nlang; i++ ) {
			AC_MEMCPY( &desc.ad_lang.bv_val[langlen],
				langs[i].bv_val, langs[i].bv_len );

			langlen += langs[i].bv_len;
			desc.ad_lang.bv_val[langlen++] = ';';
		}

		desc.ad_lang.bv_val[--langlen] = '\0';
		desc.ad_lang.bv_len = langlen;
	}

	/* see if a matching description is already cached */
	for (d2 = desc.ad_type->sat_ad; d2; d2=d2->ad_next) {
		if( d2->ad_flags != desc.ad_flags ) {
			continue;
		}
		if( d2->ad_lang.bv_len != desc.ad_lang.bv_len ) {
			continue;
		}
		if( d2->ad_lang.bv_len == 0 ) {
			break;
		}
		if( strncasecmp( d2->ad_lang.bv_val, desc.ad_lang.bv_val,
			desc.ad_lang.bv_len ) == 0 )
		{
			break;
		}
	}

	/* Not found, add new one */
	while (d2 == NULL) {
		size_t dlen = 0;
		ldap_pvt_thread_mutex_lock( &desc.ad_type->sat_ad_mutex );
		/* check again now that we've locked */
		for (d2 = desc.ad_type->sat_ad; d2; d2=d2->ad_next) {
			if (d2->ad_flags != desc.ad_flags)
				continue;
			if (d2->ad_lang.bv_len != desc.ad_lang.bv_len)
				continue;
			if (d2->ad_lang.bv_len == 0)
				break;
			if (strncasecmp(d2->ad_lang.bv_val, desc.ad_lang.bv_val,
				desc.ad_lang.bv_len) == 0)
				break;
		}
		if (d2) {
			ldap_pvt_thread_mutex_unlock( &desc.ad_type->sat_ad_mutex );
			break;
		}

		/* Allocate a single contiguous block. If there are no
		 * options, we just need space for the AttrDesc structure.
		 * Otherwise, we need to tack on the full name length +
		 * options length.
		 */
		if (desc.ad_lang.bv_len || desc.ad_flags != SLAP_DESC_NONE) {
			dlen = desc.ad_type->sat_cname.bv_len;
			if (desc.ad_lang.bv_len) {
				dlen += 1+desc.ad_lang.bv_len;
			}
			if( slap_ad_is_binary( &desc ) ) {
				dlen += sizeof(";binary")-1;
			}
		}

		d2 = ch_malloc(sizeof(AttributeDescription) + dlen + 1);
		d2->ad_type = desc.ad_type;
		d2->ad_flags = desc.ad_flags;
		d2->ad_cname.bv_len = desc.ad_type->sat_cname.bv_len;
		d2->ad_lang.bv_len = desc.ad_lang.bv_len;

		if (dlen == 0) {
			d2->ad_cname.bv_val = d2->ad_type->sat_cname.bv_val;
			d2->ad_lang.bv_val = NULL;
		} else {
			d2->ad_cname.bv_val = (char *)(d2+1);
			strcpy(d2->ad_cname.bv_val, d2->ad_type->sat_cname.bv_val);
			if( slap_ad_is_binary( &desc ) ) {
				strcpy(d2->ad_cname.bv_val+d2->ad_cname.bv_len,
					";binary");
				d2->ad_cname.bv_len += sizeof(";binary")-1;
			}
			if( d2->ad_lang.bv_len ) {
				d2->ad_cname.bv_val[d2->ad_cname.bv_len++]=';';
				d2->ad_lang.bv_val = d2->ad_cname.bv_val+
					d2->ad_cname.bv_len;
				strncpy(d2->ad_lang.bv_val,desc.ad_lang.bv_val,
					d2->ad_lang.bv_len);
				d2->ad_lang.bv_val[d2->ad_lang.bv_len] = '\0';
				ldap_pvt_str2lower(d2->ad_lang.bv_val);
				d2->ad_cname.bv_len += d2->ad_lang.bv_len;
			}
		}
		/* Add new desc to list. We always want the bare Desc with
		 * no options to stay at the head of the list, assuming
		 * that one will be used most frequently.
		 */
		if (desc.ad_type->sat_ad == NULL || dlen == 0) {
			d2->ad_next = desc.ad_type->sat_ad;
			desc.ad_type->sat_ad = d2;
		} else {
			d2->ad_next = desc.ad_type->sat_ad->ad_next;
			desc.ad_type->sat_ad->ad_next = d2;
		}
		ldap_pvt_thread_mutex_unlock( &desc.ad_type->sat_ad_mutex );
	}

	if( *ad == NULL ) {
		*ad = d2;
	} else {
		**ad = *d2;
	}

	return LDAP_SUCCESS;
}

static int is_ad_sublang(
	struct berval *sublangbv, 
	struct berval *suplangbv )
{
	const char *suplang, *supp, *supdelimp;
	const char *sublang, *subp, *subdelimp;
	int  suplen, sublen;

	if( suplangbv->bv_len == 0 ) return 1;
	if( sublangbv->bv_len == 0 ) return 0;

	sublang =sublangbv->bv_val;
	suplang =suplangbv->bv_val;

	for( supp=suplang ; supp; supp=supdelimp ) {
		supdelimp = strchrlen( supp, ';', &suplen );
		if( supdelimp ) supdelimp++;

		for( subp=sublang ; subp; subp=subdelimp ) {
			subdelimp = strchrlen( subp, ';', &sublen );
			if( subdelimp ) subdelimp++;

			if ((( suplen < sublen && supp[suplen-1] == '-' ) ||
				suplen == sublen ) && strncmp( supp, subp, suplen ) == 0 )
			{
				goto match;
			}
		}

		return 0;
match:;
	}
	return 1;
}

int is_ad_subtype(
	AttributeDescription *sub,
	AttributeDescription *super
)
{
	int lr;

	if( !is_at_subtype( sub->ad_type, super->ad_type ) ) {
		return 0;
	}

	/* ensure sub does support all flags of super */
	lr = sub->ad_lang.bv_len ? SLAP_DESC_LANG_RANGE : 0;
	if(( super->ad_flags & ( sub->ad_flags | lr )) != super->ad_flags ) {
		return 0;
	}

	/* check for language tags */
	if ( !is_ad_sublang( &sub->ad_lang, &super->ad_lang )) {
		return 0;
	}

	return 1;
}

int ad_inlist(
	AttributeDescription *desc,
	AttributeName *attrs )
{
	if (! attrs ) return 0;

	for( ; attrs->an_name.bv_val; attrs++ ) {
		ObjectClass *oc;
		int rc;
		
		if ( attrs->an_desc ) {
			if ( is_ad_subtype( desc, attrs->an_desc ))
				return 1;
			continue;
		}

		/*
		 * EXTENSION: see if requested description is an object class
		 * if so, return attributes which the class requires/allows
		 */
		oc = attrs->an_oc;
		if( oc == NULL && attrs->an_name.bv_val ) {
			switch( attrs->an_name.bv_val[0] ) {
				case '+':
				case '-': {
					struct berval ocname;
					ocname.bv_len = attrs->an_name.bv_len - 1;
					ocname.bv_val = &attrs->an_name.bv_val[1];
					oc = oc_bvfind( &ocname );
				} break;
				default:
					oc = oc_bvfind( &attrs->an_name );
			}
			attrs->an_oc = oc;
		}
		if( oc != NULL ) {
			if ( oc == slap_schema.si_oc_extensibleObject ) {
				/* extensibleObject allows the return of anything */
				return 1;
			}

			if( oc->soc_required ) {
				/* allow return of required attributes */
				int i;
   				for ( i = 0; oc->soc_required[i] != NULL; i++ ) {
					rc = is_at_subtype( desc->ad_type,
						oc->soc_required[i] );
					if( rc ) return 1;
				}
			}

			if( oc->soc_allowed ) {
				/* allow return of allowed attributes */
				int i;
   				for ( i = 0; oc->soc_allowed[i] != NULL; i++ ) {
					rc = is_at_subtype( desc->ad_type,
						oc->soc_allowed[i] );
					if( rc ) return 1;
				}
			}

		} else {
			/* short-circuit this search next time around */
			if (!slap_schema.si_at_undefined->sat_ad) {
				const char *text;
				slap_bv2undef_ad(&attrs->an_name,
					&attrs->an_desc, &text);
			} else {
				attrs->an_desc =
					slap_schema.si_at_undefined->sat_ad;
			}
		}
	}

	return 0;
}


int slap_str2undef_ad(
	const char *str,
	AttributeDescription **ad,
	const char **text )
{
	struct berval bv;
	bv.bv_val = (char *) str;
	bv.bv_len = strlen( str );

	return slap_bv2undef_ad( &bv, ad, text );
}

int slap_bv2undef_ad(
	struct berval *bv,
	AttributeDescription **ad,
	const char **text )
{
	AttributeDescription *desc;

	assert( ad != NULL );

	if( bv == NULL || bv->bv_len == 0 ) {
		*text = "empty attribute description";
		return LDAP_UNDEFINED_TYPE;
	}

	/* make sure description is IA5 */
	if( ad_keystring( bv ) ) {
		*text = "attribute description contains inappropriate characters";
		return LDAP_UNDEFINED_TYPE;
	}

	for( desc = slap_schema.si_at_undefined->sat_ad; desc;
		desc=desc->ad_next ) 
	{
		if( desc->ad_cname.bv_len == bv->bv_len &&
		    !strcasecmp( desc->ad_cname.bv_val, bv->bv_val ))
		{
		    	break;
		}
	}
	
	if( !desc ) {
		desc = ch_malloc(sizeof(AttributeDescription) + 1 +
			bv->bv_len);
		
		desc->ad_flags = SLAP_DESC_NONE;
		desc->ad_lang.bv_val = NULL;
		desc->ad_lang.bv_len = 0;

		desc->ad_cname.bv_len = bv->bv_len;
		desc->ad_cname.bv_val = (char *)(desc+1);
		strcpy(desc->ad_cname.bv_val, bv->bv_val);

		/* canonical to upper case */
		ldap_pvt_str2upper( desc->ad_cname.bv_val );

		desc->ad_type = slap_schema.si_at_undefined;
		desc->ad_next = desc->ad_type->sat_ad;
		desc->ad_type->sat_ad = desc;
	}

	if( !*ad ) {
		*ad = desc;
	} else {
		**ad = *desc;
	}

	return LDAP_SUCCESS;
}

int
an_find(
    AttributeName *a,
    struct berval *s
)
{
	if( a == NULL ) return 0;

	for ( ; a->an_name.bv_val; a++ ) {
		if ( a->an_name.bv_len != s->bv_len) continue;
		if ( strcasecmp( s->bv_val, a->an_name.bv_val ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}

/* Convert a delimited string into a list of AttributeNames; Add on
 * to an existing list if it was given.
 */
AttributeName *
str2anlist( AttributeName *an, char *in, const char *brkstr )
{
	char	*str;
	char	*s;
	char	*lasts;
	int	i, j;
	const char *text;
	AttributeName *anew;

	/* find last element in list */
	for (i = 0; an && an[i].an_name.bv_val; i++);
	
	/* protect the input string from strtok */
	str = ch_strdup( in );

	/* Count words in string */
	j=1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			j++;
		}
	}

	an = ch_realloc( an, ( i + j + 1 ) * sizeof( AttributeName ) );
	anew = an + i;
	for ( s = ldap_pvt_strtok( str, brkstr, &lasts );
		s != NULL;
		s = ldap_pvt_strtok( NULL, brkstr, &lasts ) )
	{
		anew->an_desc = NULL;
		anew->an_oc = NULL;
		ber_str2bv(s, 0, 1, &anew->an_name);
		slap_bv2ad(&anew->an_name, &anew->an_desc, &text);
		if ( !anew->an_desc ) {
			anew->an_oc = oc_bvfind( &anew->an_name );
			if ( !anew->an_oc ) {
				free( an );
				/* overwrites input string on error! */
				strcpy( in, s );
				return NULL;
			}
		}
		anew++;
	}
	anew->an_name.bv_val = NULL;

	free( str );
	return( an );
}

