/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
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
#include <ac/socket.h>
#include <ac/string.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/ds_search.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>
extern oid_table_attr *name2attr( char * );
/*extern AttributeValue str_at2AttrV( char *, IF_AttributeType * );*/

#include "lber.h"
#include "../../libraries/liblber/lber-int.h"	/* get struct berelement */
#include "ldap.h"
#include "common.h"

short	ldap_photo_syntax;
short	ldap_jpeg_syntax;
short	ldap_jpeg_nonfile_syntax;
short	ldap_audio_syntax;
short	ldap_dn_syntax;
short	ldap_postaladdress_syntax;
short	ldap_acl_syntax;
short	ldap_mtai_syntax;
short	ldap_rts_cred_syntax;
short	ldap_rtl_syntax;
short	ldap_mailbox_syntax;
short	ldap_caseignorelist_syntax;
short	ldap_caseexactstring_syntax;
short	ldap_certif_syntax;
short	ldap_iattr_syntax;
short	ldap_telex_syntax;
short	ldap_octetstring_syntax;
short	ldap_deliverymethod_syntax;
short	ldap_facsimileTelephoneNumber_syntax;
short	ldap_presentationAddress_syntax;
short	ldap_teletexTerminalIdentifier_syntax;
short	ldap_searchGuide_syntax;
short	ldap_dLSubmitPermission_syntax;

static void	de_t61( char *s, int t61mark );
static int	syntax_is_string( short syntax );

static int
get_one_syntax( char *attrib, int required )
{
	oid_table_attr	*p;

	if ( (p = name2attr( attrib )) != (oid_table_attr *) 0 )
	    return( p->oa_syntax );

	if ( !required )
	    return( -1 );

	Debug( LDAP_DEBUG_ANY, "name2attr (%s) failed - exiting\n", attrib,
	    0, 0 );

	log_and_exit( 1 );
}

void
get_syntaxes( void )
{
	Debug( LDAP_DEBUG_TRACE, "get_syntaxes\n", 0, 0, 0 );

	ldap_photo_syntax = get_one_syntax( "photo", 0 );
	ldap_jpeg_syntax = get_one_syntax( "jpegPhoto", 0 );
	ldap_jpeg_nonfile_syntax = str2syntax( "jpeg" );
	ldap_audio_syntax = get_one_syntax( "audio", 0 );
	ldap_postaladdress_syntax = get_one_syntax( "postaladdress", 0 );
	ldap_dn_syntax = get_one_syntax( "aliasedObjectName", 1 );
	ldap_acl_syntax = get_one_syntax( "acl", 0 );
	ldap_mtai_syntax = get_one_syntax( "mTAInfo", 0 );
	ldap_rts_cred_syntax= get_one_syntax( "initiatingRTSCredentials", 0 );
	ldap_rtl_syntax= get_one_syntax( "routingTreeList", 0 );
	ldap_mailbox_syntax = get_one_syntax( "otherMailbox", 0 );
	ldap_caseignorelist_syntax = str2syntax( "CaseIgnoreList" );
	ldap_caseexactstring_syntax = str2syntax( "caseexactstring" );
	ldap_octetstring_syntax = str2syntax( "OctetString" );
	ldap_deliverymethod_syntax = str2syntax( "DeliveryMethod" );
	ldap_iattr_syntax = get_one_syntax( "inheritedAttribute", 0 );
	ldap_certif_syntax = get_one_syntax( "userCertificate", 0 );
	ldap_telex_syntax = get_one_syntax( "telexNumber", 0 );
        ldap_facsimileTelephoneNumber_syntax =
            get_one_syntax( "facsimileTelephoneNumber", 0 );
        ldap_presentationAddress_syntax =
            get_one_syntax( "presentationAddress", 0 );
        ldap_teletexTerminalIdentifier_syntax =
            get_one_syntax( "teletexTerminalIdentifier", 0 );
        ldap_searchGuide_syntax = get_one_syntax( "searchGuide", 0 );
        ldap_dLSubmitPermission_syntax =
            get_one_syntax( "mhsDLSubmitPermissions", 0 );

	certif_init();	/* initialize certificate syntax handler */
}

/*
 *  From RFC 1779 "A String Representation of Distinguished Names"
 *
 *                       Key     Attribute (X.520 keys)
 *                       ------------------------------
 *                       CN      CommonName
 *                       L       LocalityName
 *                       ST      StateOrProvinceName
 *                       O       OrganizationName
 *                       OU      OrganizationalUnitName
 *                       C       CountryName
 *                       STREET  StreetAddress
 *
 *
 *                      Table 1:  Standardised Keywords
 *
 *   There is an escape mechanism from the normal user oriented form, so
 *   that this syntax may be used to print any valid distinguished name.
 *
 *   1.  Attributes types are represented in a (big-endian) dotted
 *       notation.  (e.g., OID.2.6.53).
 *
 */
static void
attr_key_rfc1779(
    AttributeType   at,
    char            *key    /* return key, caller allocated */
)
{
    char    *x;

    x = attr2name_aux ( at );

    if ( x == NULL ) {
        x = "?";
    } else if ( isdigit ( (unsigned char) *x ) ) {
        sprintf ( key, "OID.%s", x );
        return;
    } else if (strcasecmp(x,"commonName")==0) {
        x = "CN";
    } else if (strcasecmp(x,"localityName")==0) {
        x = "l";
    } else if (strcasecmp(x,"stateOrProvinceName")==0) {
        x = "st";
    } else if (strcasecmp(x,"organizationName")==0) {
        x = "o";
    } else if (strcasecmp(x,"organizationalUnitName")==0) {
        x = "ou";
    } else if (strcasecmp(x,"countryName")==0) {
        x = "c";
    } else if (strcasecmp(x,"streetAddress")==0) {
        x = "street";
    }

    strcpy ( key, x );
}

#define SEPARATOR(c)	((c) == ',' || (c) == ';')
#define SPACE(c)    	((c) == ' ' || (c) == '\n')

int
dn_print_real(
    PS	ps,
    DN	dn,
    int	format
)
{
	RDN	rdn;
	int	firstrdn;
	char	*value;
	PS	rps;
        char    key[512];

	if ( dn == NULLDN )
		return( 0 );

	if ( dn->dn_parent != NULLDN ) {
		dn_print_real( ps, dn->dn_parent, format );
		ps_print( ps, ", " );
	}

	if ( (rps = ps_alloc( str_open )) == NULLPS )
		return( -1 );
	if ( str_setup( rps, NULLCP, 0, 0 ) == NOTOK )
		return( -1 );

	firstrdn = 1;
	for ( rdn = dn->dn_rdn; rdn != NULLRDN; rdn = rdn->rdn_next ) {
		if ( firstrdn )
			firstrdn = 0;
		else
			ps_print( ps, " + " );

                attr_key_rfc1779 ( rdn->rdn_at, key );

                ps_print ( ps, key );
		ps_print( ps, "=" );

		if ( rdn->rdn_at->oa_syntax == ldap_dn_syntax ) {
			dn_print_real( rps, (DN) rdn->rdn_av.av_struct,
			    format );
			*rps->ps_ptr = '\0';
			value = rps->ps_base;
		} else {
			AttrV_print( rps, &rdn->rdn_av, EDBOUT );
			*rps->ps_ptr = '\0';
			if ( rps->ps_ptr - rps->ps_base >= 5 &&
			    strncmp( rps->ps_base, "{ASN}", 5 ) == 0 ) {
				*rps->ps_base = '#';
				SAFEMEMCPY( rps->ps_base + 1, rps->ps_base + 5,
					rps->ps_ptr - rps->ps_base - 4 );
			}
			value = rps->ps_base;
			de_t61( value, 0 );
		}

		/*
		 * ,+="\\\n all go in quotes.  " and \\ need to
		 * be preceeded by \\.
		 */

		if ( strpbrk( value, ",+=\"\\\n" ) != NULL || SPACE( value[0] )
		    || SPACE( value[max( strlen(value) - 1, (size_t) 0 )] ) ) {
			char	*p, *t, *tmp;
			int	specialcount;

			ps_print( ps, "\"" );

			specialcount = 0;
			for ( p = value; *p != '\0'; p++ ) {
				if ( *p == '"' || *p == '\\' ) {
					specialcount++;
				}
			}
			if ( specialcount > 0 ) {
				tmp = smalloc( strlen( value ) + specialcount
				    + 1 );
				for ( p = value, t = tmp; *p != '\0'; p++ ) {
					switch ( *p ) {
					case '"':
					case '\\':
						*t++ = '\\';
						/* FALL THROUGH */
					default:
						*t++ = *p;
					}
				}
				*t = '\0';
				ps_print( ps, tmp );
				free( tmp );
			} else {
				ps_print( ps, value );
			}

			ps_print( ps, "\"" );
		} else {
			ps_print( ps, value );
		}

		rps->ps_ptr = rps->ps_base;
	}

	ps_free( rps );

	return( 0 );
}

void
ldap_dn_print(
    PS	ps,
    DN	dn,
    DN	base,	/* if non-NULL, subsitute '*' for base (for CLDAP) */
    int	format
)
{
	DN	tmpdn;
	int	addstar;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn_print\n", 0, 0, 0 );

	addstar = 0;
	if ( base != NULLDN && dn != NULL ) {
		for ( tmpdn = dn; base != NULLDN && tmpdn != NULLDN;
		    base = base->dn_parent, tmpdn = tmpdn->dn_parent ) {
			if ( dn_comp_cmp( base, tmpdn ) == NOTOK ) {
				break;
			}
		}
		if (( addstar = ( base == NULLDN && tmpdn != NULL ))) {
			dn = tmpdn;
		}
	}

	dn_print_real( ps, dn, format );
	if ( addstar ) {
	    ps_print( ps, ", *" );
	}
}

int
encode_dn(
    BerElement	*ber,
    DN		dn,
    DN		base	/* if non-NULL, subsitute '*' for base (for CLDAP) */
)
{
	PS	ps;
	int	rc;

	Debug( LDAP_DEBUG_TRACE, "encode_dn\n", 0, 0, 0 );

	if ( (ps = ps_alloc( str_open )) == NULLPS )
		return( -1 );
	if ( str_setup( ps, NULLCP, 0, 0 ) == NOTOK )
		return( -1 );

	ldap_dn_print( ps, dn, base, EDBOUT );
	*ps->ps_ptr = '\0';

	rc = ber_printf( ber, "s", ps->ps_base );

	ps_free( ps );

	return( rc );
}

static int
put_jpeg_value( BerElement *ber, AttributeValue av )
{
	PE	pe;
	int	len;

	Debug( LDAP_DEBUG_TRACE, "put_jpeg_value\n", 0, 0, 0 );

	if (av->av_syntax == AV_FILE)
		pe = (PE) (((struct file_syntax *) av->av_struct)->
		    fs_attr->av_struct);
	else
		pe = (PE) av->av_struct;

	Debug( LDAP_DEBUG_ARGS,
	    "put_jpeg_value: pe_class %x, pe_form %x, pe_id %x\n",
	    pe->pe_class, pe->pe_form, pe->pe_id );

	if ( (pe->pe_class != PE_CLASS_UNIV && pe->pe_class != PE_CLASS_CONT)
	    || pe->pe_form != PE_FORM_PRIM || pe->pe_id != PE_PRIM_OCTS ) {
		Debug( LDAP_DEBUG_ANY, "put_jpeg_value: unknown type\n", 0,
		    0, 0 );
		return( -1 );
	}

	if ( pe_pullup( pe ) == NOTOK ) {
		Debug( LDAP_DEBUG_ANY, "put_jpeg_value: cannot pullup\n", 0,
		    0, 0 );
		return( -1 );
	}

	len = ps_get_abs( pe );

	Debug( LDAP_DEBUG_ARGS, "put_jeg_value: ber_printf %d bytes\n",
	    len, 0, 0 );
	if ( ber_printf( ber, "o", (char *) pe->pe_prim, len ) == -1 ) {
		Debug( LDAP_DEBUG_ANY, "put_jpeg_value: ber_printf failed\n",
		    0, 0, 0 );
		return( -1 );
	}

	return( 0 );
}

static int
put_audio_value( BerElement *ber, AttributeValue av )
{
	struct qbuf	*qb, *p;
	int		rc, len;
	char		*buf;

	Debug( LDAP_DEBUG_TRACE, "put_audio_value\n", 0, 0, 0 );

	qb = (struct qbuf *) (((struct file_syntax *)
	    av->av_struct)->fs_attr->av_struct);

	len = 0;
	for ( p = qb->qb_forw; p != qb; p = p->qb_forw ) {
		len += p->qb_len;
	}

	if ( (buf = (char *) malloc( len )) == NULL )
		return( -1 );

	len = 0;
	for ( p = qb->qb_forw; p != qb; p = p->qb_forw ) {
		SAFEMEMCPY( buf + len, p->qb_data, p->qb_len );
		len += p->qb_len;
	}

	Debug( LDAP_DEBUG_ARGS, "put_audio_value: ber_printf %d bytes\n",
	    len, 0, 0 );

	if ( (rc = ber_printf( ber, "o", buf, len )) == -1 )
		Debug( LDAP_DEBUG_ANY, "put_audio_value: ber_printf failed\n",
		    0, 0, 0 );

	free( buf );

	return( rc );
}

static int
put_photo_value( BerElement *ber, AttributeValue av )
{
	PE		pe;
	PS		ps;
	int		len;
	char		*faxparamset = "\000\300\000\000";
	BerElement	*phber;

	Debug( LDAP_DEBUG_TRACE, "put_photo_value\n", 0, 0, 0 );

	pe = (PE) (((struct file_syntax *) av->av_struct)->fs_attr->av_struct);

	/* old bit string-like format - only handle this for now */
	if ( pe->pe_class == PE_CLASS_UNIV && pe->pe_form == PE_FORM_PRIM
	    && pe->pe_id == PE_PRIM_BITS ) {
		len = ps_get_abs( pe );
		Debug( LDAP_DEBUG_ARGS, "put_photo_val: ber_printf %d bytes\n",
		    len, 0, 0 );
		if (( phber = der_alloc()) == NULL ) {
			Debug( LDAP_DEBUG_ANY, "der_alloc failed\n", 0, 0, 0 );
			return( -1 );
		}
		if ( ber_printf( phber, "t{[tB]{B}}", 0xA3, 0x81, faxparamset,
		    31, (char *)pe->pe_prim, len * 8 ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( phber, 1 );
			return( -1 );
		}
		if ( ber_printf( ber, "o", phber->ber_buf, phber->ber_ptr
		    - phber->ber_buf ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ber_free( phber, 1 );
			return( -1 );
		}
		ber_free( phber, 1 );
	} else {
		/*
		 * try just writing this into a PS and sending it along
		 */
		ps_len_strategy = PS_LEN_LONG;
		if ( (ps = ps_alloc( str_open )) == NULLPS )
			return( -1 );
		if ( str_setup( ps, NULLCP, 0, 0 ) == NOTOK ||
		    pe2ps( ps, pe ) == NOTOK ) {
			ps_free( ps );
			return( -1 );
		}

		len = ps->ps_ptr - ps->ps_base;
		Debug( LDAP_DEBUG_ARGS, "put_photo_val: ber_printf %d bytes\n",
		    len, 0, 0 );
		if ( ber_printf( ber, "o", (char *) ps->ps_base, len ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
			ps_free( ps );
			return( -1 );
		}
		ps_free( ps );
	}

	return( 0 );
}

static int
put_values(
    BerElement	*ber,
    PS		ps,
    short	syntax,
    AV_Sequence	vals
)
{
	AV_Sequence	av;
	char		*strvalue;

	Debug( LDAP_DEBUG_TRACE, "put_values\n", 0, 0, 0 );

	for ( av = vals; av != NULLAV; av = av->avseq_next ) {
		if ( syntax == ldap_jpeg_syntax ||
		    syntax == ldap_jpeg_nonfile_syntax ) {
			if ( put_jpeg_value( ber, &av->avseq_av ) == -1 )
				return( -1 );
		} else if ( syntax == ldap_photo_syntax ) {
			if ( put_photo_value( ber, &av->avseq_av ) == -1 )
				return( -1 );
		} else if ( syntax == ldap_audio_syntax ) {
			if ( put_audio_value( ber, &av->avseq_av ) == -1 )
				return( -1 );
		} else if ( syntax == ldap_dn_syntax ) {
			if ( encode_dn( ber, (DN) av->avseq_av.av_struct,
			    NULLDN ) == -1 )
				return( -1 );
		} else if ( syntax > AV_WRITE_FILE ) {
			struct file_syntax	*fsyntax;

			fsyntax = (struct file_syntax *) av->avseq_av.av_struct;

			ps->ps_ptr = ps->ps_base;
			AttrV_print( ps, fsyntax->fs_attr, EDBOUT );
			*ps->ps_ptr = '\0';

			if ( ber_printf( ber, "o", ps->ps_base,
			    ps->ps_ptr - ps->ps_base ) == -1 )
				return( -1 );
		} else {
			ps->ps_ptr = ps->ps_base;
			AttrV_print( ps, &av->avseq_av, EDBOUT );
			*ps->ps_ptr = '\0';
			de_t61( ps->ps_base, 0 );

			if ( syntax_is_string( av->avseq_av.av_syntax ) &&
				*ps->ps_base == '\0' ) {
			    /*
			     * If this is a zero-length string, make it
			     * a single blank (this is gross, but it works
			     * around a dsap library bug).
			     */
			    Debug( LDAP_DEBUG_ANY,
				    "put_values: replaced zero-length string with single blank\n", 0, 0, 0 );
			    strvalue = " ";
			} else {
			    strvalue = ps->ps_base;
			}
			if ( ber_printf( ber, "s", strvalue ) == -1 )
				return( -1 );
		}
	}

	return( 0 );
}

int
encode_attrs( BerElement *ber, Attr_Sequence as )
{
	PS		ps;

	Debug( LDAP_DEBUG_TRACE, "encode_attrs\n", 0, 0, 0 );

	if ( (ps = ps_alloc( str_open )) == NULLPS )
		return( -1 );
	if ( str_setup( ps, NULLCP, 0, 0 ) == NOTOK )
		return( -1 );

#ifdef LDAP_COMPAT20
	if ( ber_printf( ber, "t{", ldap_compat == 20 ? OLD_LBER_SEQUENCE :
	    LBER_SEQUENCE ) == -1 ) {
#else
	if ( ber_printf( ber, "{" ) == -1 ) {
#endif
		ps_free( ps );
		return( -1 );
	}

	while ( as != NULLATTR ) {
		ps->ps_ptr = ps->ps_base;
		AttrT_print( ps, as->attr_type, EDBOUT );
		*ps->ps_ptr = '\0';

#ifdef LDAP_COMPAT20
		if ( ber_printf( ber, "t{st[", ldap_compat == 20 ?
		    OLD_LBER_SEQUENCE : LBER_SEQUENCE, ps->ps_base,
		    ldap_compat == 20 ? OLD_LBER_SET : LBER_SET ) == -1 ) {
#else
		if ( ber_printf( ber, "{s[", ps->ps_base ) == -1 ) {
#endif
			ps_free( ps );
			return( -1 );
		}

		put_values( ber, ps, as->attr_type->oa_syntax, as->attr_value );

		if ( ber_printf( ber, "]}" ) == -1 ) {
			ps_free( ps );
			return( -1 );
		}

		as = as->attr_link;
	}
	ps_free( ps );

	if ( ber_printf( ber, "}" ) == -1 )
		return( -1 );

	return( 0 );
}

static void
trim_trailing_spaces( char *s )
{
	char	*t;

	t = s + strlen( s );
	while ( --t > s ) {
		if ( SPACE( *t ) ) {
			*t = '\0';
		} else {
			break;
		}
	}
}

DN
ldap_str2dn( char *str )
{
	DN		dn, save;
	RDN		rdn, newrdn, tmprdn;
	AttributeType	at;
	AttributeValue	av;
	char		*type, *value, *savestr;
	int		morerdncomps;

	Debug( LDAP_DEBUG_TRACE, "ldap_str2dn\n", 0, 0, 0 );

	savestr = str = strdup( str );
	dn = NULLDN;
	do {
		char	*r;
		int	state;

		rdn = NULLRDN;
		morerdncomps = 1;
		do {
			/* get the type */
			while ( *str == ' ' || *str == '\n' )
				str++;
			type = str;
			while ( *str != '\0' && *str != '=' )
				str++;
			if ( *str == '\0' ) {
				free( savestr );
				Debug( LDAP_DEBUG_ARGS, "no =\n", 0, 0, 0 );
				return( NULLDN );
			}
			*str++ = '\0';
			if ( strncmp( type, "OID.", 4 ) == 0 )
				type += 4;

#define BEGINVALUE	1
#define INVALUE		2
#define INQUOTE 	3
#define ENDVALUE	4
			if ( *str == '#' ) {
				++str;
			}
			r = value = str;
			state = BEGINVALUE;
			/* break or return out */
			while ( state != ENDVALUE ) {
				switch ( *str ) {
				case '"':
					if ( state == BEGINVALUE ) {
						state = INQUOTE;
						str++;
					} else if ( state == INQUOTE ) {
						state = ENDVALUE;
						str++;
					} else {
						free( savestr );
						Debug( LDAP_DEBUG_ARGS,
						    "quote state %d\n", state,
						    0, 0 );
						return( NULLDN );
					}
					break;

				case ',':
				case ';':
				case '+':
					if ( state == INVALUE ) {
						state = ENDVALUE;
					} else if ( state == INQUOTE ) {
						*r++ = *str++;
					} else {
						free( savestr );
						Debug( LDAP_DEBUG_ARGS,
						    "comma state %d\n", state,
						    0, 0 );
						return( NULLDN );
					}
					break;

				case ' ':
				case '\n':
					if ( state == BEGINVALUE ) {
						str++;
					} else {
						*r++ = *str++;
					}
					break;

				case '\\':
					str++;
					*r++ = *str++;
					break;

				case '\0':
					state = ENDVALUE;
					break;

				default:
					if ( state == BEGINVALUE )
						state = INVALUE;
					*r++ = *str++;
					break;
				}
			}

			while ( SPACE( *str ) )
				str++;
			if ( *str == '+' ) {
				morerdncomps = 1;
				str++;
			} else {
				morerdncomps = 0;
				if ( SEPARATOR( *str ) )
					str++;
			}
			*r = '\0';

			/* type */
			trim_trailing_spaces( type );
			if ( (at = str2AttrT( type )) == NULLAttrT ) {
				dn_free( dn );
				free( savestr );
				Debug( LDAP_DEBUG_ARGS, "bad type (%s)\n",
				    type, 0, 0 );
				return( NULLDN ); /* LDAP_UNDEFINED_TYPE */
			}
			/* value */
			if ( (av = ldap_str2AttrV( value, at->oa_syntax ))
			    == NULLAttrV ) {
				dn_free( dn );
				free( savestr );
				Debug( LDAP_DEBUG_ARGS, "bad val\n", 0, 0, 0 );
				return( NULLDN ); /* LDAP_INVALID_SYNTAX */
			}
			/* make the rdn */
			newrdn = rdn_comp_new( at, av );

			/* add it to the list */
			for ( tmprdn = rdn; tmprdn != NULLRDN &&
			    tmprdn->rdn_next != NULLRDN;
			    tmprdn = tmprdn->rdn_next )
				;	/* NULL */
			if ( tmprdn != NULLRDN )
				tmprdn->rdn_next = newrdn;
			else
				rdn = newrdn;

			AttrV_free( av );
		} while ( morerdncomps );

		save = dn;
		dn = dn_comp_new( rdn );
		dn->dn_parent = save;
	} while ( str != NULL && *str != '\0' );

	free( savestr );
	Debug( LDAP_DEBUG_TRACE, "ldap_str2dn OK\n", 0, 0, 0 );
	return( dn );
}

#define T61	"{T.61}"
#define T61LEN	6

static void
de_t61( char *s, int t61mark )
{
	char	*next = s;
	unsigned char	c;
	unsigned int	hex;

	while ( *s ) {
		switch ( *s ) {
		case '{' :
			if ( strncasecmp( s, T61, T61LEN) == 0 ) {
				s += T61LEN;
				if ( t61mark )
					*next++ = '@';
			} else {
				*next++ = *s++;
			}
			break;

		case '\\':
			c = *(s + 1);
			if ( c == '\n' ) {
				s += 2;
				if ( *s == '\t' )
					s++;
				break;
			}
                        if ( c == '\\' ) {
                            /* reverse solidus character itself */
                            s += 2;
                            *next++ = c;
                            break;
                        }
			if ( isdigit( c ) )
				hex = c - '0';
			else if ( c >= 'A' && c <= 'F' )
				hex = c - 'A' + 10;
			else if ( c >= 'a' && c <= 'f' )
				hex = c - 'a' + 10;
			else {
				*next++ = *s++;
				break;
			}
			hex <<= 4;
			c = *(s + 2);
			if ( isdigit( c ) )
				hex += c - '0';
			else if ( c >= 'A' && c <= 'F' )
				hex += c - 'A' + 10;
			else if ( c >= 'a' && c <= 'f' )
				hex += c - 'a' + 10;
			else {
				*next++ = *s++;
				*next++ = *s++;
				break;
			}

			*next++ = hex;
			s += 3;
			break;

		default:
			*next++ = *s++;
			break;
		}
	}
	*next = '\0';
}


static PE
bv_asn2pe( struct berval *bv )
{
	PS	ps;
	PE	pe;

	if (( ps = ps_alloc(str_open)) == NULLPS || str_setup( ps, bv->bv_val,
	    bv->bv_len, 0 ) == NOTOK ) {
		Debug( LDAP_DEBUG_TRACE, "bv_asn2pe: ps_alloc failed\n",
		    0, 0, 0 );
		return( NULLPE );
	}

	pe = ps2pe( ps );
	if ( ps->ps_errno != PS_ERR_NONE ) {
		Debug( LDAP_DEBUG_TRACE, "bv_asn2pe: ps2pe failed %s\n",
		    ps_error(ps->ps_errno), 0, 0 );
		if ( pe != NULLPE ) {
			pe_free( pe );
		}
		return( NULLPE );
	}

	return( pe );
}


AttributeValue
bv_octet2AttrV( struct berval *bv )
{
	AttributeValue	av;

	av = AttrV_alloc();
	if ( av == NULLAttrV ) {
		return( NULLAttrV );
	}

	if (( av->av_struct = (caddr_t) str2prim( bv->bv_val, bv->bv_len,
	    PE_CLASS_UNIV, PE_PRIM_OCTS )) == NULL ) {
		free((char *)av );
		return( NULLAttrV );
	}

	av->av_syntax = 0;
	return( av );
}


AttributeValue
bv_asn2AttrV( struct berval *bv )
{
	AttributeValue	av;

	av = AttrV_alloc();
	if ( av == NULLAttrV ) {
		return( NULLAttrV );
	}

	if (( av->av_struct = (caddr_t) bv_asn2pe( bv )) == NULL ) {
		free((char *)av );
		return( NULLAttrV );
	}

	av->av_syntax = 0;
	return( av );
}


AttributeValue
ldap_strdn2AttrV( char *dnstr )
{
	DN		dn;
	AttributeValue	av;

	if (( dn = ldap_str2dn( dnstr )) == NULL ) {
		return( NULLAttrV );
	}

	av = AttrV_alloc();
	if ( av == NULLAttrV ) {
		dn_free( dn );
		return( NULLAttrV );
	}

	av->av_struct = (caddr_t)dn; 
	av->av_syntax = ldap_dn_syntax;
	return( av );
}

RDN
ldap_str2rdn( char *rdnstr )
{
	DN	dn;
	RDN	rdn;

	if ( (dn = ldap_str2dn( rdnstr )) == NULL ) {
		return( NULL );
	}

	if ( (rdn = rdn_cpy( dn->dn_rdn )) == NULL ) {
		return( NULL );
	}

	dn_free( dn );

	return( rdn );
}

AttributeValue
ldap_str_at2AttrV( char *str, AttributeType type )
{
	char		*s, *res, *r;

	Debug( LDAP_DEBUG_TRACE, "ldap_str_at2AttrV str (%s) type (%s)\n", str,
	    type->oa_ot.ot_name, 0 );

	if ( type->oa_syntax == ldap_rts_cred_syntax ||
	    type->oa_syntax == ldap_mtai_syntax ||
	    type->oa_syntax == ldap_acl_syntax ||
	    type->oa_syntax == ldap_mailbox_syntax ||
	    type->oa_syntax == ldap_caseignorelist_syntax ||
	    type->oa_syntax == ldap_certif_syntax ||
	    type->oa_syntax == ldap_iattr_syntax ||
	    type->oa_syntax == ldap_telex_syntax ||
	    type->oa_syntax == ldap_deliverymethod_syntax ||
	    type->oa_syntax == ldap_facsimileTelephoneNumber_syntax ||
	    type->oa_syntax == ldap_presentationAddress_syntax ||
	    type->oa_syntax == ldap_teletexTerminalIdentifier_syntax ||
	    type->oa_syntax == ldap_searchGuide_syntax ||
            type->oa_syntax == ldap_dLSubmitPermission_syntax ||
	    type->oa_syntax == ldap_rtl_syntax ) {
		res = str;
	} else {
		res = (char *) malloc( max( 2 * strlen( str ), (size_t) 10 ) );

		r = res;
		for ( s = str; *s; s++ ) {
			switch ( *s ) {
			case '&':
			case '#':
			case '$':
			case '%':
			case '@':
			case '\\':
				sprintf( r, "\\%02x", *s & 0xff );
				r += 3;
				break;

			default:
				*r++ = *s;
			}
		}
		*r = '\0';
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_str_at2AttrV returning (%s)\n", res,
	    0, 0 );

	return( str_at2AttrV( res, type ) );
}

AttributeValue
ldap_str2AttrV( char *value, short syntax )
{
	if ( syntax == ldap_dn_syntax ) {
		return( ldap_strdn2AttrV( value ) );
	} else {
		return( str2AttrV( value, syntax ) );
	}
}


static int
syntax_is_string( short syntax )
{
/*
 * this code depends on the order and nunber of strings that are in
 * the ISODE file lib/syntax/x500/string.c 
 */
    return ( syntax >= ldap_caseexactstring_syntax &&
	    syntax <= ldap_caseexactstring_syntax + 8 );
}
