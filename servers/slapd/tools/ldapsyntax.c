/* $OpenLDAP$ */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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
#include <ac/string.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/ds_search.h>
/* #include <quipu/dap2.h> */
#include <quipu/dua.h>

#include <ldap.h>

#include "ldif.h"
#include "ldapsyntax.h"

short	ldap_dn_syntax;
short   ldap_password_syntax;
short	ldap_photo_syntax;
short	ldap_jpeg_syntax;
short	ldap_audio_syntax;

static int	dn2ldif( PS ps, DN dn );
static int	jpeg2ldif( PS ps, AttributeValue av );
static int	audio2ldif( PS ps, AttributeValue av );
static int	photo2ldif( PS ps, AttributeValue av );
static int	fileattr2ldif( PS ps, AttributeValue av );
static void	de_t61( char *s, int t61mark );
static void	de_crypt( char *s );

extern char	*progname;

#define SEPARATOR(c)	((c) == ',' || (c) == ';')
#define SPACE(c)    	((c) == ' ' || (c) == '\n')


int
init_syntaxes()
{
    if (( ldap_dn_syntax = str2syntax( "DN" )) == 0 ) {
	return( -1 );	/* must have this syntax handler */
    }
    ldap_password_syntax = str2syntax( "password" );
    ldap_photo_syntax = str2syntax( "photo" );
    ldap_jpeg_syntax = str2syntax( "jpeg" );
    ldap_audio_syntax = str2syntax( "audio" );

    return( 0 );
}


/*
 * av2ldif:  convert attribute value contained in "av" to ldif format
 * and write to "outfp".  If "dn" is not NULL, convert it instead of "av".
 */
int
av2ldif( FILE *outfp, AV_Sequence av, DN dn, short syntax, char *attrname,
    PS str_ps )
{
    char		*buf;
    int			rc;
    struct file_syntax	*fsyntax;

    if ( av != NULLAV ) {
	fsyntax = (struct file_syntax *) av->avseq_av.av_struct;
    }

    rc = 0;	/* optimistic */
    str_ps->ps_ptr = str_ps->ps_base;	/* reset string PS */

    if ( dn != NULL || syntax == ldap_dn_syntax ) {	/* DNs */
	rc = dn2ldif( str_ps, ( dn != NULLDN ) ? dn :
		(DN)(av->avseq_av.av_struct));

    } else if ( syntax == ldap_jpeg_syntax || ( syntax > AV_WRITE_FILE &&
	    fsyntax->fs_real_syntax == ldap_jpeg_syntax )) {
	rc = jpeg2ldif( str_ps, &av->avseq_av );

    } else if ( syntax == ldap_photo_syntax || ( syntax > AV_WRITE_FILE &&
	    fsyntax->fs_real_syntax == ldap_photo_syntax )) {
	rc = photo2ldif( str_ps, &av->avseq_av );

    } else if ( syntax == ldap_audio_syntax || ( syntax > AV_WRITE_FILE &&
	    fsyntax->fs_real_syntax == ldap_audio_syntax )) {
	rc = audio2ldif( str_ps, &av->avseq_av );

    } else if ( syntax > AV_WRITE_FILE ) {
	rc = fileattr2ldif( str_ps, &av->avseq_av );

    } else {
	AttrV_print( str_ps, &av->avseq_av, EDBOUT );
	*str_ps->ps_ptr = '\0';
	de_t61( str_ps->ps_base, 0 );

	if ( syntax == ldap_password_syntax ) {
	    de_crypt( str_ps->ps_base );
	}

	str_ps->ps_ptr = str_ps->ps_base + strlen( str_ps->ps_base );
    }

    if ( rc == 0 && str_ps->ps_ptr > str_ps->ps_base ) {
	*str_ps->ps_ptr = '\0';
	if (( buf = ldif_type_and_value( attrname, str_ps->ps_base,
		str_ps->ps_ptr - str_ps->ps_base )) == NULL ) {
	    rc = -1;
	} else {
	    if ( fputs( buf, outfp ) == EOF ) {
		rc = -1;
	    }
	    ber_memfree( buf );
	}
    }

    if ( rc == -2 ) {
	if ( syntax > AV_WRITE_FILE ) {
	    fprintf( stderr,
		    "%s: attribute file '%s' not found (skipping value)\n",
		     progname, fsyntax->fs_name );
	}
	rc = 0;	/* treat as "soft" error -- keep going */
    }

    return( rc );
}


static int
dn2ldif( PS ps, DN dn )
{
    RDN	rdn;
    int	firstrdn, rc;
    char	*value;
    PS	rps;

    if ( dn == NULLDN ) {
	return( 0 );
    }

    if ( dn->dn_parent != NULLDN ) {
	if (( rc = dn2ldif( ps, dn->dn_parent )) != 0 ) {
	    return( rc );
	}
	ps_print( ps, ", " );
    }

    if ( (rps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( rps, NULLCP, 0, 0 ) == NOTOK ) {
	return( -1 );
    }

    firstrdn = 1;
    for ( rdn = dn->dn_rdn; rdn != NULLRDN; rdn = rdn->rdn_next ) {
	if ( firstrdn ) {
	    firstrdn = 0;
	} else {
	    ps_print( ps, " + " );
	}

	AttrT_print( ps, rdn->rdn_at, EDBOUT );
	ps_print( ps, "=" );

	if ( rdn->rdn_at->oa_syntax == ldap_dn_syntax ) {
	    if (( rc = dn2ldif( rps, (DN) rdn->rdn_av.av_struct )) != 0 ) {
		return( rc );
	    }
	    *rps->ps_ptr = '\0';
	    value = rps->ps_base;
	} else {
	    AttrV_print( rps, &rdn->rdn_av, EDBOUT );
	    *rps->ps_ptr = '\0';
	    value = rps->ps_base;
	    de_t61( value, 0 );
	}

	/*
	 * ,+="\\\n all go in quotes.  " and \\ need to
	 * be preceeded by \\.
	 */

	if ( strpbrk( value, ",+=\"\\\n" ) != NULL || SPACE( value[0] )
		|| SPACE( value[max( strlen(value) - 1, 0 )] ) ) {
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
		tmp = smalloc( strlen( value ) + specialcount + 1 );
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

#define T61	"{T.61}"
#define T61LEN	6

static void
de_t61( s, t61mark )
char	*s;
int	t61mark;
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


#define CRYPT_MASK 0x23

static void
de_crypt( char *s )
{
    char *p;

    if ( strncmp( s, "{CRYPT}", 7 ) == 0 ) {
	SAFEMEMCPY( s, s + 7, strlen( s + 7 ) + 1 ); /* strip off "{CRYPT}" */

	for ( p = s; *p != '\0'; ++p) {		/* "decrypt" each byte */
	    if ( *p != CRYPT_MASK ) {
		*p ^= CRYPT_MASK;
	    }
	}
    }
}


static int
jpeg2ldif( PS ps, AttributeValue av )
{
    PE	pe;
    int	len;

    if (( pe = grab_pe( av )) == NULLPE || pe->pe_id == PE_PRIM_NULL ) {
	return( -2 );	/* signal soft error */
    }

    if (( pe->pe_class != PE_CLASS_UNIV && pe->pe_class != PE_CLASS_CONT )
	    || pe->pe_form != PE_FORM_PRIM || pe->pe_id != PE_PRIM_OCTS ) {
	return( -1 );
    }

    if ( pe_pullup( pe ) == NOTOK ) {
	return( -1 );
    }

    len = ps_get_abs( pe );

    if ( ps_write( ps, (PElementData)pe->pe_prim, len ) == NOTOK ) {
	return( -1 );
    }

    return( 0 );
}


static int
audio2ldif( PS ps, AttributeValue av )
{
    PE		pe;
    struct qbuf	*qb, *p;
    int		rc, len;
    char	*buf;

    return( 0 );	/* for now */

    if (( pe = grab_pe( av )) == NULLPE || pe->pe_id == PE_PRIM_NULL ) {
	return( -2 );	/* signal soft error */
    }

    qb = (struct qbuf *)pe;

    len = 0;
    for ( p = qb->qb_forw; p != qb; p = p->qb_forw ) {
	len += p->qb_len;
    }

    if (( buf = (char *) malloc( len )) == NULL ) {
	return( -1 );
    }

    len = 0;
    for ( p = qb->qb_forw; p != qb; p = p->qb_forw ) {
	SAFEMEMCPY( buf + len, p->qb_data, p->qb_len );
	len += p->qb_len;
    }

    if ( ps_write( ps, (PElementData)buf, len ) == NOTOK ) {
	rc = -1;
    } else {
	rc = 0;
    }

    free( buf );

    return( rc );
}


static int
photo2ldif( PS ps, AttributeValue av )
{
    PE		pe;
    int		len;
    char	*faxparamset = "\000\300\000\000";
    BerElement	*phber;

    if (( pe = grab_pe( av )) == NULLPE || pe->pe_id == PE_PRIM_NULL ) {
	return( -2 );	/* signal soft error */
    }

    /* old bit string-like format - only handle this for now */
    if ( pe->pe_class == PE_CLASS_UNIV && pe->pe_form == PE_FORM_PRIM
	    && pe->pe_id == PE_PRIM_BITS ) {
	len = ps_get_abs( pe );
	if (( phber = der_alloc()) == NULL ) {
	    return( -1 );
	}
	if ( ber_printf( phber, "t{[tB]{B}}",
		(ber_tag_t) 0xA3, (ber_tag_t) 0x81, faxparamset, (ber_len_t) 31,
		(char *)pe->pe_prim, (ber_len_t) (len * 8) ) == -1 )
	{
	    ber_free( phber, 1 );
	    return( -1 );
	}
	if ( ps_write( ps, (PElementData)phber->ber_buf,
		phber->ber_ptr - phber->ber_buf ) == NOTOK ) {
	    ber_free( phber, 1 );
	    return( -1 );
	}
	ber_free( phber, 1 );
    } else {
	/*
	 * try just writing this into a PS and sending it along
	 */
	if ( pe2ps( ps, pe ) == NOTOK ) {
	    return( -1 );
	}
    }

    return( 0 );
}


static int
fileattr2ldif( PS ps, AttributeValue av )
{
    PE		pe;

    if (( pe = grab_pe( av )) == NULLPE || pe->pe_id == PE_PRIM_NULL ) {
	return( -2 );	/* signal soft error */
    }

    /*
     * try just writing this into a PS and sending it along
     */
    if ( pe2ps( ps, pe ) == NOTOK ) {
	return( -1 );
    }

    return( 0 );
}
