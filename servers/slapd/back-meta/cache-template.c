/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Apurva Kumar for inclusion
 * in OpenLDAP Software based, in part, on existing OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "../../../libraries/libldap/ldap-int.h"

void 
filter2template(
	Filter			*f,
	struct			berval *fstr,
	AttributeName**		filter_attrs, 
	int*			filter_cnt,
	struct exception*	result	)
{
	int	i;
	Filter	*p;
	struct berval tmp;
	ber_len_t len;
	const char* text; 

	/*
	 * FIXME: should we use an assert here?
	 */
	if ( f == NULL ) {
		ber_str2bv( "No filter!", sizeof("No filter!")-1, 1, fstr );
		result->type = FILTER_ERR; 
		return; 
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
				( sizeof("(=)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=)",
				f->f_av_desc->ad_cname.bv_val );

		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs,
				(*filter_cnt + 2)*sizeof(AttributeName)); 
		
#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[*filter_cnt].an_name,
				&f->f_av_desc->ad_cname); 
#endif
		
		(*filter_attrs)[*filter_cnt].an_name = f->f_av_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_av_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text); 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt)++; 
		break;
	case LDAP_FILTER_GE:
		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
				+ ( sizeof("(>=)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s>=)",
			f->f_av_desc->ad_cname.bv_val);

		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs, 
				(*filter_cnt + 2)*sizeof(AttributeName)); 
#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[filter_cnt].an_name,
				&f->f_av_desc->ad_cname);
#endif

		(*filter_attrs)[*filter_cnt].an_name = f->f_av_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_av_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text); 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt)++; 

		break;

	case LDAP_FILTER_LE:
		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			+ ( sizeof("(<=)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s<=)",
			f->f_av_desc->ad_cname.bv_val);

		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs, 
				(*filter_cnt + 2)*sizeof(AttributeName)); 
#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[filter_cnt].an_name,
				&f->f_av_desc->ad_cname);
#endif
		
		(*filter_attrs)[*filter_cnt].an_name = f->f_av_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_av_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text); 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt++); 

		break;

	case LDAP_FILTER_APPROX:
		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			+ ( sizeof("(~=)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s~=)",
			f->f_av_desc->ad_cname.bv_val);
		
		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs,
				(*filter_cnt + 2)*sizeof(AttributeName));

#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[filter_cnt].an_name,
				&f->f_av_desc->ad_cname);
#endif
		
		(*filter_attrs)[*filter_cnt].an_name = f->f_av_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_av_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text); 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt)++; 

		break;

	case LDAP_FILTER_SUBSTRINGS:
		fstr->bv_len = f->f_sub_desc->ad_cname.bv_len +
			( sizeof("(=)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=)",
			f->f_sub_desc->ad_cname.bv_val );

		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs,
				(*filter_cnt + 2)*sizeof(AttributeName));

#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[filter_cnt].an_name,
				&f->f_av_desc->ad_cname);
#endif
		
		(*filter_attrs)[*filter_cnt].an_name = f->f_av_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_av_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text);
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt)++; 

		break;

	case LDAP_FILTER_PRESENT:
		fstr->bv_len = f->f_desc->ad_cname.bv_len +
			( sizeof("(=*)") - 1 );
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			f->f_desc->ad_cname.bv_val );

		*filter_attrs = (AttributeName *)ch_realloc(*filter_attrs,
				(*filter_cnt+2)*sizeof(AttributeName)); 

#if 0	/* ? */
		ber_dupbv(&(*filter_attrs)[filter_cnt].an_name,
				&f->f_av_desc->ad_cname);
#endif
		
		(*filter_attrs)[*filter_cnt].an_name = f->f_desc->ad_cname; 
		(*filter_attrs)[*filter_cnt].an_desc = NULL; 
		slap_bv2ad(&f->f_desc->ad_cname,
				&(*filter_attrs)[*filter_cnt].an_desc, &text);
		(*filter_attrs)[*filter_cnt+1].an_name.bv_val = NULL; 
		(*filter_attrs)[*filter_cnt+1].an_name.bv_len = 0; 
		(*filter_cnt)++; 

		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		fstr->bv_len = sizeof("(%)") - 1;
		fstr->bv_val = ch_malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%c)",
			f->f_choice == LDAP_FILTER_AND ? '&' :
			f->f_choice == LDAP_FILTER_OR ? '|' : '!' );

		for ( p = f->f_list; p != NULL; p = p->f_next ) {
			len = fstr->bv_len;

			filter2template( p, &tmp, filter_attrs, filter_cnt,
					result); 
			if (result->type != SUCCESS) {
				return; 
			}
			
			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val,
					fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-1], tmp.bv_len + 2, 
				/*"("*/ "%s)", tmp.bv_val );

			ch_free( tmp.bv_val );
		}

		break;

	default:
		ber_str2bv( "(?=unknown)", sizeof("(?=unknown)")-1, 1, fstr );
		result->type = FILTER_ERR; 
		return;
	}
}
