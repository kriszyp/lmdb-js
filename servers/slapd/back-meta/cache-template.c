/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
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

#ifdef LDAP_CACHING
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
#endif /* LDAP_CACHING */
