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

#include <ac/socket.h>
#include <ac/string.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/ds_search.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "../../libraries/liblber/lber-int.h"	/* get struct berelement */
#include "ldap.h"
#include "common.h"

static int	get_filter( BerElement *ber, Filter *filt );
static int	get_filter_list( BerElement *ber, Filter f );
static int	get_substring_filter( BerElement *ber, Filter f );

#ifdef LDAP_COMPAT
#define SEARCHRESTAG	(ldap_compat == 20 ? OLD_LDAP_RES_SEARCH_RESULT : LDAP_RES_SEARCH_RESULT)
#else
#define SEARCHRESTAG	LDAP_RES_SEARCH_RESULT
#endif

int
do_search(
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	int			rc, err;
	int			deref, attrsonly;
	int			sizelimit, timelimit;
	char			*base;
	char			**attrs;
	struct ds_search_arg	sa;
	static CommonArgs	common = default_common_args;

	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );

	/*
	 * Parse the search request.  It looks like this:
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree	(2)
	 *		},
	 *		derefAliases	ENUMERATED {
	 *			neverDerefaliases	(0),
	 *			derefInSearching	(1),
	 *			derefFindingBaseObj	(2),
	 *			alwaysDerefAliases	(3)
	 *		},
	 *		sizelimit	INTEGER (0 .. 65535),
	 *		timelimit	INTEGER (0 .. 65535),
	 *		attrsOnly	BOOLEAN,
	 *		filter		Filter,
	 *		attributes	SEQUENCE OF AttributeType
	 *	}
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_SearchArgument_INIT( &sa );
#endif
#endif

	if ( ber_scanf( ber, "{aiiiib", &base, &sa.sra_subset, &deref,
	    &sizelimit, &timelimit, &attrsonly ) == LBER_ERROR ) {
		send_ldap_msgresult( clientsb, SEARCHRESTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	sa.sra_baseobject = ldap_str2dn( base );
	if ( sa.sra_baseobject == NULLDN && *base != '\0' ) {
		free( base );
		send_ldap_msgresult( clientsb, SEARCHRESTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}
	free( base );

	sa.sra_common = common;	/* struct copy */
	sa.sra_searchaliases = (deref == LDAP_DEREF_SEARCHING ||
	    deref == LDAP_DEREF_ALWAYS);
	if ( deref == LDAP_DEREF_NEVER || deref == LDAP_DEREF_SEARCHING )
		sa.sra_common.ca_servicecontrol.svc_options |=
		    SVC_OPT_DONTDEREFERENCEALIAS;

	sa.sra_common.ca_servicecontrol.svc_sizelimit = (sizelimit == 0 ?
	    SVC_NOSIZELIMIT : sizelimit);

	sa.sra_common.ca_servicecontrol.svc_timelimit = (timelimit == 0 ?
	    SVC_NOTIMELIMIT : timelimit);

	sa.sra_eis.eis_infotypes = (attrsonly ? EIS_ATTRIBUTETYPESONLY :
	    EIS_ATTRIBUTESANDVALUES);

	/* search filter */
	if ( (err = get_filter( ber, &sa.sra_filter )) != 0 ) {
		send_ldap_msgresult( clientsb, SEARCHRESTAG, m,
		    err, NULL, "Bad search filter" );
		return( 0 );
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_ARGS ) {
		PS	ps;

		ps = ps_alloc( std_open );
		std_setup( ps, stderr );
		ps_print( ps, "Filter: " );
		fi_print( ps, sa.sra_filter, EDBOUT );
		ps_print( ps, "\n" );
		ps_free( ps );
	}
#endif

	/* attrs to return */
	attrs = NULL;
	if ( ber_scanf( ber, "{v}}", &attrs ) == LBER_ERROR ) {
		send_ldap_msgresult( clientsb, SEARCHRESTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}
	sa.sra_eis.eis_select = NULLATTR;
	if ( attrs == NULL ) {
		sa.sra_eis.eis_allattributes = 1;
	} else {
		Attr_Sequence	as;
		int		i;

		sa.sra_eis.eis_allattributes = 0;
		for ( i = 0; attrs[i] != NULL; i++ ) {
			AttributeType	type;

			if ( (type = AttrT_new( attrs[i] )) == NULLAttrT ) {
				Debug( LDAP_DEBUG_TRACE, "unknown attr (%s)\n",
				    attrs[i], 0, 0 );
				continue;
			}

			as = as_comp_alloc();
			as->attr_type = type;
			as->attr_acl = NULLACL_INFO;
			as->attr_link = NULLATTR;
			as->attr_value = NULLAV;

			sa.sra_eis.eis_select = as_merge( as,
			    sa.sra_eis.eis_select );
		}

		/* complain only if we know about none of the attrs */
		if ( sa.sra_eis.eis_select == NULLATTR ) {
			send_ldap_msgresult( clientsb, SEARCHRESTAG,
			    m, LDAP_UNDEFINED_TYPE, NULL, attrs[0] );
			charlist_free( attrs );
			return( 0 );
		}

		charlist_free( attrs );
	}

	rc = initiate_dap_operation( OP_SEARCH, m, &sa );

#ifdef LDAP_CONNECTIONLESS
	if (  m->m_cldap )
		m->m_searchbase = sa.sra_baseobject;
	else
#endif /* LDAP_CONNECTIONLESS */
		dn_free( sa.sra_baseobject );

	filter_free( sa.sra_filter );
	as_free( sa.sra_eis.eis_select );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, SEARCHRESTAG, m,
		    rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

static int
get_filter( BerElement *ber, Filter *filt )
{
	unsigned long	tag, len;
	int		err;
	char		typestr[64];
	Filter		f;

	Debug( LDAP_DEBUG_TRACE, "get_filter\n", 0, 0, 0 );

	/*
	 * A filter looks like this coming in:
	 *	Filter ::= CHOICE {
	 *		and		[0]	SET OF Filter,
	 *		or		[1]	SET OF Filter,
	 *		not		[2]	Filter,
	 *		equalityMatch	[3]	AttributeValueAssertion,
	 *		substrings	[4]	SubstringFilter,
	 *		greaterOrEqual	[5]	AttributeValueAssertion,
	 *		lessOrEqual	[6]	AttributeValueAssertion,
	 *		present		[7]	AttributeType,,
	 *		approxMatch	[8]	AttributeValueAssertion
	 *	}
	 *
	 *	SubstringFilter ::= SEQUENCE {
	 *		type               AttributeType,
	 *		SEQUENCE OF CHOICE {
	 *			initial          [0] IA5String,
	 *			any              [1] IA5String,
	 *			final            [2] IA5String
	 *		}
	 *	}
	 */

	f = filter_alloc();
	*filt = f;
	f->flt_next = NULLFILTER;

	err = 0;
	switch (tag = ber_peek_tag( ber, &len )) {
#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_EQUALITY:
#endif
	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_ARGS, "EQUALITY\n", 0, 0, 0 );
		f->flt_type = FILTER_ITEM;
		f->FUITEM.fi_type = FILTERITEM_EQUALITY;
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 )
			(void) ber_skip_tag( ber, &len );
#endif

		if ( (err = get_ava( ber, &f->FUITEM.UNAVA )) != 0 ) {
			free( f );
			return( err );
		}
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_SUBSTRINGS:
#endif
	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_ARGS, "SUBSTRINGS\n", 0, 0, 0 );
		err = get_substring_filter( ber, f );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_GE:
#endif
	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_ARGS, "GE\n", 0, 0, 0 );
		f->flt_type = FILTER_ITEM;
		f->FUITEM.fi_type = FILTERITEM_GREATEROREQUAL;
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 )
			(void) ber_skip_tag( ber, &len );
#endif
		if ( (err = get_ava( ber, &f->FUITEM.UNAVA )) != 0 ) {
			free( f );
			return( err );
		}
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_LE:
#endif
	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_ARGS, "LE\n", 0, 0, 0 );
		f->flt_type = FILTER_ITEM;
		f->FUITEM.fi_type = FILTERITEM_LESSOREQUAL;
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 )
			(void) ber_skip_tag( ber, &len );
#endif

		if ( (err = get_ava( ber, &f->FUITEM.UNAVA )) != 0 ) {
			free( f );
			return( err );
		}
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_PRESENT:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_FILTER_PRESENT_30:
#endif
	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_ARGS, "PRESENT\n", 0, 0, 0 );
		f->flt_type = FILTER_ITEM;
		f->FUITEM.fi_type = FILTERITEM_PRESENT;
		len = sizeof(typestr);
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 )
			(void) ber_skip_tag( ber, &len );
#endif

		if ( ber_scanf( ber, "s", typestr, &len ) == LBER_ERROR )
			return( LDAP_PROTOCOL_ERROR );
		if ( (f->FUITEM.UNTYPE = str2AttrT( typestr )) == NULLAttrT )
			return( LDAP_UNDEFINED_TYPE );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_APPROX:
#endif
	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_ARGS, "APPROX\n", 0, 0, 0 );
		f->flt_type = FILTER_ITEM;
		f->FUITEM.fi_type = FILTERITEM_APPROX;
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 )
			(void) ber_skip_tag( ber, &len );
#endif

		if ( (err = get_ava( ber, &f->FUITEM.UNAVA )) != 0 ) {
			free( f );
			return( err );
		}
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_AND:
#endif
	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_ARGS, "AND\n", 0, 0, 0 );
		f->flt_type = FILTER_AND;
		err = get_filter_list( ber, f );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_OR:
#endif
	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_ARGS, "OR\n", 0, 0, 0 );
		f->flt_type = FILTER_OR;
		err = get_filter_list( ber, f );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_FILTER_NOT:
#endif
	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_ARGS, "NOT\n", 0, 0, 0 );
		f->flt_type = FILTER_NOT;
		(void) ber_skip_tag( ber, &len );
		err = get_filter( ber, &f->FUFILT );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "unknown filter type %lu\n", tag, 0, 0 );
		free( f );
		return( LDAP_PROTOCOL_ERROR );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "end get_filter\n", 0, 0, 0 );
	return( err );
}

static int
get_filter_list( BerElement *ber, Filter f )
{
	Filter		new, tail;
	int		err;
	unsigned long	tag, len;
	char		*last;

	Debug( LDAP_DEBUG_TRACE, "get_filter_list\n", 0, 0, 0 );

#ifdef LDAP_COMPAT30
	if ( ldap_compat == 30 )
		(void) ber_skip_tag( ber, &len );
#endif
	f->FUFILT = tail = NULLFILTER;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) ) {
		if ( (err = get_filter( ber, &new )) != 0 )
			return( err );

		if ( f->FUFILT == NULLFILTER ) {
			f->FUFILT = new;
		} else {
			tail->flt_next = new;
		}
		tail = new;
	}

	Debug( LDAP_DEBUG_TRACE, "end get_filter_list\n", 0, 0, 0 );
	return( 0 );
}

static int
get_substring_filter( BerElement *ber, Filter f )
{
	unsigned long	tag, len;
	char		typestr[64];
	AttributeType	type;
	char		*valstr, *last;
	AttributeValue	value;

	Debug( LDAP_DEBUG_TRACE, "get_substring_filter\n", 0, 0, 0 );

#ifdef LDAP_COMPAT30
	if ( ldap_compat == 30 )
		(void) ber_skip_tag( ber, &len );
#endif

	f->flt_type = FILTER_ITEM;
	f->FUITEM.fi_type = FILTERITEM_SUBSTRINGS;
	len = sizeof(typestr);
	if ( ber_scanf( ber, "{s", typestr, &len ) == LBER_ERROR ) {
		return( LDAP_PROTOCOL_ERROR );
	}
	if ( (type = str2AttrT( typestr )) == NULLAttrT ) {
		return( LDAP_UNDEFINED_TYPE );
	}
	f->FUITEM.UNSUB.fi_sub_type = type;
	f->FUITEM.UNSUB.fi_sub_initial = NULLAV;
	f->FUITEM.UNSUB.fi_sub_any = NULLAV;
	f->FUITEM.UNSUB.fi_sub_final = NULLAV;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) ) {
		AV_Sequence	avs, any_end;

#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 ) {
			if ( ber_scanf( ber, "{a}", &valstr ) == LBER_ERROR ) {
				return( LDAP_PROTOCOL_ERROR );
			}
		} else
#endif
			if ( ber_scanf( ber, "a", &valstr ) == LBER_ERROR ) {
				return( LDAP_PROTOCOL_ERROR );
			}

		value = ldap_str2AttrV( valstr, type->oa_syntax );
		free( valstr );

		if ( value == NULLAttrV ) {
			return( LDAP_INVALID_SYNTAX );
		}

		if ( (avs = avs_comp_new( value )) == NULLAV )
			return( LDAP_OPERATIONS_ERROR );

		switch ( tag ) {
#ifdef LDAP_COMPAT20
		case OLD_LDAP_SUBSTRING_INITIAL:
#endif
#ifdef LDAP_COMPAT30
		case LDAP_SUBSTRING_INITIAL_30:
#endif
		case LDAP_SUBSTRING_INITIAL:
			Debug( LDAP_DEBUG_ARGS, "  INITIAL\n", 0, 0, 0 );
			if ( f->FUITEM.UNSUB.fi_sub_initial != NULLAV
			    && f->FUITEM.UNSUB.fi_sub_initial->avseq_next
			    != NULLAV ) {
				return( LDAP_PROTOCOL_ERROR );
			}
			f->FUITEM.UNSUB.fi_sub_initial = avs;
			break;

#ifdef LDAP_COMPAT20
		case OLD_LDAP_SUBSTRING_ANY:
#endif
#ifdef LDAP_COMPAT30
		case LDAP_SUBSTRING_ANY_30:
#endif
		case LDAP_SUBSTRING_ANY:
			Debug( LDAP_DEBUG_ARGS, "  ANY\n", 0, 0, 0 );
	
			if (f->FUITEM.UNSUB.fi_sub_any != NULLAV) {
			  	any_end->avseq_next = avs;
			} else {
			  	f->FUITEM.UNSUB.fi_sub_any = avs;
			}

			any_end = avs;
			break;

#ifdef LDAP_COMPAT20
		case OLD_LDAP_SUBSTRING_FINAL:
#endif
#ifdef LDAP_COMPAT30
		case LDAP_SUBSTRING_FINAL_30:
#endif
		case LDAP_SUBSTRING_FINAL:
			Debug( LDAP_DEBUG_ARGS, "  FINAL\n", 0, 0, 0 );
			if ( f->FUITEM.UNSUB.fi_sub_final != NULLAV
			    && f->FUITEM.UNSUB.fi_sub_final->avseq_next
			    != NULLAV ) {
				return( LDAP_PROTOCOL_ERROR );
			}
			f->FUITEM.UNSUB.fi_sub_final = avs;
			break;

		default:
			Debug( LDAP_DEBUG_ARGS, "  unknown type\n", tag, 0, 0 );
			return( LDAP_PROTOCOL_ERROR );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "end get_substring_filter\n", 0, 0, 0 );
	return( 0 );
}

void
search_result(
    Sockbuf			*sb,
    struct msg			*m,
    struct ds_search_result	*sr
)
{
	EntryInfo	*e;
	BerElement	*ber;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "search_result\n", 0, 0, 0 );

	ber = NULL;

	if ( ! sr->srr_correlated ) {
		Debug( LDAP_DEBUG_ARGS, "correlating results\n", 0, 0, 0 );
		correlate_search_results( sr );
	}

#ifdef LDAP_CONNECTIONLESS
	if ( m->m_cldap ) {
		if ((ber = der_alloc()) == NULL ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "der_alloc" );
			return;
		}
		if ( ber_printf( ber, "t{is{", LBER_SEQUENCE, m->m_msgid,
		    "" ) == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "ber_printf" );
			return;
		}
	}
#endif

	for ( e = sr->CSR_entries; e != NULLENTRYINFO; e = e->ent_next ) {
		Debug( LDAP_DEBUG_ARGS, "\tentry:\n", 0, 0, 0 );

#ifdef LDAP_CONNECTIONLESS
		if ( !m->m_cldap )
#endif /* LDAP_CONNECTIONLESS */

			if ( (ber = der_alloc()) == NULL ) {
				send_ldap_msgresult( sb, SEARCHRESTAG, m,
				    LDAP_OPERATIONS_ERROR, NULL, "der_alloc" );
				return;
			}

#ifdef LDAP_COMPAT20
		if ( version == 1 ) {
			if ( ber_printf( ber, "t{it{", OLD_LBER_SEQUENCE,
			    m->m_msgid, OLD_LDAP_RES_SEARCH_ENTRY ) == -1 ) {
				send_ldap_msgresult( sb, SEARCHRESTAG, m,
				    LDAP_OPERATIONS_ERROR, NULL, "ber_printf" );
				return;
			}
		} else
#endif
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 ) {
			if ( ber_printf( ber, "{it{{", m->m_msgid,
			    LDAP_RES_SEARCH_ENTRY ) == -1 ) {
				send_ldap_msgresult( sb, SEARCHRESTAG, m,
				    LDAP_OPERATIONS_ERROR, NULL, "ber_printf" );
				return;
			}
		} else
#endif
#ifdef LDAP_CONNECTIONLESS
		if ( m->m_cldap )
			rc = ber_printf( ber, "t{", LDAP_RES_SEARCH_ENTRY );
		else
#endif /* LDAP_CONNECTIONLESS */
			rc = ber_printf( ber, "{it{", m->m_msgid,
			    LDAP_RES_SEARCH_ENTRY );

		if ( rc == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "ber_printf" );
			return;
		}

#ifdef LDAP_CONNECTIONLESS
		if (  m->m_cldap )
			rc = encode_dn( ber, e->ent_dn, m->m_searchbase );
#endif /* LDAP_CONNECTIONLESS */
		else
			rc = encode_dn( ber, e->ent_dn, NULLDN );

		if ( rc == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "encode_dn" );
			return;
		}

		if ( encode_attrs( ber, e->ent_attr ) == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "encode_attrs" );
			return;
		}

#ifdef LDAP_COMPAT20
		if ( version == 1 ) {
			if ( ber_printf( ber, "}}" ) == -1 ) {
				send_ldap_msgresult( sb, SEARCHRESTAG, m,
				    LDAP_OPERATIONS_ERROR, NULL,
				    "ber_printf 2" );
				return;
			}
		} else
#endif
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 ) {
			if ( ber_printf( ber, "}}}" ) == -1 ) {
				send_ldap_msgresult( sb, SEARCHRESTAG, m,
				    LDAP_OPERATIONS_ERROR, NULL,
				    "ber_printf 2" );
				return;
			}
		} else
#endif
#ifdef LDAP_CONNECTIONLESS
		if ( m->m_cldap )
			rc = ber_printf( ber, "}" );
		else
#endif /* LDAP_CONNECTIONLESS */
			rc = ber_printf( ber, "}}" );

		if ( rc == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "ber_printf 2" );
			return;
		}

#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_BER )
			trace_ber( 0, ber->ber_ptr - ber->ber_buf,
			    ber->ber_buf, stderr, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
		if ( !m->m_cldap )
#endif
			(void) ber_flush( sb, ber, 1 );
	}

	switch ( sr->CSR_limitproblem ) {
	case LSR_NOLIMITPROBLEM:
		rc = LDAP_SUCCESS;
		break;
	case LSR_TIMELIMITEXCEEDED:
		rc = LDAP_TIMELIMIT_EXCEEDED;
		break;
	case LSR_SIZELIMITEXCEEDED:
	case LSR_ADMINSIZEEXCEEDED:
		rc = LDAP_SIZELIMIT_EXCEEDED;
		break;
	}

	Debug( LDAP_DEBUG_ARGS, "\tresult:\n", 0, 0, 0 );

#ifdef LDAP_CONNECTIONLESS
	if ( m->m_cldap ) {
		if ( ber_printf( ber, "t{ess}}}", SEARCHRESTAG, rc, "", "" )
		    == -1 ) {
			send_ldap_msgresult( sb, SEARCHRESTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "ber_printf" );
			return;
		}
	   	ber_pvt_sb_udp_set_dst( sb, &m->m_clientaddr );

		if ( ber_flush( sb, ber, 1 ) != 0 ) {
		    send_ldap_msgresult( sb, SEARCHRESTAG, m, 
			LDAP_RESULTS_TOO_LARGE, NULL, "ber_flush" );
		}
	} else
#endif
	send_ldap_msgresult( sb, SEARCHRESTAG, m, rc, NULL, "" );

	return;
}
