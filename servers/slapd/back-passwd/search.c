/* search.c - /etc/passwd backend search function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *     Hallvard B. Furuseth
 *     Howard Chu
 *     Kurt D. Zeilenga
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <pwd.h>

#include "slap.h"
#include "back-passwd.h"
#include <ldap_pvt.h>

static void pw_start( Backend *be );

static Entry *pw2entry(
	Backend *be,
	struct passwd *pw,
	const char **text);

int
passwd_back_search(
    Operation	*op,
    SlapReply	*rs )
{
	struct passwd	*pw;
	Entry		*e;
	char		*s;
	time_t		stoptime;

	LDAPRDN rdn = NULL;
	struct berval parent = { 0, NULL };

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;

	op->oq_search.rs_tlimit = (op->oq_search.rs_tlimit > op->o_bd->be_timelimit || op->oq_search.rs_tlimit < 1) ? op->o_bd->be_timelimit
	    : op->oq_search.rs_tlimit;
	stoptime = op->o_time + op->oq_search.rs_tlimit;
	op->oq_search.rs_slimit = (op->oq_search.rs_slimit > op->o_bd->be_sizelimit || op->oq_search.rs_slimit < 1) ? op->o_bd->be_sizelimit
	    : op->oq_search.rs_slimit;

	/* Handle a query for the base of this backend */
	if ( be_issuffix( op->o_bd, &op->o_req_ndn ) ) {
		struct berval	vals[2];

		vals[1].bv_val = NULL;

		rs->sr_matched = op->o_req_dn.bv_val;

		if( op->oq_search.rs_scope != LDAP_SCOPE_ONELEVEL ) {
			AttributeDescription *desc = NULL;

			/* Create an entry corresponding to the base DN */
			e = (Entry *) ch_calloc(1, sizeof(Entry));
			e->e_name.bv_val = ch_strdup( op->o_req_dn.bv_val );
			e->e_name.bv_len = op->o_req_dn.bv_len;
			e->e_nname.bv_val =  ch_strdup( op->o_req_ndn.bv_val );
			e->e_nname.bv_len = op->o_req_ndn.bv_len;
			e->e_attrs = NULL;
			e->e_private = NULL;

			/* Use the first attribute of the DN
		 	* as an attribute within the entry itself.
		 	*/
			if( ldap_bv2rdn( &op->o_req_dn, &rdn, (char **)&rs->sr_text, 
				LDAP_DN_FORMAT_LDAP ) )
			{
				rs->sr_err = LDAP_INVALID_DN_SYNTAX;
				goto done;
			}

			if( slap_bv2ad( &rdn[0]->la_attr, &desc, &rs->sr_text )) {
				rs->sr_err = LDAP_NO_SUCH_OBJECT;
				ldap_rdnfree(rdn);
				goto done;
			}

			vals[0] = rdn[0]->la_value;
			attr_mergeit( e, desc, vals );

			ldap_rdnfree(rdn);
			rdn = NULL;

			/* Every entry needs an objectclass. We don't really
			 * know if our hardcoded choice here agrees with the
			 * DN that was configured for this backend, but it's
			 * better than nothing.
			 *
			 * should be a configuratable item
			 */
			vals[0].bv_val = "organizationalUnit";
			vals[0].bv_len = sizeof("organizationalUnit")-1;
			attr_mergeit( e, ad_objectClass, vals );
	
			if ( test_filter( op, e, op->oq_search.rs_filter ) == LDAP_COMPARE_TRUE ) {
				rs->sr_entry = e;
				rs->sr_attrs = op->oq_search.rs_attrs;
				send_search_entry( op, rs );
			}
		}

		if ( op->oq_search.rs_scope != LDAP_SCOPE_BASE ) {
			/* check all our "children" */

			ldap_pvt_thread_mutex_lock( &passwd_mutex );
			pw_start( op->o_bd );
			for ( pw = getpwent(); pw != NULL; pw = getpwent() ) {
				/* check for abandon */
				if ( op->o_abandon ) {
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					return( -1 );
				}

				/* check time limit */
				if ( slap_get_time() > stoptime ) {
					send_ldap_error( op, rs, LDAP_TIMELIMIT_EXCEEDED, NULL );
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					return( 0 );
				}

				if ( !(e = pw2entry( op->o_bd, pw, &rs->sr_text )) ) {
					rs->sr_err = LDAP_OTHER;
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					goto done;
				}

				if ( test_filter( op, e, op->oq_search.rs_filter ) == LDAP_COMPARE_TRUE ) {
					/* check size limit */
					if ( --op->oq_search.rs_slimit == -1 ) {
						send_ldap_error( op, rs, LDAP_SIZELIMIT_EXCEEDED, NULL );
						endpwent();
						ldap_pvt_thread_mutex_unlock( &passwd_mutex );
						return( 0 );
					}

					rs->sr_entry = e;
					rs->sr_attrs = op->oq_search.rs_attrs;
					send_search_entry( op, rs );
				}

				entry_free( e );
			}
			endpwent();
			ldap_pvt_thread_mutex_unlock( &passwd_mutex );
		}

	} else {
		if (! be_issuffix( op->o_bd, &op->o_req_ndn ) ) {
			dnParent( &op->o_req_ndn, &parent );
		}

		/* This backend is only one layer deep. Don't answer requests for
		 * anything deeper than that.
		 */
		if( !be_issuffix( op->o_bd, &parent ) ) {
			int i;
			for( i=0; op->o_bd->be_nsuffix[i].bv_val != NULL; i++ ) {
				if( dnIsSuffix( &op->o_req_ndn, &op->o_bd->be_nsuffix[i] ) ) {
					rs->sr_matched = op->o_bd->be_suffix[i].bv_val;
					break;
				}
			}
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			goto done;
		}

		if( op->oq_search.rs_scope == LDAP_SCOPE_ONELEVEL ) {
			goto done;
		}

		if ( ldap_bv2rdn( &op->o_req_dn, &rdn, (char **)&rs->sr_text,
			LDAP_DN_FORMAT_LDAP ))
		{ 
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

		ldap_pvt_thread_mutex_lock( &passwd_mutex );
		pw_start( op->o_bd );
		if ( (pw = getpwnam( rdn[0]->la_value.bv_val )) == NULL ) {
			rs->sr_matched = parent.bv_val;
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			ldap_pvt_thread_mutex_unlock( &passwd_mutex );
			goto done;
		}

		e = pw2entry( op->o_bd, pw, &rs->sr_text );
		ldap_pvt_thread_mutex_unlock( &passwd_mutex );
		if ( !e ) {
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

		if ( test_filter( op, e, op->oq_search.rs_filter ) == LDAP_COMPARE_TRUE ) {
			rs->sr_entry = e;
			rs->sr_attrs = op->oq_search.rs_attrs;
			send_search_entry( op, rs );
		}

		entry_free( e );
	}

done:
	if( rs->sr_err != LDAP_NO_SUCH_OBJECT ) rs->sr_matched = NULL;
	send_ldap_result( op, rs );

	if( rdn != NULL ) ldap_rdnfree( rdn );

	return( 0 );
}

static void
pw_start(
	Backend *be
)
{
	endpwent();

#ifdef HAVE_SETPWFILE
	if ( be->be_private != NULL ) {
		(void) setpwfile( (char *) be->be_private );
	}
#endif /* HAVE_SETPWFILE */
}

static Entry *
pw2entry( Backend *be, struct passwd *pw, const char **text )
{
	size_t pwlen;
	Entry		*e;
	struct berval	vals[2];
	struct berval	bv;

	int rc;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	AttributeDescription *ad_cn = NULL;
	AttributeDescription *ad_sn = NULL;
	AttributeDescription *ad_uid = NULL;
	AttributeDescription *ad_description = NULL;

	rc = slap_str2ad( "cn", &ad_cn, text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "sn", &ad_sn, text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "uid", &ad_uid, text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "description", &ad_description, text );
	if(rc != LDAP_SUCCESS) return NULL;

	/*
	 * from pw we get pw_name and make it cn
	 * give it an objectclass of person.
	 */

	pwlen = strlen( pw->pw_name );
	vals[0].bv_len = (sizeof("uid=,")-1) + ( pwlen + be->be_suffix[0].bv_len );
	vals[0].bv_val = ch_malloc( vals[0].bv_len + 1 );

	/* rdn attribute type should be a configuratable item */
	sprintf( vals[0].bv_val, "uid=%s,%s",
		pw->pw_name, be->be_suffix[0].bv_val );

	rc = dnNormalize( 0, NULL, NULL, vals, &bv, NULL );
	if( rc != LDAP_SUCCESS ) {
		free( vals[0].bv_val );
		return NULL;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );
	e->e_name = vals[0];
	e->e_nname = bv;

	e->e_attrs = NULL;

	vals[1].bv_val = NULL;

	/* objectclasses should be configurable items */
	vals[0].bv_val = "top";
	vals[0].bv_len = sizeof("top")-1;
	attr_mergeit( e, ad_objectClass, vals );

	vals[0].bv_val = "person";
	vals[0].bv_len = sizeof("person")-1;
	attr_mergeit( e, ad_objectClass, vals );

	vals[0].bv_val = "uidObject";
	vals[0].bv_len = sizeof("uidObject")-1;
	attr_mergeit( e, ad_objectClass, vals );

	vals[0].bv_val = pw->pw_name;
	vals[0].bv_len = pwlen;
	attr_mergeit( e, ad_uid, vals );	/* required by uidObject */
	attr_mergeit( e, ad_cn, vals );	/* required by person */
	attr_mergeit( e, ad_sn, vals );	/* required by person */

#ifdef HAVE_PW_GECOS
	/*
	 * if gecos is present, add it as a cn. first process it
	 * according to standard BSD usage. If the processed cn has
	 * a space, use the tail as the surname.
	 */
	if (pw->pw_gecos[0]) {
		char *s;

		vals[0].bv_val = pw->pw_gecos;
		vals[0].bv_len = strlen(vals[0].bv_val);
		attr_mergeit(e, ad_description, vals);

		s = strchr(vals[0].bv_val, ',');
		if (s) *s = '\0';

		s = strchr(vals[0].bv_val, '&');
		if (s) {
			char buf[1024];

			if( vals[0].bv_len + pwlen < sizeof(buf) ) {
				int i = s - vals[0].bv_val;
				strncpy(buf, vals[0].bv_val, i);
				s = buf+i;
				strcpy(s, pw->pw_name);
				*s = TOUPPER((unsigned char)*s);
				strcat(s, vals[0].bv_val+i+1);
				vals[0].bv_val = buf;
			}
		}
		vals[0].bv_len = strlen(vals[0].bv_val);

		if ( vals[0].bv_len && strcasecmp( vals[0].bv_val, pw->pw_name )) {
			attr_mergeit( e, ad_cn, vals );
		}

		if ( (s=strrchr(vals[0].bv_val, ' '))) {
			vals[0].bv_val = s + 1;
			vals[0].bv_len = strlen(vals[0].bv_val);
			attr_mergeit(e, ad_sn, vals);
		}
	}
#endif

	return( e );
}
