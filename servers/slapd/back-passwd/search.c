/* search.c - /etc/passwd backend search function */
/* $OpenLDAP$ */

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
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval *base,
    struct berval *nbase,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    struct berval	*filterstr,
    AttributeName	*attrs,
    int		attrsonly
)
{
	struct passwd	*pw;
	Entry		*e;
	char		*s;
	time_t		stoptime;

	int sent = 0;
	int err = LDAP_SUCCESS;

	LDAPRDN *rdn = NULL;
	struct berval parent = { 0, NULL };
	char *matched = NULL;
	const char *text = NULL;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;

	tlimit = (tlimit > be->be_timelimit || tlimit < 1) ? be->be_timelimit
	    : tlimit;
	stoptime = op->o_time + tlimit;
	slimit = (slimit > be->be_sizelimit || slimit < 1) ? be->be_sizelimit
	    : slimit;

	/* Handle a query for the base of this backend */
	if ( be_issuffix( be, nbase ) ) {
		struct berval	vals[2];

		vals[1].bv_val = NULL;

		matched = (char *) base;

		if( scope != LDAP_SCOPE_ONELEVEL ) {
			AttributeDescription *desc = NULL;

			/* Create an entry corresponding to the base DN */
			e = (Entry *) ch_calloc(1, sizeof(Entry));
			e->e_name.bv_val = ch_strdup( base->bv_val );
			e->e_name.bv_len = base->bv_len;
			e->e_nname.bv_val =  ch_strdup( nbase->bv_val );
			e->e_nname.bv_len = nbase->bv_len;
			e->e_attrs = NULL;
			e->e_private = NULL;

			/* Use the first attribute of the DN
		 	* as an attribute within the entry itself.
		 	*/
			if( ldap_bv2rdn( base, &rdn, (char **)&text, 
				LDAP_DN_FORMAT_LDAP ) )
			{
				err = LDAP_INVALID_DN_SYNTAX;
				goto done;
			}

			if( slap_bv2ad( &rdn[0][0]->la_attr, &desc, &text )) {
				err = LDAP_NO_SUCH_OBJECT;
				ldap_rdnfree(rdn);
				goto done;
			}

			vals[0] = rdn[0][0]->la_value;
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
	
			if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
				send_search_entry( be, conn, op,
					e, attrs, attrsonly, NULL );
				sent++;
			}
		}

		if ( scope != LDAP_SCOPE_BASE ) {
			/* check all our "children" */

			ldap_pvt_thread_mutex_lock( &passwd_mutex );
			pw_start( be );
			for ( pw = getpwent(); pw != NULL; pw = getpwent() ) {
				/* check for abandon */
				if ( op->o_abandon ) {
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					return( -1 );
				}

				/* check time limit */
				if ( slap_get_time() > stoptime ) {
					send_ldap_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
			    		NULL, NULL, NULL, NULL );
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					return( 0 );
				}

				if ( !(e = pw2entry( be, pw, &text )) ) {
					err = LDAP_OTHER;
					endpwent();
					ldap_pvt_thread_mutex_unlock( &passwd_mutex );
					goto done;
				}

				if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
					/* check size limit */
					if ( --slimit == -1 ) {
						send_ldap_result( conn, op, LDAP_SIZELIMIT_EXCEEDED,
				    		NULL, NULL, NULL, NULL );
						endpwent();
						ldap_pvt_thread_mutex_unlock( &passwd_mutex );
						return( 0 );
					}

					send_search_entry( be, conn, op,
						e, attrs, attrsonly, NULL );
					sent++;
				}

				entry_free( e );
			}
			endpwent();
			ldap_pvt_thread_mutex_unlock( &passwd_mutex );
		}

	} else {
		if (! be_issuffix( be, nbase ) ) {
			dnParent( nbase, &parent );
		}

		/* This backend is only one layer deep. Don't answer requests for
		 * anything deeper than that.
		 */
		if( !be_issuffix( be, &parent ) ) {
			int i;
			for( i=0; be->be_nsuffix[i].bv_val != NULL; i++ ) {
				if( dnIsSuffix( nbase, &be->be_nsuffix[i] ) ) {
					matched = be->be_suffix[i].bv_val;
					break;
				}
			}
			err = LDAP_NO_SUCH_OBJECT;
			goto done;
		}

		if( scope == LDAP_SCOPE_ONELEVEL ) {
			goto done;
		}

		if ( ldap_bv2rdn( base, &rdn, (char **)&text,
			LDAP_DN_FORMAT_LDAP ))
		{ 
			err = LDAP_OTHER;
			goto done;
		}

		ldap_pvt_thread_mutex_lock( &passwd_mutex );
		pw_start( be );
		if ( (pw = getpwnam( rdn[0][0]->la_value.bv_val )) == NULL ) {
			matched = parent.bv_val;
			err = LDAP_NO_SUCH_OBJECT;
			ldap_pvt_thread_mutex_unlock( &passwd_mutex );
			goto done;
		}

		e = pw2entry( be, pw, &text );
		ldap_pvt_thread_mutex_unlock( &passwd_mutex );
		if ( !e ) {
			err = LDAP_OTHER;
			goto done;
		}

		if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
			send_search_entry( be, conn, op,
				e, attrs, attrsonly, NULL );
			sent++;
		}

		entry_free( e );
	}

done:
	send_ldap_result( conn, op,
		err, err == LDAP_NO_SUCH_OBJECT ? matched : NULL, text,
		NULL, NULL );

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

	rc = dnNormalize2( NULL, vals, &bv );
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
