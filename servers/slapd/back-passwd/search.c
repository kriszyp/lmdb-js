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
#include "external.h"
#include <ldap_pvt.h>

static Entry *pw2entry(
	Backend *be,
	struct passwd *pw,
	char *rdn);

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
    const char	*filterstr,
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

	char *rdn = NULL;
	char *parent = NULL;
	char *matched = NULL;
	char *user = NULL;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;

	tlimit = (tlimit > be->be_timelimit || tlimit < 1) ? be->be_timelimit
	    : tlimit;
	stoptime = op->o_time + tlimit;
	slimit = (slimit > be->be_sizelimit || slimit < 1) ? be->be_sizelimit
	    : slimit;

	endpwent();

#ifdef HAVE_SETPWFILE
	if ( be->be_private != NULL ) {
		(void) setpwfile( (char *) be->be_private );
	}
#endif /* HAVE_SETPWFILE */

	/* Handle a query for the base of this backend */
	if ( be_issuffix( be,  nbase->bv_val ) ) {
		struct berval	val, *vals[2];

		vals[0] = &val;
		vals[1] = NULL;

		matched = (char *) base;

		if( scope != LDAP_SCOPE_ONELEVEL ) {
			char *type;
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
			rdn = dn_rdn(NULL, base);

			if( rdn == NULL || (s = strchr(rdn, '=')) == NULL ) {
				err = LDAP_INVALID_DN_SYNTAX;
				free(rdn);
				goto done;
			}

			val.bv_val = rdn_attr_value(rdn);
			val.bv_len = strlen( val.bv_val );

			type = rdn_attr_type(rdn);

			{
				int rc;
				const char *text;
				rc = slap_str2ad( type, &desc, &text );

				if( rc != LDAP_SUCCESS ) {
					err = LDAP_NO_SUCH_OBJECT;
					free(rdn);
					goto done;
				}
			}

			attr_merge( e, desc, vals );

			free(rdn);
			rdn = NULL;

			/* Every entry needs an objectclass. We don't really
			 * know if our hardcoded choice here agrees with the
			 * DN that was configured for this backend, but it's
			 * better than nothing.
			 *
			 * should be a configuratable item
			 */
			val.bv_val = "organizationalUnit";
			val.bv_len = sizeof("organizationalUnit")-1;
			attr_merge( e, ad_objectClass, vals );
	
			if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
				send_search_entry( be, conn, op,
					e, attrs, attrsonly, NULL );
				sent++;
			}
		}

		if ( scope != LDAP_SCOPE_BASE ) {
			/* check all our "children" */

			for ( pw = getpwent(); pw != NULL; pw = getpwent() ) {
				/* check for abandon */
				ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
				if ( op->o_abandon ) {
					ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
					endpwent();
					return( -1 );
				}
				ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

				/* check time limit */
				if ( slap_get_time() > stoptime ) {
					send_ldap_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
			    		NULL, NULL, NULL, NULL );
					endpwent();
					return( 0 );
				}

				e = pw2entry( be, pw, NULL );

				if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
					/* check size limit */
					if ( --slimit == -1 ) {
						send_ldap_result( conn, op, LDAP_SIZELIMIT_EXCEEDED,
				    		NULL, NULL, NULL, NULL );
						endpwent();
						return( 0 );
					}

					send_search_entry( be, conn, op,
						e, attrs, attrsonly, NULL );
					sent++;
				}

				entry_free( e );
			}
			endpwent();
		}

	} else {
		parent = dn_parent( be, nbase->bv_val );

		/* This backend is only one layer deep. Don't answer requests for
		 * anything deeper than that.
		 */
		if( !be_issuffix( be, parent ) ) {
			int i;
			for( i=0; be->be_nsuffix[i] != NULL; i++ ) {
				if( dnIsSuffix( nbase, be->be_nsuffix[i] ) ) {
					matched = be->be_suffix[i]->bv_val;
					break;
				}
			}
			err = LDAP_NO_SUCH_OBJECT;
			goto done;
		}

		if( scope == LDAP_SCOPE_ONELEVEL ) {
			goto done;
		}

		rdn = dn_rdn( NULL, base );

		if ( (user = rdn_attr_value(rdn)) == NULL) {
			err = LDAP_OPERATIONS_ERROR;
			goto done;
		}

		if ( (pw = getpwnam( user )) == NULL ) {
			matched = parent;
			err = LDAP_NO_SUCH_OBJECT;
			goto done;
		}

		e = pw2entry( be, pw, rdn );

		if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
			send_search_entry( be, conn, op,
				e, attrs, attrsonly, NULL );
			sent++;
		}

		entry_free( e );
	}

done:
	send_ldap_result( conn, op,
		err, err == LDAP_NO_SUCH_OBJECT ? matched : NULL, NULL,
		NULL, NULL );

	if( rdn != NULL ) free( rdn );
	if( user != NULL ) free( user );

	return( 0 );
}

static Entry *
pw2entry( Backend *be, struct passwd *pw, char *rdn )
{
	size_t pwlen;
	Entry		*e;
	struct berval	val;
	struct berval	*vals[2];
	struct berval	bv;

	int rc;
	const char *text;

	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	AttributeDescription *ad_cn = NULL;
	AttributeDescription *ad_sn = NULL;
	AttributeDescription *ad_uid = NULL;
	AttributeDescription *ad_description = NULL;

	rc = slap_str2ad( "cn", &ad_cn, &text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "sn", &ad_sn, &text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "uid", &ad_uid, &text );
	if(rc != LDAP_SUCCESS) return NULL;
	rc = slap_str2ad( "description", &ad_description, &text );
	if(rc != LDAP_SUCCESS) return NULL;

	/*
	 * from pw we get pw_name and make it cn
	 * give it an objectclass of person.
	 */

	pwlen = strlen( pw->pw_name );
	val.bv_len = (sizeof("uid=,")-1) + ( pwlen + be->be_suffix[0]->bv_len );
	val.bv_val = ch_malloc( val.bv_len + 1 );

	/* rdn attribute type should be a configuratable item */
	sprintf( val.bv_val, "uid=%s,%s",
		pw->pw_name, be->be_suffix[0]->bv_val );

	rc = dnNormalize2( NULL, &val, &bv );
	if( rc != LDAP_SUCCESS ) {
		free( val.bv_val );
		return NULL;
	}

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );
	e->e_name = val;
	e->e_nname = bv;

	e->e_attrs = NULL;

	vals[0] = &val;
	vals[1] = NULL;

	/* objectclasses should be configurable items */
	val.bv_val = "top";
	val.bv_len = sizeof("top")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "person";
	val.bv_len = sizeof("person")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = "uidObject";
	val.bv_len = sizeof("uidObject")-1;
	attr_merge( e, ad_objectClass, vals );

	val.bv_val = pw->pw_name;
	val.bv_len = pwlen;
	attr_merge( e, ad_uid, vals );	/* required by uidObject */
	attr_merge( e, ad_cn, vals );	/* required by person */
	attr_merge( e, ad_sn, vals );	/* required by person */

#ifdef HAVE_PW_GECOS
	/*
	 * if gecos is present, add it as a cn. first process it
	 * according to standard BSD usage. If the processed cn has
	 * a space, use the tail as the surname.
	 */
	if (pw->pw_gecos[0]) {
		char *s;

		val.bv_val = pw->pw_gecos;
		val.bv_len = strlen(val.bv_val);
		attr_merge(e, ad_description, vals);

		s = strchr(val.bv_val, ',');
		if (s) *s = '\0';

		s = strchr(val.bv_val, '&');
		if (s) {
			char buf[256];
			int i = s - val.bv_val;
			strncpy(buf, val.bv_val, i);
			s = buf+i;
			strcpy(s, pw->pw_name);
			*s = TOUPPER(*s);
			strcat(s, val.bv_val+i+1);
			val.bv_val = buf;
		}
		val.bv_len = strlen(val.bv_val);
		if ( strcmp( val.bv_val, pw->pw_name ))
			attr_merge( e, ad_cn, vals );
		if ( (s=strrchr(val.bv_val, ' '))) {
			val.bv_val = s + 1;
			val.bv_len = strlen(val.bv_val);
			attr_merge(e, ad_sn, vals);
		}
	}
#endif

	return( e );
}
