/* search.c - /etc/passwd backend search function */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <pwd.h>

#include "slap.h"
#include "external.h"

static Entry	*pw2entry(Backend *be, struct passwd *pw);

int
passwd_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*base,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    char	*filterstr,
    char	**attrs,
    int		attrsonly
)
{
	struct passwd	*pw;
	Entry		*e;
	char		*s;
	time_t		stoptime;

	tlimit = (tlimit > be->be_timelimit || tlimit < 1) ? be->be_timelimit
	    : tlimit;
	stoptime = op->o_time + tlimit;
	slimit = (slimit > be->be_sizelimit || slimit < 1) ? be->be_sizelimit
	    : slimit;

#ifdef HAVE_SETPWFILE
	if ( be->be_private != NULL ) {
		endpwent();
		(void) setpwfile( (char *) be->be_private );
	}
#endif /* HAVE_SETPWFILE */

	if ( scope == LDAP_SCOPE_BASE ) {
		if ( (s = strchr( base, '@' )) != NULL ) {
			*s = '\0';
		}

		if ( (pw = getpwnam( base )) == NULL ) {
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			    s != NULL ? s + 1 : NULL, NULL );
			return( -1 );
		}

		e = pw2entry( be, pw );
		if ( test_filter( be, conn, op, e, filter ) == 0 ) {
			send_search_entry( be, conn, op, e, attrs, attrsonly );
		}
		entry_free( e );

		send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );

		return( 0 );
	}

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
			    NULL, NULL );
			endpwent();
			return( 0 );
		}

		e = pw2entry( be, pw );

		if ( test_filter( be, conn, op, e, filter ) == 0 ) {
			/* check size limit */
			if ( --slimit == -1 ) {
				send_ldap_result( conn, op, LDAP_SIZELIMIT_EXCEEDED,
				    NULL, NULL );
				endpwent();
				return( 0 );
			}

			send_search_entry( be, conn, op, e, attrs, attrsonly );
		}

		entry_free( e );
	}
	endpwent();
	send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );

	return( 0 );
}

static Entry *
pw2entry( Backend *be, struct passwd *pw )
{
	Entry		*e;
	char		buf[256];
	struct berval	val;
	struct berval	*vals[2];

	vals[0] = &val;
	vals[1] = NULL;

	/*
	 * from pw we get pw_name and make it uid and cn and sn and
	 * we get pw_gecos and make it cn and we give it an objectclass
	 * of person.
	 */

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );
	e->e_attrs = NULL;

	sprintf( buf, "%s@%s", pw->pw_name, be->be_suffix[0] );
	e->e_dn = ch_strdup( buf );
	e->e_ndn = dn_normalize_case( ch_strdup( buf ) );

	val.bv_val = pw->pw_name;
	val.bv_len = strlen( pw->pw_name );
	attr_merge( e, "cn", vals );
	attr_merge( e, "sn", vals );
	attr_merge( e, "uid", vals );
#ifdef HAVE_PW_GECOS
	val.bv_val = pw->pw_gecos;
	val.bv_len = strlen( pw->pw_gecos );
	attr_merge( e, "cn", vals );
#endif
	val.bv_val = "person";
	val.bv_len = strlen( val.bv_val );
	attr_merge( e, "objectclass", vals );

	return( e );
}
