/* user.c - set user id, group id and group access list
 *
 * Copyright 1999 by PM Lashley and The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
*/

#include "portable.h"

#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include <ac/ctype.h>
#include <ac/unistd.h>

#include "slap.h"


/*
 * Set real and effective user id and group id, and group access list
 */

void
slap_init_user( char *user, char *group )
{
    uid_t	uid = (gid_t) -1;
    gid_t	gid = (gid_t) -1;

    if ( user ) {
	struct passwd *pwd;
	if ( isdigit( (unsigned char) *user )) {
	    uid = atoi( user );
#ifdef HAVE_GETPWUID
	    pwd = getpwuid( uid );
	    goto did_getpw;
#endif
	} else {
	    pwd = getpwnam( user );
	did_getpw:
	    if ( pwd == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No passwd entry for user %s\n",
		       user, 0, 0 );
		exit( 1 );
	    }
	    if ( uid >= 0 ) {
		free( user );
		user = (pwd != NULL ? ch_strdup( pwd->pw_name ) : NULL);
	    } else {
		uid = pwd->pw_uid;
	    }
	    gid = pwd->pw_gid;
#ifdef HAVE_ENDPWENT
	    endpwent();
#endif
	}
    }

    if ( group ) {
	struct group *grp;
	if ( isdigit( (unsigned char) *group )) {
	    gid = atoi( group );
#ifdef HAVE_GETGRGID
	    grp = getgrgid( gid );
	    goto did_group;
#endif
	} else {
	    grp = getgrnam( group );
	    if ( grp != NULL )
		gid = grp->gr_gid;
	did_group:
	    if ( grp == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No group entry for group %s\n",
		       group, 0, 0 );
		exit( 1 );
	    }
	}
	free( group );
    }

    if ( user ) {
	if ( getuid() == 0 && initgroups( user, gid ) != 0 ) {
	    Debug( LDAP_DEBUG_ANY,
		   "Could not set the group access (gid) list\n", 0, 0, 0 );
	    exit( 1 );
	}
	free( user );
    }

#ifdef HAVE_ENDGRENT
    endgrent();
#endif

    if ( gid >= 0 ) {
	if ( setgid( gid ) != 0 ) {
	    Debug( LDAP_DEBUG_ANY, "Could not set real group id to %d\n",
		   gid, 0, 0 );
	    exit( 1 );
	}
	if ( setegid( gid ) != 0 ) {
	    Debug( LDAP_DEBUG_ANY, "Could not set effective group id to %d\n",
		   gid, 0, 0 );
	    exit( 1 );
	}
    }

    if ( uid >= 0 ) {
	if ( setuid( uid ) != 0 ) {
	    Debug( LDAP_DEBUG_ANY, "Could not set effective user id to %d\n",
		   uid, 0, 0 );
	    exit( 1 );
	}
	if ( seteuid( uid ) != 0 ) {
	    Debug( LDAP_DEBUG_ANY, "Could not set real user id to %d\n",
		   uid, 0, 0 );
	    exit( 1 );
	}
    }
}

#endif /* HAVE_PWD_H && HAVE_GRP_H */
