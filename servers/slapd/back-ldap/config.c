/* config.c - ldap backend configuration file routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* This is an altered version */
/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: ldap backend info is null!\n",
		    fname, lineno );
		return( 1 );
	}

	/* server address to query (depricated, use "uri" directive) */
	if ( strcasecmp( argv[0], "server" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing address in \"server <address>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if (li->url != NULL)
			ch_free(li->url);
		li->url = ch_calloc(strlen(argv[1]) + 9, sizeof(char));
		if (li->url != NULL) {
			strcpy(li->url, "ldap://");
			strcat(li->url, argv[1]);
			strcat(li->url, "/");
		}

	/* URI of server to query (preferred over "server" directive) */
	} else if ( strcasecmp( argv[0], "uri" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing address in \"uri <address>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if (li->url != NULL)
			ch_free(li->url);
		li->url = ch_strdup(argv[1]);

	/* name to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "binddn" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing name in \"binddn <name>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->binddn = ch_strdup(argv[1]);

	/* password to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "bindpw" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing password in \"bindpw <password>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->bindpw = ch_strdup(argv[1]);
	
	/* dn massaging */
	} else if ( strcasecmp( argv[0], "suffixmassage" ) == 0 ) {
		char *dn, *massaged_dn;
		BackendDB *tmp_be;
		
		if ( argc != 3 ) {
			fprintf( stderr,
	"%s: line %d: syntax is \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno );
			return( 1 );
		}
		
		tmp_be = select_backend( argv[1], 0 );
		if ( tmp_be != NULL && tmp_be != be ) {
			fprintf( stderr,
	"%s: line %d: suffix already in use by another backend in"
	" \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno );
			return( 1 );						
		}

		tmp_be = select_backend( argv[2], 0 );
		if ( tmp_be != NULL ) {
			fprintf( stderr,
        "%s: line %d: massaged suffix already in use by another backend in" 
        " \"suffixMassage <suffix> <massaged suffix>\"\n",
                                fname, lineno );
                        return( 1 );
		}
		
                dn = ch_strdup( argv[1] );
		charray_add( &li->suffix_massage, dn );
		(void) dn_normalize( dn );
		charray_add( &li->suffix_massage, dn );
		
		massaged_dn = ch_strdup( argv[2] );
		charray_add( &li->suffix_massage, massaged_dn );
		(void) dn_normalize( massaged_dn );
		charray_add( &li->suffix_massage, massaged_dn );
		
		free( dn );
		free( massaged_dn );

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in ldap database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}
	return 0;
}
