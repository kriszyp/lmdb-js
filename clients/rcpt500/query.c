/* $OpenLDAP$ */
/*
 * query.c: for rcpt500 (X.500 email query responder)
 *
 * 18 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

#include "portable.h"

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/time.h>

#include <stdio.h>

#include <ldap.h>
#include <disptmpl.h>

#include "rcpt500.h"
#include "ldap_defaults.h"

static char buf[ MAXSIZE ];
static char *errpreface = "Your query failed: ";

static void close_ldap(LDAP *ld);
static void append_entry_list(char *rep, char *qu, LDAP *ld, LDAPMessage *msg);
static int  append_text(void *reply, char *text, ber_len_t len);
static int  do_read (LDAP *ld, char *dn, char *rep, struct ldap_disptmpl *tmp);
static void report_ldap_err (LDAP *ldp, char *reply);
static void remove_trailing_space (char *s);


int
query_cmd( struct msginfo *msgp, char *reply )
{
    LDAP			*ldp;
    LDAPMessage			*ldmsgp, *entry;
    char			*dn;
    int				matches, rc, ld_errno, ufn;
    LDAPFiltDesc		*lfdp;
    LDAPFiltInfo		*lfi;
    struct ldap_disptmpl	*tmpllist = NULL;
    static char	*attrs[] = { "cn", "title",
#ifdef RCPT500_SORT_ATTR
			RCPT500_SORT_ATTR,
#endif
			NULL };

    ufn = 0;

    if ( msgp->msg_arg == NULL ) {
	return( help_cmd( msgp, reply ));
    }

    remove_trailing_space( msgp->msg_arg );
    if ( *msgp->msg_arg == '\0' ) {
	return( help_cmd( msgp, reply ));
    }

    if (( lfdp = ldap_init_getfilter( filterfile )) == NULL ) {
	strcat( reply, errpreface );
	strcat( reply, "filter file configuration error.  Try again later." );
	return( 0 );
    }

    /*
     * open connection to LDAP server and bind as dapuser
     */
#ifdef LDAP_CONNECTIONLESS
    if ( do_cldap )
	ldp = cldap_open( ldaphost, ldapport );
    else
#endif /* LDAP_CONNECTIONLESS */
	ldp = ldap_init( ldaphost, ldapport );

    if ( ldp == NULL ) {
	strcat( reply, errpreface );
	strcat( reply, "X.500 service unavailable.  Try again later." );
	ldap_getfilter_free( lfdp );
	return( 0 );
    }

#ifdef LDAP_CONNECTIONLESS
    if ( !do_cldap )
#endif /* LDAP_CONNECTIONLESS */
	if ( ldap_simple_bind_s( ldp, dapuser, NULL ) != LDAP_SUCCESS ) {
	    report_ldap_err( ldp, reply );
	    close_ldap( ldp );
	    ldap_getfilter_free( lfdp );
	    return( 0 );
	}

    /*
     * set options for search and build filter
     */
	ldap_set_option(ldp, LDAP_OPT_DEREF, &derefaliases);
	ldap_set_option(ldp, LDAP_OPT_SIZELIMIT, &sizelimit);

    matches = 0;

#ifdef RCPT500_UFN
#ifdef LDAP_CONNECTIONLESS
    if ( !do_cldap && strchr( msgp->msg_arg, ',' ) != NULL ) {
#else /* LDAP_CONNECTIONLESS */
    if ( strchr( msgp->msg_arg, ',' ) != NULL ) {
#endif /* LDAP_CONNECTIONLESS */
	struct timeval	tv;

	ldap_ufn_setprefix( ldp, searchbase );
	if (( rc = ldap_ufn_search_s( ldp, msgp->msg_arg, attrs, 0, &ldmsgp ))
		!= LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED
		&& rc != LDAP_TIMELIMIT_EXCEEDED ) {
	    report_ldap_err( ldp, reply );
	    close_ldap( ldp );
	    ldap_getfilter_free( lfdp );
	    return( 0 );
	}
	matches = ldap_count_entries( ldp, ldmsgp );
	ufn = 1;
    } else {
#endif /* RCPT500_UFN */
    
	for ( lfi = ldap_getfirstfilter( lfdp, "rcpt500", msgp->msg_arg );
		lfi != NULL; lfi = ldap_getnextfilter( lfdp )) {
#ifdef LDAP_CONNECTIONLESS
	    if ( do_cldap )
		rc = cldap_search_s( ldp, searchbase, LDAP_SCOPE_SUBTREE,
			lfi->lfi_filter, attrs, 0, &ldmsgp, dapuser );
	    else 
#endif /* LDAP_CONNECTIONLESS */
		rc = ldap_search_s( ldp, searchbase, LDAP_SCOPE_SUBTREE,
			lfi->lfi_filter, attrs, 0, &ldmsgp );

	    if ( rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED
		    && rc != LDAP_TIMELIMIT_EXCEEDED ) {
		report_ldap_err( ldp, reply );
		close_ldap( ldp );
		ldap_getfilter_free( lfdp );
		return( 0 );
	    }

	    if (( matches = ldap_count_entries( ldp, ldmsgp )) != 0 ) {
		break;
	    }

	    if ( ldmsgp != NULL ) {
		ldap_msgfree( ldmsgp );
	    }
	}
#ifdef RCPT500_UFN
    }
#endif /* RCPT500_UFN */

    if ( matches == 0 ) {
	sprintf( buf, "No matches were found for '%s'\n", msgp->msg_arg );
	strcat( reply, buf );
	close_ldap( ldp );
	ldap_getfilter_free( lfdp );
	return( 0 );
    }

	ld_errno = 0;
	ldap_get_option(ldp, LDAP_OPT_ERROR_NUMBER, &ld_errno);

    if ( ld_errno == LDAP_TIMELIMIT_EXCEEDED
	    || ld_errno == LDAP_SIZELIMIT_EXCEEDED ) {
	strcat( reply, "(Partial results only - a limit was exceeded)\n" );
    }

    if ( matches <= RCPT500_LISTLIMIT ) {
	sprintf( buf, "%d %s match%s found for '%s':\n\n", matches,
		ufn ? "UFN" : lfi->lfi_desc,
		( matches > 1 ) ? "es" : "", msgp->msg_arg );
	strcat( reply, buf );

	if (( rc = ldap_init_templates( templatefile, &tmpllist )) != 0 ) {
	    sprintf( buf, "%s ldap_init_templates( %s ) failed (error %d)\n",
		errpreface, templatefile, rc );
	    strcat( reply, buf );
	}

	for ( entry = ldap_first_entry( ldp, ldmsgp ); entry != NULL; ) {
	    dn = ldap_get_dn( ldp, entry );
	    if ( do_read( ldp, dn, reply, tmpllist ) != LDAP_SUCCESS ) {
		report_ldap_err( ldp, reply );
	    }
	    free( dn );
	    if (( entry = ldap_next_entry( ldp, entry )) != NULL ) {
		strcat( reply, "\n-------\n\n" );
	    }
	}

	if ( tmpllist != NULL ) {
	    ldap_free_templates( tmpllist );
	}
	ldap_msgfree( ldmsgp );

    } else {
	sprintf( buf, "%d %s matches were found for '%s':\n",
		matches, ufn ? "UFN" : lfi->lfi_desc, msgp->msg_arg );
	strcat( reply, buf );
	append_entry_list( reply, msgp->msg_arg, ldp, ldmsgp );
	ldap_msgfree( ldmsgp );
    }

    close_ldap( ldp );
    ldap_getfilter_free( lfdp );
    return( 0 );
}


static void
close_ldap( LDAP *ld )
{
#ifdef LDAP_CONNECTIONLESS
    if ( do_cldap )
	cldap_close( ld );
    else
#endif /* LDAP_CONNECTIONLESS */
	ldap_unbind( ld );
}


static void
append_entry_list( char *reply, char *query, LDAP *ldp, LDAPMessage *ldmsgp )
{
    LDAPMessage	*e;
    char	*dn, *rdn, *s, **title;
    int		free_rdn = 0;

#ifdef RCPT500_SORT_ATTR
    ldap_sort_entries( ldp, &ldmsgp, RCPT500_SORT_ATTR, strcasecmp );
#endif

    for ( e = ldap_first_entry( ldp, ldmsgp ); e != NULL;
		e = ldap_next_entry( ldp, e )) {
	dn = ldap_get_dn( ldp, e );
	if (( s = strchr( dn, ',' )) != NULL ) {
	    *s = '\0';
	}
	if (( s = strchr( dn, '=' )) == NULL ) {
	    rdn = dn;
	} else {
	    rdn = s + 1;
	}

#ifdef UOFM
	/*
	 * if this entry's rdn is an exact match for the thing looked up, we
	 * return the CN that has a digit after it, so that the user is
	 * returned something guaranteed to yield exactly one match if they
	 * pick it from the list and query it
	 */

	if ( strcasecmp( rdn, query ) == 0 ) {
	    char	**cn;
	    int		i;

	    if (( cn = ldap_get_values( ldp, e, "cn" )) != NULL ) {
		for ( i = 0; cn[i] != NULL; i++ ) {
		    if ( isdigit((unsigned char) cn[i][strlen( cn[i] ) - 1])) {
			rdn = strdup( cn[i] );
			free_rdn = 1;
			break;
		    }
		}
		ldap_value_free( cn );
	    }
	}
#endif /* UOFM */

	title = ldap_get_values( ldp, e, "title" );
	sprintf( buf, "  %-20s    %s\n", rdn, title ? title[0] : "" );
	strcat( reply, buf );
	if ( title != NULL ) {
	    ldap_value_free( title );
	}
	free( dn );
	if ( free_rdn ) {
	    free( rdn );
	}
    }
}


static int
append_text( void *reply, char *text, ber_len_t len )
{
    strcat( (char *) reply, text );
    return( len );
}
    

static int
do_read( LDAP *ldp, char *dn, char *reply, struct ldap_disptmpl *tmpll )
{
    int				rc;
    static char	*maildefvals[] = { "None registered in this service", NULL };
    static char	*defattrs[] = { "mail", NULL };
    static char	**defvals[] = { maildefvals, NULL };


    rc = ldap_entry2text_search( ldp, dn, searchbase, NULL, tmpll,
	    defattrs, defvals, append_text, (void *)reply, "\n",
	    rdncount, LDAP_DISP_OPT_DOSEARCHACTIONS );

    return( rc );
}


static void
report_ldap_err( LDAP *ldp, char *reply )
{
	int ld_errno = 0;
	ldap_get_option(ldp, LDAP_OPT_ERROR_NUMBER, &ld_errno);

    strcat( reply, errpreface );
    strcat( reply, ldap_err2string( ld_errno ));
    strcat( reply, "\n" );
}


static void
remove_trailing_space( char *s )
{
    char	*p = s + strlen( s ) - 1;

    while ( isspace( (unsigned char) *p ) && p > s ) {
	--p;
    }
    *(++p) = '\0';
}
