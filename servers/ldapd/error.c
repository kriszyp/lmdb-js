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

#include <ac/ctype.h>
#include <ac/socket.h>

#include <quipu/ds_error.h>
#include <quipu/attrvalue.h>
#include <quipu/name.h>
#include <quipu/commonarg.h>

#include "lber.h"
#include "ldap.h"
#include "ldap_log.h"
#include "common.h"			/* get ldap_dn_print() */

void
print_error( struct DSError *e )
{
	PS	ps;

        if ( (ps = ps_alloc( std_open )) == NULLPS ) {
                fprintf( stderr, "error in ps_alloc\n" );
                return;
        }
        if ( std_setup( ps, stderr ) == NOTOK ) {
                fprintf( stderr, "error in std_setup = %d", ps->ps_errno );
                return;
        }

	ds_error( ps, e );

	ps_flush( ps );
	ps_free( ps );
}

int
x500err2ldaperr( struct DSError *e, char **matched )
{
	int		ldaperr = LDAP_OTHER;
	static PS	ps;

	Debug( LDAP_DEBUG_TRACE, "x500err2ldaperr\n", 0, 0, 0 );

	*matched = NULL;
	switch ( e->dse_type ) {
	case DSE_ATTRIBUTEERROR:
#if ISODEPACKAGE == IC || ISODEPACKAGE == XT
		switch ( e->ERR_ATTRIBUTE.DSE_at_plist->DSE_at_what ) {
#else
		switch ( e->ERR_ATTRIBUTE.DSE_at_plist.DSE_at_what ) {
#endif
		case DSE_AT_NOSUCHATTRIBUTE:
			ldaperr = LDAP_NO_SUCH_ATTRIBUTE;
			break;
		case DSE_AT_INVALIDATTRIBUTESYNTAX:
			ldaperr = LDAP_INVALID_SYNTAX;
			break;
		case DSE_AT_UNDEFINEDATTRIBUTETYPE:
			ldaperr = LDAP_UNDEFINED_TYPE;
			break;
		case DSE_AT_INAPPROPRIATEMATCHING:
			ldaperr = LDAP_INAPPROPRIATE_MATCHING;
			break;
		case DSE_AT_CONSTRAINTVIOLATION:
			ldaperr = LDAP_CONSTRAINT_VIOLATION;
			break;
		case DSE_AT_TYPEORVALUEEXISTS:
			ldaperr = LDAP_TYPE_OR_VALUE_EXISTS;
			break;
		default:
			break;
		}
		break;

	case DSE_NAMEERROR:
		switch( e->ERR_NAME.DSE_na_problem ) {
		case DSE_NA_NOSUCHOBJECT:
			ldaperr = LDAP_NO_SUCH_OBJECT;
			break;
		case DSE_NA_ALIASPROBLEM:
			ldaperr = LDAP_ALIAS_PROBLEM;
			break;
		case DSE_NA_INVALIDATTRIBUTESYNTAX:
			ldaperr = LDAP_INVALID_SYNTAX;
			break;
		case DSE_NA_ALIASDEREFERENCE:
			ldaperr = LDAP_ALIAS_DEREF_PROBLEM;
			break;
		default:
			break;
		}

		if ( e->ERR_NAME.DSE_na_matched == NULLDN ) {
			break;
		}

		if ( ps == NULL ) {
			ps = ps_alloc( str_open );
			str_setup( ps, NULLCP, 0, 0 );
		}
		ldap_dn_print( ps, e->ERR_NAME.DSE_na_matched, NULLDN, EDBOUT );
		*ps->ps_ptr = '\0';

		*matched = (char *) strdup( ps->ps_base );

		ps->ps_ptr = ps->ps_base;
		ps->ps_cnt = ps->ps_bufsiz;
		break;

	case DSE_SERVICEERROR:
		switch( e->ERR_SERVICE.DSE_sv_problem ) {
		case DSE_SV_BUSY:
			ldaperr = LDAP_BUSY;
			break;
		case DSE_SV_UNAVAILABLE:
			ldaperr = LDAP_UNAVAILABLE;
			break;
		case DSE_SV_UNWILLINGTOPERFORM:
			ldaperr = LDAP_UNWILLING_TO_PERFORM;
			break;
		case DSE_SV_TIMELIMITEXCEEDED:
			ldaperr = LDAP_TIMELIMIT_EXCEEDED;
			break;
		case DSE_SV_ADMINLIMITEXCEEDED:
			ldaperr = LDAP_SIZELIMIT_EXCEEDED;
			break;
		case DSE_SV_LOOPDETECT:
			ldaperr = LDAP_LOOP_DETECT;
			break;
		default:
			break;
		}
		break;

	case DSE_SECURITYERROR:
		switch( e->ERR_SECURITY.DSE_sc_problem ) {
		case DSE_SC_AUTHENTICATION:
			ldaperr = LDAP_INAPPROPRIATE_AUTH;
			break;
		case DSE_SC_INVALIDCREDENTIALS:
			ldaperr = LDAP_INVALID_CREDENTIALS;
			break;
		case DSE_SC_ACCESSRIGHTS:
			ldaperr = LDAP_INSUFFICIENT_ACCESS;
			break;
		default:
			break;
		}
		break;

	case DSE_UPDATEERROR:
		switch( e->ERR_UPDATE.DSE_up_problem ) {
		case DSE_UP_NAMINGVIOLATION:
			ldaperr = LDAP_NAMING_VIOLATION;
			break;
		case DSE_UP_OBJECTCLASSVIOLATION:
			ldaperr = LDAP_OBJECT_CLASS_VIOLATION;
			break;
		case DSE_UP_NOTONNONLEAF:
			ldaperr = LDAP_NOT_ALLOWED_ON_NONLEAF;
			break;
		case DSE_UP_NOTONRDN:
			ldaperr = LDAP_NOT_ALLOWED_ON_RDN;
			break;
		case DSE_UP_ALREADYEXISTS:
			ldaperr = LDAP_ALREADY_EXISTS;
			break;
		case DSE_UP_NOOBJECTCLASSMODS:
			ldaperr = LDAP_NO_OBJECT_CLASS_MODS;
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}

	return( ldaperr );
}
