/* extended.c - ldap backend extended routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2007 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati. 
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"
#include "lber_pvt.h"

static BI_op_extended ldap_back_exop_passwd;
static BI_op_extended ldap_back_exop_generic;

static struct exop {
	struct berval	oid;
	BI_op_extended	*extended;
} exop_table[] = {
	{ BER_BVC(LDAP_EXOP_MODIFY_PASSWD),	ldap_back_exop_passwd },
	{ BER_BVNULL, NULL }
};

static int
ldap_back_extended_one( Operation *op, SlapReply *rs, BI_op_extended exop )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;

	ldapconn_t	*lc = NULL;
	LDAPControl	**oldctrls = NULL;
	int		rc;

	/* FIXME: this needs to be called here, so it is
	 * called twice; maybe we could avoid the 
	 * ldap_back_dobind() call inside each extended()
	 * call ... */
	if ( !ldap_back_dobind( &lc, op, rs, LDAP_BACK_SENDERR ) ) {
		return -1;
	}

	oldctrls = op->o_ctrls;
	if ( ldap_back_proxy_authz_ctrl( &lc->lc_bound_ndn,
		li->li_version, &li->li_idassert, op, rs, &op->o_ctrls ) )
	{
		op->o_ctrls = oldctrls;
		send_ldap_extended( op, rs );
		rs->sr_text = NULL;
		/* otherwise frontend resends result */
		rc = rs->sr_err = SLAPD_ABANDON;
		goto done;
	}

	rc = exop( op, rs );

	if ( op->o_ctrls && op->o_ctrls != oldctrls ) {
		free( op->o_ctrls[ 0 ] );
		free( op->o_ctrls );
	}
	op->o_ctrls = oldctrls;

done:;
	if ( lc != NULL ) {
		ldap_back_release_conn( li, lc );
	}
			
	return rc;
}

int
ldap_back_extended(
		Operation	*op,
		SlapReply	*rs )
{
	int	i;

	for ( i = 0; exop_table[i].extended != NULL; i++ ) {
		if ( bvmatch( &exop_table[i].oid, &op->oq_extended.rs_reqoid ) )
		{
			return ldap_back_extended_one( op, rs, exop_table[i].extended );
		}
	}

	/* if we get here, the exop is known; the best that we can do
	 * is pass it thru as is */
	/* FIXME: maybe a list of OIDs to pass thru would be safer */
	return ldap_back_extended_one( op, rs, ldap_back_exop_generic );
}

static int
ldap_back_exop_passwd(
		Operation	*op,
		SlapReply	*rs )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;

	ldapconn_t	*lc = NULL;
	req_pwdexop_s	*qpw = &op->oq_pwdexop;
	LDAPMessage	*res;
	ber_int_t	msgid;
	int		rc, isproxy;
	int		do_retry = 1;
	char *text = NULL;

	if ( !ldap_back_dobind( &lc, op, rs, LDAP_BACK_SENDERR ) ) {
		return -1;
	}

	isproxy = ber_bvcmp( &op->o_req_ndn, &op->o_ndn );

	Debug( LDAP_DEBUG_ARGS, "==> ldap_back_exop_passwd(\"%s\")%s\n",
		op->o_req_dn.bv_val, isproxy ? " (proxy)" : "", 0 );

retry:
	rc = ldap_passwd( lc->lc_ld, isproxy ? &op->o_req_dn : NULL,
		qpw->rs_old.bv_val ? &qpw->rs_old : NULL,
		qpw->rs_new.bv_val ? &qpw->rs_new : NULL,
		op->o_ctrls, NULL, &msgid );

	if ( rc == LDAP_SUCCESS ) {
		if ( ldap_result( lc->lc_ld, msgid, LDAP_MSG_ALL, NULL, &res ) == -1 ) {
			ldap_get_option( lc->lc_ld, LDAP_OPT_ERROR_NUMBER, &rc );
			rs->sr_err = rc;

		} else {
			/* only touch when activity actually took place... */
			if ( li->li_idle_timeout && lc ) {
				lc->lc_time = op->o_time;
			}

			/* sigh. parse twice, because parse_passwd
			 * doesn't give us the err / match / msg info.
			 */
			rc = ldap_parse_result( lc->lc_ld, res, &rs->sr_err,
					(char **)&rs->sr_matched,
					&text,
					NULL, NULL, 0 );
#ifndef LDAP_NULL_IS_NULL
			if ( rs->sr_matched && rs->sr_matched[ 0 ] == '\0' ) {
				free( (char *)rs->sr_matched );
				rs->sr_matched = NULL;
			}
			if ( rs->sr_text && rs->sr_text[ 0 ] == '\0' ) {
				free( (char *)rs->sr_text );
				rs->sr_text = NULL;
			}
#endif /* LDAP_NULL_IS_NULL */

			if ( rc == LDAP_SUCCESS ) {
				if ( rs->sr_err == LDAP_SUCCESS ) {
					struct berval	newpw;

					/* this never happens because 
					 * the frontend	is generating 
					 * the new password, so when
					 * the passwd exop is proxied,
					 * it never delegates password
					 * generation to the remote server
					 */
					rc = ldap_parse_passwd( lc->lc_ld, res,
							&newpw );
					if ( rc == LDAP_SUCCESS &&
							!BER_BVISNULL( &newpw ) )
					{
						rs->sr_type = REP_EXTENDED;
						rs->sr_rspdata = slap_passwd_return( &newpw );
						free( newpw.bv_val );
					}

				} else {
					rc = rs->sr_err;
				}
			}
			ldap_msgfree( res );
		}
	}

	if ( rc != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
			do_retry = 0;
			if ( ldap_back_retry( &lc, op, rs, LDAP_BACK_SENDERR ) ) {
				goto retry;
			}
		}

		if ( LDAP_BACK_QUARANTINE( li ) ) {
			ldap_back_quarantine( op, rs );
		}

		if ( text ) rs->sr_text = text;
		send_ldap_extended( op, rs );
		/* otherwise frontend resends result */
		rc = rs->sr_err = SLAPD_ABANDON;

	} else if ( LDAP_BACK_QUARANTINE( li ) ) {
		ldap_back_quarantine( op, rs );
	}

	/* these have to be freed anyway... */
	if ( rs->sr_matched ) {
		free( (char *)rs->sr_matched );
		rs->sr_matched = NULL;
	}

	if ( text ) {
		free( text );
		rs->sr_text = NULL;
	}

	if ( lc != NULL ) {
		ldap_back_release_conn( li, lc );
	}

	return rc;
}

static int
ldap_back_exop_generic(
	Operation	*op,
	SlapReply	*rs )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;

	ldapconn_t	*lc = NULL;
	LDAPMessage	*res;
	ber_int_t	msgid;
	int		rc;
	int		do_retry = 1;
	char *text = NULL;

	if ( !ldap_back_dobind( &lc, op, rs, LDAP_BACK_SENDERR ) ) {
		return -1;
	}

	Debug( LDAP_DEBUG_ARGS, "==> ldap_back_exop_generic(%s, \"%s\")\n",
		op->ore_reqoid.bv_val, op->o_req_dn.bv_val, 0 );

retry:
	rc = ldap_extended_operation( lc->lc_ld,
		op->ore_reqoid.bv_val, op->ore_reqdata,
		op->o_ctrls, NULL, &msgid );

	if ( rc == LDAP_SUCCESS ) {
		if ( ldap_result( lc->lc_ld, msgid, LDAP_MSG_ALL, NULL, &res ) == -1 ) {
			ldap_get_option( lc->lc_ld, LDAP_OPT_ERROR_NUMBER, &rc );
			rs->sr_err = rc;

		} else {
			/* only touch when activity actually took place... */
			if ( li->li_idle_timeout && lc ) {
				lc->lc_time = op->o_time;
			}

			/* sigh. parse twice, because parse_passwd
			 * doesn't give us the err / match / msg info.
			 */
			rc = ldap_parse_result( lc->lc_ld, res, &rs->sr_err,
					(char **)&rs->sr_matched,
					&text,
					NULL, NULL, 0 );
#ifndef LDAP_NULL_IS_NULL
			if ( rs->sr_matched && rs->sr_matched[ 0 ] == '\0' ) {
				free( (char *)rs->sr_matched );
				rs->sr_matched = NULL;
			}
			if ( rs->sr_text && rs->sr_text[ 0 ] == '\0' ) {
				free( (char *)rs->sr_text );
				rs->sr_text = NULL;
			}
#endif /* LDAP_NULL_IS_NULL */
			if ( rc == LDAP_SUCCESS ) {
				if ( rs->sr_err == LDAP_SUCCESS ) {
					rc = ldap_parse_extended_result( lc->lc_ld, res,
							(char **)&rs->sr_rspoid, &rs->sr_rspdata, 0 );
					if ( rc == LDAP_SUCCESS ) {
						rs->sr_type = REP_EXTENDED;
					}

				} else {
					rc = rs->sr_err;
				}
			}
			ldap_msgfree( res );
		}
	}

	if ( rc != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
			do_retry = 0;
			if ( ldap_back_retry( &lc, op, rs, LDAP_BACK_SENDERR ) ) {
				goto retry;
			}
		}

		if ( LDAP_BACK_QUARANTINE( li ) ) {
			ldap_back_quarantine( op, rs );
		}

		if ( text ) rs->sr_text = text;
		send_ldap_extended( op, rs );
		/* otherwise frontend resends result */
		rc = rs->sr_err = SLAPD_ABANDON;

	} else if ( LDAP_BACK_QUARANTINE( li ) ) {
		ldap_back_quarantine( op, rs );
	}

	/* these have to be freed anyway... */
	if ( rs->sr_matched ) {
		free( (char *)rs->sr_matched );
		rs->sr_matched = NULL;
	}

	if ( text ) {
		free( text );
		rs->sr_text = NULL;
	}

	if ( lc != NULL ) {
		ldap_back_release_conn( li, lc );
	}

	return rc;
}

