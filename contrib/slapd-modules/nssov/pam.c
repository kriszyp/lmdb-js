/* pam.c - pam processing routines */
/* $OpenLDAP$ */
/*
 * Copyright 2009 by Howard Chu, Symas Corp.
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

#include "nssov.h"

#include <security/pam_modules.h>

static int ppolicy_cid;

struct bindinfo {
	int authz;
	struct berval msg;
};

static int pam_bindcb(
	Operation *op, SlapReply *rs)
{
	struct bindinfo *bi = op->o_callback->sc_private;
	LDAPControl *ctrl = ldap_control_find(LDAP_CONTROL_PASSWORDPOLICYRESPONSE,
		rs->sr_ctrls, NULL);
	if (ctrl) {
		LDAP *ld;
		ber_int_t expire, grace;
		LDAPPasswordPolicyError error;

		ldap_create(&ld);
		if (ld) {
			int rc = ldap_parse_passwordpolicy_control(ld,ctrl,
				&expire,&grace,&error);
			if (rc == LDAP_SUCCESS) {
				if (expire >= 0) {
					char *unit = "seconds";
					if (expire > 60) {
						expire /= 60;
						unit = "minutes";
					}
					if (expire > 60) {
						expire /= 60;
						unit = "hours";
					}
					if (expire > 24) {
						expire /= 24;
						unit = "days";
					}
#if 0	/* Who warns about expiration so far in advance? */
					if (expire > 7) {
						expire /= 7;
						unit = "weeks";
					}
					if (expire > 4) {
						expire /= 4;
						unit = "months";
					}
					if (expire > 12) {
						expire /= 12;
						unit = "years";
					}
#endif
					bi->msg.bv_len = sprintf(bi->msg.bv_val,
						"\nWARNING: Password expires in %d %s\n", expire, unit);
				} else if (grace > 0) {
					bi->msg.bv_len = sprintf(bi->msg.bv_val,
						"Password expired; %d grace logins remaining",
						grace);
					bi->authz = PAM_NEW_AUTHTOK_REQD;
				} else if (error != PP_noError) {
					ber_str2bv(ldap_passwordpolicy_err2txt(error), 0, 0,
						&bi->msg);
					switch (error) {
					case PP_passwordExpired:
						/* report this during authz */
						rs->sr_err = LDAP_SUCCESS;
						/* fallthru */
					case PP_changeAfterReset:
						bi->authz = PAM_NEW_AUTHTOK_REQD;
					}
				}
			}
			ldap_ld_free(ld,0,NULL,NULL);
		}
	}
	return LDAP_SUCCESS;
}

int pam_authc(nssov_info *ni,TFILE *fp,Operation *op)
{
	int32_t tmpint32;
	int rc;
	slap_callback cb = {0};
	SlapReply rs = {REP_RESULT};
	char uidc[32];
	char svcc[256];
	char pwdc[256];
	struct berval uid, svc, pwd, sdn, dn;
	int hlen;
	struct bindinfo bi;

	bi.authz = PAM_SUCCESS;
	bi.msg.bv_val = pwdc;
	bi.msg.bv_len = 0;

	READ_STRING_BUF2(fp,uidc,sizeof(uidc));
	uid.bv_val = uidc;
	uid.bv_len = tmpint32;
	READ_STRING_BUF2(fp,svcc,sizeof(svcc));
	svc.bv_val = svcc;
	svc.bv_len = tmpint32;
	READ_STRING_BUF2(fp,pwdc,sizeof(pwdc));
	pwd.bv_val = pwdc;
	pwd.bv_len = tmpint32;

	Debug(LDAP_DEBUG_TRACE,"nssov_pam_authc(%s)\n",uid.bv_val,0,0);

	if (!isvalidusername(&uid)) {
		Debug(LDAP_DEBUG_ANY,"nssov_pam_authc(%s): invalid user name\n",uid.bv_val,0,0);
		rc = PAM_USER_UNKNOWN;
		goto finish;
	}

	/* Why didn't we make this a berval? */
	hlen = strlen(global_host);

	/* First try this form, to allow service-dependent mappings */
	/* cn=<service>+uid=<user>,cn=<host>,cn=pam,cn=auth */
	sdn.bv_len = uid.bv_len + svc.bv_len + hlen + STRLENOF( "cn=+uid=,cn=,cn=pam,cn=auth" );
	sdn.bv_val = op->o_tmpalloc( sdn.bv_len + 1, op->o_tmpmemctx );
	sprintf(sdn.bv_val, "cn=%s+uid=%s,cn=%s,cn=pam,cn=auth", svcc, uidc, global_host);
	BER_BVZERO(&dn);
	slap_sasl2dn(op, &sdn, &dn, 0);
	op->o_tmpfree( sdn.bv_val, op->o_tmpmemctx );

	/* If no luck, do a basic uid search */
	if (BER_BVISEMPTY(&dn)) {
		if (!nssov_uid2dn(op, ni, &uid, &dn)) {
			rc = PAM_USER_UNKNOWN;
			goto finish;
		}
		sdn = dn;
		dnNormalize( 0, NULL, NULL, &sdn, &dn, op->o_tmpmemctx );
	}
	BER_BVZERO(&sdn);

	/* Should only need to do this once at open time, but there's always
	 * the possibility that ppolicy will get loaded later.
	 */
	if (!ppolicy_cid) {
		rc = slap_find_control_id(LDAP_CONTROL_PASSWORDPOLICYREQUEST,
			&ppolicy_cid);
	}
	/* of course, 0 is a valid cid, but it won't be ppolicy... */
	if (ppolicy_cid) {
		op->o_ctrlflag[ppolicy_cid] = SLAP_CONTROL_NONCRITICAL;
	}
	cb.sc_response = pam_bindcb;
	cb.sc_private = &bi;
	op->o_callback = &cb;
	op->o_dn.bv_val[0] = 0;
	op->o_dn.bv_len = 0;
	op->o_ndn.bv_val[0] = 0;
	op->o_ndn.bv_len = 0;
	op->o_tag = LDAP_REQ_BIND;
	op->o_protocol = LDAP_VERSION3;
	op->orb_method = LDAP_AUTH_SIMPLE;
	op->orb_cred = pwd;
	op->o_req_dn = dn;
	op->o_req_ndn = dn;
	slap_op_time( &op->o_time, &op->o_tincr );
	rc = op->o_bd->be_bind( op, &rs );
	memset(pwd.bv_val,0,pwd.bv_len);
	/* quirk: on successful bind, caller has to send result. we need
	 * to make sure callbacks run.
	 */
	if (rc == LDAP_SUCCESS)
		send_ldap_result(op, &rs);
	switch(rs.sr_err) {
	case LDAP_SUCCESS: rc = PAM_SUCCESS; break;
	case LDAP_INVALID_CREDENTIALS: rc = PAM_AUTH_ERR; break;
	default: rc = PAM_AUTH_ERR; break;
	}

finish:
	WRITE_INT32(fp,NSLCD_VERSION);
	WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHC);
	WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
	WRITE_INT32(fp,rc);
	WRITE_INT32(fp,bi.authz);	/* authz */
	WRITE_BERVAL(fp,&dn);
	WRITE_BERVAL(fp,&bi.msg);	/* authzmsg */
	return 0;
}

int pam_authz(nssov_info *ni,TFILE *fp,Operation *op)
{
	struct berval dn, svc;
	struct berval authzmsg = BER_BVNULL;
	struct berval tmpluser = BER_BVNULL;
	int32_t tmpint32;
	char dnc[1024];
	char svcc[256];

	READ_STRING_BUF2(fp,dnc,sizeof(dnc));
	dn.bv_val = dnc;
	dn.bv_len = tmpint32;
	READ_STRING_BUF2(fp,svcc,sizeof(svcc));
	svc.bv_val = svcc;
	svc.bv_len = tmpint32;

	Debug(LDAP_DEBUG_TRACE,"nssov_pam_authz(%s)\n",dn.bv_val,0,0);

	WRITE_INT32(fp,NSLCD_VERSION);
	WRITE_INT32(fp,NSLCD_ACTION_PAM_AUTHZ);
	WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
	WRITE_INT32(fp,PAM_SUCCESS);
	WRITE_BERVAL(fp,&authzmsg);
	WRITE_BERVAL(fp,&tmpluser);
	return 0;
}

int pam_sess_o(nssov_info *ni,TFILE *fp,Operation *op)
{
	struct berval dn, svc;
	int32_t tmpint32;
	char dnc[1024];
	char svcc[256];

	READ_STRING_BUF2(fp,dnc,sizeof(dnc));
	dn.bv_val = dnc;
	dn.bv_len = tmpint32;
	READ_STRING_BUF2(fp,svcc,sizeof(svcc));
	svc.bv_val = svcc;
	svc.bv_len = tmpint32;

	Debug(LDAP_DEBUG_TRACE,"nssov_pam_sess_o(%s)\n",dn.bv_val,0,0);

	WRITE_INT32(fp,NSLCD_VERSION);
	WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_O);
	WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
	return 0;
}

int pam_sess_c(nssov_info *ni,TFILE *fp,Operation *op)
{
	struct berval dn, svc;
	int32_t tmpint32;
	char dnc[1024];
	char svcc[256];

	READ_STRING_BUF2(fp,dnc,sizeof(dnc));
	dn.bv_val = dnc;
	dn.bv_len = tmpint32;
	READ_STRING_BUF2(fp,svcc,sizeof(svcc));
	svc.bv_val = svcc;
	svc.bv_len = tmpint32;

	Debug(LDAP_DEBUG_TRACE,"nssov_pam_sess_c(%s)\n",dn.bv_val,0,0);

	WRITE_INT32(fp,NSLCD_VERSION);
	WRITE_INT32(fp,NSLCD_ACTION_PAM_SESS_C);
	WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
	return 0;
}

int pam_pwmod(nssov_info *ni,TFILE *fp,Operation *op)
{
	struct berval dn, uid, opw, npw;
	int32_t tmpint32;
	char dnc[1024];
	char uidc[256];
	char opwc[256];
	char npwc[256];

	READ_STRING_BUF2(fp,dnc,sizeof(dnc));
	dn.bv_val = dnc;
	dn.bv_len = tmpint32;
	READ_STRING_BUF2(fp,uidc,sizeof(uidc));
	uid.bv_val = uidc;
	uid.bv_len = tmpint32;
	READ_STRING_BUF2(fp,opwc,sizeof(opwc));
	opw.bv_val = opwc;
	opw.bv_len = tmpint32;
	READ_STRING_BUF2(fp,npwc,sizeof(npwc));
	npw.bv_val = npwc;
	npw.bv_len = tmpint32;

	Debug(LDAP_DEBUG_TRACE,"nssov_pam_pwmod(%s), %s\n",dn.bv_val,uid.bv_val,0);

	BER_BVZERO(&npw);
	WRITE_INT32(fp,NSLCD_VERSION);
	WRITE_INT32(fp,NSLCD_ACTION_PAM_PWMOD);
	WRITE_INT32(fp,NSLCD_RESULT_SUCCESS);
	WRITE_INT32(fp,PAM_SUCCESS);
	WRITE_BERVAL(fp,&npw);
	return 0;
}
