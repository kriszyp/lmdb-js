/* $OpenLDAP$ */
/* SASL LDAP auxprop implementation
 * Copyright (C) 2002,2003 Howard Chu, All rights reserved. <hyc@symas.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include <config.h>

#include <stdio.h>

#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"

#include "plugin_common.h"

#include <ldap.h>

static char ldapdb[] = "ldapdb";

typedef struct ldapctx {
	const char *uri;	/* URI of LDAP server */
	struct berval id;	/* SASL authcid to bind as */
	struct berval pw;	/* password for bind */
	struct berval mech;	/* SASL mech */
	int use_tls;		/* Issue StartTLS request? */
} ldapctx;

static int ldapdb_interact(LDAP *ld, unsigned flags __attribute__((unused)),
	void *def, void *inter)
{
	sasl_interact_t *in = inter;
	ldapctx *ctx = def;
	struct berval p;

	for (;in->id != SASL_CB_LIST_END;in++)
	{
		p.bv_val = NULL;
		switch(in->id)
		{
			case SASL_CB_GETREALM:
				ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &p.bv_val);
				if (p.bv_val) p.bv_len = strlen(p.bv_val);
				break;		
			case SASL_CB_AUTHNAME:
				p = ctx->id;
				break;
			case SASL_CB_PASS:
				p = ctx->pw;
				break;
		}
		if (p.bv_val)
		{
			in->result = p.bv_val;
			in->len = p.bv_len;
		}
	}
	return LDAP_SUCCESS;
}

typedef struct connparm {
	LDAP *ld;
	LDAPControl c;
	LDAPControl *ctrl[2];
	struct berval *dn;
} connparm;

static int ldapdb_connect(ldapctx *ctx, sasl_server_params_t *sparams,
	const char *user, unsigned ulen, connparm *cp)
{
    int i;
    char *authzid;

    if((i=ldap_initialize(&cp->ld, ctx->uri))) {
    	return i;
    }

    authzid = sparams->utils->malloc(ulen + sizeof("u:"));
    if (!authzid) {
    	return LDAP_NO_MEMORY;
    } 
    strcpy(authzid, "u:");
    strcpy(authzid+2, user);
    cp->c.ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
    cp->c.ldctl_value.bv_val = authzid;
    cp->c.ldctl_value.bv_len = ulen + 2;
    cp->c.ldctl_iscritical = 1;

    i = LDAP_VERSION3;
    ldap_set_option(cp->ld, LDAP_OPT_PROTOCOL_VERSION, &i);

    /* If TLS is set and it fails, continue or bail out as requested */
    if (ctx->use_tls && (i=ldap_start_tls_s(cp->ld, NULL, NULL)) != LDAP_SUCCESS
    	&& ctx->use_tls > 1) {
    	sparams->utils->free(authzid);
	return i;
    }

    i = ldap_sasl_interactive_bind_s(cp->ld, NULL, ctx->mech.bv_val, NULL,
    	NULL, LDAP_SASL_QUIET, ldapdb_interact, ctx);
    if (i != LDAP_SUCCESS) {
    	sparams->utils->free(authzid);
	return i;
    }
    
    cp->ctrl[0] = &cp->c;
    cp->ctrl[1] = NULL;
    i = ldap_whoami_s(cp->ld, &cp->dn, cp->ctrl, NULL);
    if (i == LDAP_SUCCESS && cp->dn) {
    	if (!cp->dn->bv_val || strncmp(cp->dn->bv_val, "dn:", 3)) {
	    ber_bvfree(cp->dn);
	    cp->dn = NULL;
	    i = LDAP_INVALID_SYNTAX;
	} else {
    	    cp->c.ldctl_value = *(cp->dn);
	}
    }
    sparams->utils->free(authzid);
    return i;
}

static void ldapdb_auxprop_lookup(void *glob_context,
				  sasl_server_params_t *sparams,
				  unsigned flags,
				  const char *user,
				  unsigned ulen)
{
    ldapctx *ctx = glob_context;
    connparm cp;
    int ret, i, n, *aindx;
    const struct propval *pr;
    struct berval **bvals;
    LDAPMessage *msg, *res;
    char **attrs = NULL;
    
    if(!ctx || !sparams || !user) return;

    pr = sparams->utils->prop_get(sparams->propctx);
    if(!pr) return;

    /* count how many attrs to fetch */
    for(i = 0, n = 0; pr[i].name; i++) {
	if(pr[i].name[0] == '*' && (flags & SASL_AUXPROP_AUTHZID))
	    continue;
	if(pr[i].values && !(flags & SASL_AUXPROP_OVERRIDE))
	    continue;
	n++;
    }
    /* nothing to do, bail out */
    if (!n) return;

    /* alloc an array of attr names for search, and index to the props */
    attrs = sparams->utils->malloc((n+1)*sizeof(char *)*2);
    if (!attrs) return;

    aindx = (int *)(attrs + n + 1);

    /* copy attr list */
    for (i=0, n=0; pr[i].name; i++) {
	if(pr[i].name[0] == '*' && (flags & SASL_AUXPROP_AUTHZID))
	    continue;
	if(pr[i].values && !(flags & SASL_AUXPROP_OVERRIDE))
	    continue;
    	attrs[n] = (char *)pr[i].name;
	if (pr[i].name[0] == '*') attrs[n]++;
	aindx[n] = i;
	n++;
    }
    attrs[n] = NULL;

    if(ldapdb_connect(ctx, sparams, user, ulen, &cp)) {
    	goto done;
    }

    ret = ldap_search_ext_s(cp.ld, cp.dn->bv_val+3, LDAP_SCOPE_BASE,
    	"(objectclass=*)", attrs, 0, cp.ctrl, NULL, NULL, 1, &res);
    ber_bvfree(cp.dn);

    if (ret != LDAP_SUCCESS) goto done;

    for(msg=ldap_first_message(cp.ld, res); msg; msg=ldap_next_message(cp.ld, msg))
    {
    	if (ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY) continue;
	for (i=0; i<n; i++)
	{
	    bvals = ldap_get_values_len(cp.ld, msg, attrs[i]);
	    if (!bvals) continue;
	    if (pr[aindx[i]].values)
	    	sparams->utils->prop_erase(sparams->propctx, pr[aindx[i]].name);
	    sparams->utils->prop_set(sparams->propctx, pr[aindx[i]].name,
				 bvals[0]->bv_val, bvals[0]->bv_len);
	    ber_bvecfree(bvals);
	}
    }
    ldap_msgfree(res);

 done:
    if(attrs) sparams->utils->free(attrs);
    if(cp.ld) ldap_unbind(cp.ld);
}

static int ldapdb_auxprop_store(void *glob_context,
				  sasl_server_params_t *sparams,
				  struct propctx *prctx,
				  const char *user,
				  unsigned ulen)
{
    ldapctx *ctx = glob_context;
    connparm cp;
    const struct propval *pr;
    int i, n;
    LDAPMod **mods;

    /* just checking if we are enabled */
    if (!prctx) return SASL_OK;

    if (!sparams || !user) return SASL_BADPARAM;

    pr = sparams->utils->prop_get(prctx);
    if (!pr) return SASL_BADPARAM;

    for (n=0; pr[n].name; n++);
    if (!n) return SASL_BADPARAM;

    mods = sparams->utils->malloc((n+1) * sizeof(LDAPMod*) + n * sizeof(LDAPMod));
    if (!mods) return SASL_NOMEM;

    if((i=ldapdb_connect(ctx, sparams, user, ulen, &cp)) == 0) {

	for (i=0; i<n; i++) {
	    mods[i] = (LDAPMod *)((char *)(mods+n+1) + i * sizeof(LDAPMod));
	    mods[i]->mod_op = LDAP_MOD_REPLACE;
	    mods[i]->mod_type = (char *)pr[i].name;
	    mods[i]->mod_values = (char **)pr[i].values;
	}
	mods[i] = NULL;

	i = ldap_modify_ext_s(cp.ld, cp.dn->bv_val+3, mods, cp.ctrl, NULL);
	ber_bvfree(cp.dn);
    }

    sparams->utils->free(mods);

    if (i) {
    	sparams->utils->seterror(sparams->utils->conn, 0,
	    ldap_err2string(i));
	if (i == LDAP_NO_MEMORY) i = SASL_NOMEM;
	else i = SASL_FAIL;
    }
    if (cp.ld) ldap_unbind(cp.ld);
    return i;
}

static void ldapdb_auxprop_free(void *glob_ctx, const sasl_utils_t *utils)
{
	utils->free(glob_ctx);
}

static sasl_auxprop_plug_t ldapdb_auxprop_plugin = {
    0,           /* Features */
    0,           /* spare */
    NULL,        /* glob_context */
    ldapdb_auxprop_free,	/* auxprop_free */
    ldapdb_auxprop_lookup,	/* auxprop_lookup */
    ldapdb,    /* name */
    ldapdb_auxprop_store	/* spare if <2.1.16*/
};

static int ldapdb_auxprop_plug_init(const sasl_utils_t *utils,
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname __attribute__((unused))) 
{
    ldapctx tmp, *p;
    const char *s;
    unsigned len;

    if(!out_version || !plug) return SASL_BADPARAM;

    if(max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    
    memset(&tmp, 0, sizeof(tmp));

    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_uri", &tmp.uri, NULL);
    if(!tmp.uri) return SASL_BADPARAM;

    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_id",
    	(const char **)&tmp.id.bv_val, &len);
    tmp.id.bv_len = len;
    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_pw",
    	(const char **)&tmp.pw.bv_val, &len);
    tmp.pw.bv_len = len;
    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_mech",
    	(const char **)&tmp.mech.bv_val, &len);
    tmp.mech.bv_len = len;
    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_starttls", &s, NULL);
    if (s)
    {
    	if (!strcasecmp(s, "demand")) tmp.use_tls = 2;
	else if (!strcasecmp(s, "try")) tmp.use_tls = 1;
    }
    utils->getopt(utils->getopt_context, ldapdb, "ldapdb_rc", &s, &len);
    if (s)
    {
    	char *str = utils->malloc(sizeof("LDAPRC=")+len);
	if (!str) return SASL_NOMEM;
	strcpy( str, "LDAPRC=" );
	strcpy( str + sizeof("LDAPRC=")-1, s );
	if (putenv(str))
	{
	    utils->free(str);
	    return SASL_NOMEM;
	}
    }

    p = utils->malloc(sizeof(ldapctx));
    if (!p) return SASL_NOMEM;
    *p = tmp;
    ldapdb_auxprop_plugin.glob_context = p;

    *out_version = SASL_AUXPROP_PLUG_VERSION;

    *plug = &ldapdb_auxprop_plugin;

    return SASL_OK;
}

SASL_AUXPROP_PLUG_INIT( ldapdb )

