/* bconfig.c - the config backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005 The OpenLDAP Foundation.
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
 * This work was originally developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "config.h"

#define CONFIG_DN	"cn=config"

typedef struct CfEntryInfo {
	struct CfEntryInfo *ce_sibs;
	struct CfEntryInfo *ce_kids;
	Entry *ce_entry;
	BackendInfo *ce_bi;
	BackendDB *ce_be;
} CfEntryInfo;

typedef struct {
	ConfigFile *cb_config;
	CfEntryInfo *cb_root;
} CfBackInfo;

static AttributeDescription *cfAd_backend, *cfAd_database, *cfAd_overlay,
	*cfAd_include;

static ObjectClass *cfOc_global, *cfOc_backend, *cfOc_database,
	*cfOc_include, *cfOc_overlay;

static struct oc_info {
	char *def;
	ObjectClass **oc;
} cf_ocs[] = {
	{ "( OLcfgOc:1 "
		"NAME 'olcConfig' "
		"DESC 'OpenLDAP configuration object' "
		"ABSTRACT SUP top "
		"MAY ( cn $ olcConfigFile ) )", NULL },
	{ "( OLcfgOc:3 "
		"NAME 'olcGlobal' "
		"DESC 'OpenLDAP Global configuration options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcAccess $ olcAllows $ olcArgsFile $ olcAttributeOptions $ "
		 "olcAuthRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ "
		 "olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ "
		 "olcDefaultSearchBase $ olcDisallows $ olcGentleHUP $ "
		 "olcIdleTimeout $ olcIndexSubstrIfMaxLen $ olcIndexSubstrIfMinLen $ "
		 "olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcLocalSSF $ "
		 "olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectIdentifier $ "
		 "olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ "
		 "olcPlugin $ olcPluginLogFile $ olcReadOnly $ olcReferral $ "
		 "olcReplicaPidFile $ olcReplicaArgsFile $ olcReplicationInterval $ "
		 "olcReplogFile $ olcRequires $ olcRestrict $ olcReverseLookup $ "
		 "olcRootDSE $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ "
		 "olcSchemaCheck $ olcSchemaDN $ olcSecurity $ olcSizeLimit $ "
		 "olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcSrvtab $ "
		 "olcThreads $ olcTimeLimit $ olcTLSCACertificateFile $ "
		 "olcTLSCACertificatePath $ olcTLSCertificateFile $ "
		 "olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ "
		 "olcTLSRandFile $ olcTLSVerifyClient ) )", &cfOc_global },
	{ "( OLcfgOc:4 "
		"NAME 'olcBackendConfig' "
		"DESC 'OpenLDAP Backend-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcBackend ) )", &cfOc_backend },
	{ "( OLcfgOc:5 "
		"NAME 'olcDatabaseConfig' "
		"DESC 'OpenLDAP Database-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcAccess $ olcDatabase $ olcLastMod $ olcLimits $ "
		 "olcMaxDerefDepth $ olcReadOnly $ olcReplica $ olcReplogFile $ "
		 "olcRequires $ olcRestrict $ olcRootDN $ olcRootPW $ olcSchemaDN $ "
		 "olcSecurity $ olcSizeLimit $ olcSuffix $ olcSyncrepl $ "
		 "olcTimeLimit $ olcUpdateDN $ olcUpdateRef ) )", &cfOc_database },
	{ "( OLcfgOc:6 "
		"NAME 'olcIncludeFile' "
		"DESC 'OpenLDAP configuration include file' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcInclude $ olcModuleLoad $ olcModulePath $ olcRootDSE ) )",
		&cfOc_include },
	{ "( OLcfgOc:7 "
		"NAME 'olcOverlayConfig' "
		"DESC 'OpenLDAP Overlay-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcOverlay ) )", &cfOc_overlay },
	{ NULL, NULL }
};

static int
config_back_bind( Operation *op, SlapReply *rs )
{
	if ( op->orb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op )) {
		ber_dupbv( &op->orb_edn, be_root_dn( op->o_bd ));
		/* frontend sends result */
		return LDAP_SUCCESS;
	}

	rs->sr_err = LDAP_INVALID_CREDENTIALS;
	send_ldap_result( op, rs );

	return rs->sr_err;
}

static CfEntryInfo *
config_find_base( CfEntryInfo *root, struct berval *dn, CfEntryInfo **last )
{
	struct berval cdn;
	char *c;

	if ( dn_match( &root->ce_entry->e_nname, dn ))
		return root;

	c = dn->bv_val+dn->bv_len;
	for (;*c != ',';c--);

	while(root) {
		*last = root;
		for (--c;c>dn->bv_val && *c != ',';c--);
		if ( *c == ',' )
			c++;
		cdn.bv_val = c;
		cdn.bv_len = dn->bv_len - (c-dn->bv_val);

		root = root->ce_kids;

		for (;root;root=root->ce_sibs) {
			if ( dn_match( &root->ce_entry->e_nname, &cdn )) {
				if ( cdn.bv_val == dn->bv_val ) {
					return root;
				}
				break;
			}
		}
	}
	return root;
}

static int
config_send( Operation *op, SlapReply *rs, CfEntryInfo *ce, int depth )
{
	int rc = 0;

	if ( test_filter( op, ce->ce_entry, op->ors_filter ) == LDAP_COMPARE_TRUE )
	{
		rs->sr_attrs = op->ors_attrs;
		rs->sr_entry = ce->ce_entry;
		rc = send_search_entry( op, rs );
	}
	if ( op->ors_scope == LDAP_SCOPE_SUBTREE ) {
		if ( ce->ce_kids ) {
			rc = config_send( op, rs, ce->ce_kids, 1 );
			if ( rc ) return rc;
		}
		if ( depth ) {
			for (ce=ce->ce_sibs; ce; ce=ce->ce_sibs) {
				rc = config_send( op, rs, ce, 0 );
				if ( rc ) break;
			}
		}
	}
	return rc;
}

static int
config_back_search( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;
	int rc;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ce = config_find_base( cfb->cb_root, &op->o_req_ndn, &last );
	if ( !ce ) {
		if ( last )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto out;
	}
	switch ( op->ors_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_SUBTREE:
		config_send( op, rs, ce, 0 );
		break;
		
	case LDAP_SCOPE_ONELEVEL:
		for (ce = ce->ce_kids; ce; ce=ce->ce_sibs) {
			config_send( op, rs, ce, 1 );
		}
		break;
	}
		
	rs->sr_err = LDAP_SUCCESS;
out:
	send_ldap_result( op, rs );
	return 0;
}

static Entry *
config_alloc_entry( struct berval *pdn, struct berval *rdn )
{
	Entry *e = ch_calloc( 1, sizeof(Entry) );
	CfEntryInfo *ce = ch_calloc( 1, sizeof(CfEntryInfo) );
	e->e_private = ce;
	ce->ce_entry = e;
	build_new_dn( &e->e_name, pdn, rdn, NULL );
	ber_dupbv( &e->e_nname, &e->e_name );
	return e;
}

#define	NO_TABLE	0
#define	BI_TABLE	1
#define	BE_TABLE	2

static int
config_build_entry( ConfigArgs *c, Entry *e, ObjectClass *oc,
	 struct berval *rdn, ConfigTable *ct, int table )
{
	struct berval vals[2];
	struct berval ad_name;
	AttributeDescription *ad = NULL;
	int rc, i;
	char *ptr;
	const char *text;
	AttributeType **at;

	BER_BVZERO( &vals[1] );

	vals[0] = oc->soc_cname;
	attr_merge(e, slap_schema.si_ad_objectClass, vals, NULL );
	ptr = strchr(rdn->bv_val, '=');
	ad_name.bv_val = rdn->bv_val;
	ad_name.bv_len = ptr - rdn->bv_val;
	rc = slap_bv2ad( &ad_name, &ad, &text );
	if ( rc ) {
		return rc;
	}
	vals[0].bv_val = ptr+1;
	vals[0].bv_len = rdn->bv_len - (vals[0].bv_val - rdn->bv_val);
	attr_merge(e, ad, vals, NULL );

	for (at=oc->soc_allowed;*at;at++) {
		/* Skip the naming attr */
		if ((*at)->sat_ad == ad || (*at)->sat_ad == slap_schema.si_ad_cn )
			continue;
		for (i=0;ct[i].name;i++) {
			if (ct[i].ad == (*at)->sat_ad)
				break;
		}
		rc = config_get_vals(&ct[i], c);
		if (rc == LDAP_SUCCESS) {
			attr_merge(e, ct[i].ad, c->rvalue_vals, c->rvalue_nvals);
			ber_bvarray_free( c->rvalue_nvals );
			ber_bvarray_free( c->rvalue_vals );
		}
	}

	if ( table ) {
		if ( table == BI_TABLE )
			ct = c->bi->bi_cf_table;
		else
			ct = c->be->be_cf_table;
		for (;ct && ct->name;ct++) {
			if (!ct->ad) continue;
			rc = config_get_vals(ct, c);
			if (rc == LDAP_SUCCESS) {
				attr_merge(e, ct->ad, c->rvalue_vals, c->rvalue_nvals);
			}
		}
	}

	return 0;
}

static CfEntryInfo *
config_build_includes( ConfigArgs *c, Entry *parent )
{
	Entry *e;
	int i;
	ConfigFile *cf = (ConfigFile *)c->line;
	CfEntryInfo *ce, *ceparent, *ceprev;

	ceparent = parent->e_private;

	for (i=0; cf; cf=cf->c_sibs, i++) {
		c->value_dn.bv_val = c->log;
		c->value_dn.bv_len = sprintf(c->value_dn.bv_val, "cn=include{%d}", i);
		e = config_alloc_entry( &parent->e_nname, &c->value_dn );
		c->line = (char *)cf;
		config_build_entry( c, e, cfOc_include, &c->value_dn,
			c->bi->bi_cf_table, NO_TABLE );
		ce = e->e_private;
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
		if ( cf->c_kids ) {
			c->line = (char *)cf->c_kids;
			config_build_includes( c, e );
		}
	}
	return ce;
}

static int
config_back_db_open( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	struct berval rdn;
	Entry *e, *parent;
	CfEntryInfo *ce, *ceparent, *ceprev;
	int i, rc;
	BackendInfo *bi;
	BackendDB *bptr;
	ConfigArgs c;
	ConfigTable *ct;

	/* create root of tree */
	ber_str2bv( CONFIG_DN, STRLENOF( CONFIG_DN ), 0, &rdn );
	e = config_alloc_entry( NULL, &rdn );
	ce = e->e_private;
	cfb->cb_root = ce;
	c.be = be;
	c.bi = be->bd_info;
	c.line = (char *)cfb->cb_config;
	ct = c.bi->bi_cf_table;
	config_build_entry( &c, e, cfOc_global, &rdn, ct, NO_TABLE );

	parent = e;
	ceparent = ce;

	/* Create includeFile nodes... */
	if ( cfb->cb_config->c_kids ) {
		c.line = (char *)cfb->cb_config->c_kids;
		ceprev = config_build_includes( &c, parent );
	}

	/* Create backend nodes. Skip if they don't provide a cf_table.
	 * There usually aren't any of these.
	 */
	
	c.line = 0;
	bi = backendInfo;
	for (i=0; i<nBackendInfo; i++, bi++) {
		if (!bi->bi_cf_table) continue;
		if (!bi->bi_private) continue;

		rdn.bv_val = c.log;
		rdn.bv_len = sprintf(rdn.bv_val, "%s=%s", cfAd_backend->ad_cname.bv_val, bi->bi_type);
		e = config_alloc_entry( &parent->e_nname, &rdn );
		ce = e->e_private;
		ce->ce_bi = bi;
		c.bi = bi;
		config_build_entry( &c, e, cfOc_backend, &rdn, ct, BI_TABLE );
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
	}

	/* Create database nodes... */
	for (i=0; i<nBackendDB; i++) {
		slap_overinfo *oi = NULL;
		if ( i == 0 ) {
			bptr = frontendDB;
		} else {
			bptr = &backendDB[i];
		}
		if ( overlay_is_over( bptr )) {
			oi = bptr->bd_info->bi_private;
			bi = oi->oi_orig;
		} else {
			bi = bptr->bd_info;
		}
		rdn.bv_val = c.log;
		rdn.bv_len = sprintf(rdn.bv_val, "%s={%0x}%s", cfAd_database->ad_cname.bv_val,
			i, bi->bi_type);
		e = config_alloc_entry( &parent->e_nname, &rdn );
		ce = e->e_private;
		c.be = bptr;
		c.bi = bi;
		ce->ce_be = c.be;
		ce->ce_bi = c.bi;
		config_build_entry( &c, e, cfOc_database, &rdn, ct, BE_TABLE );
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
		/* Iterate through overlays */
		if ( oi ) {
			slap_overinst *on;
			Entry *oe;
			CfEntryInfo *opar = ce, *oprev = NULL;
			int j;

			for (j=0,on=oi->oi_list; on; j++,on=on->on_next) {
				rdn.bv_val = c.log;
				rdn.bv_len = sprintf(rdn.bv_val, "%s={%0x}%s",
					cfAd_overlay->ad_cname.bv_val, j, on->on_bi.bi_type );
				oe = config_alloc_entry( &e->e_nname, &rdn );
				ce = oe->e_private;
				c.be = bptr;
				c.bi = &on->on_bi;
				ce->ce_be = c.be;
				ce->ce_bi = c.bi;
				config_build_entry( &c, oe, cfOc_overlay, &rdn, ct, BI_TABLE );
				if ( !opar->ce_kids ) {
					opar->ce_kids = ce;
				} else {
					oprev->ce_sibs = ce;
				}
				oprev = ce;
			}
		}
	}

	return 0;
}

static int
config_back_db_destroy( Backend *be )
{
	free( be->be_private );
	return 0;
}

int
config_back_initialize( BackendInfo *bi )
{
	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = 0;
	bi->bi_db_config = 0;
	bi->bi_db_open = config_back_db_open;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = config_back_db_destroy;

	bi->bi_op_bind = config_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = config_back_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = 0;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = 0;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

static struct {
	char *name;
	AttributeDescription **desc;
	AttributeDescription *sub;
} ads[] = {
	{ "attribute", NULL, NULL },
	{ "backend", &cfAd_backend, NULL },
	{ "database", &cfAd_database, NULL },
	{ "ditcontentrule", NULL, NULL },
	{ "include", &cfAd_include, NULL },
	{ "objectclass", NULL, NULL },
	{ "overlay", &cfAd_overlay, NULL },
	{ NULL, NULL, NULL }
};

int config_back_init( ConfigFile *cfp, ConfigTable *ct )
{
	BackendInfo bi = {0};
	BackendDB *be;
	struct berval dn;
	CfBackInfo *cfb;
	int i;

	bi.bi_type = "config";
	bi.bi_init = config_back_initialize;
	bi.bi_cf_table = ct;
	backend_add( &bi );
	be = backend_db_init( bi.bi_type );
	ber_str2bv( CONFIG_DN, 0, 1, &be->be_rootdn );
	ber_dupbv( &be->be_rootndn, &be->be_rootdn );
	ber_dupbv( &dn, &be->be_rootdn );
	ber_bvarray_add( &be->be_suffix, &dn );
	ber_dupbv( &dn, &be->be_rootdn );
	ber_bvarray_add( &be->be_nsuffix, &dn );
	cfb = ch_calloc( 1, sizeof(CfBackInfo));
	cfb->cb_config = cfp;
	be->be_private = cfb;

	/* set up the notable AttributeDescriptions */
	ads[0].sub = slap_schema.si_ad_attributeTypes;
	ads[3].sub = slap_schema.si_ad_ditContentRules;
	ads[5].sub = slap_schema.si_ad_objectClasses;

	i = 0;
	for (;ct->name;ct++) {
		if (strcmp(ct->name, ads[i].name)) continue;
		if (ads[i].sub) {
			ct->ad = ads[i].sub;
		} else {
			*ads[i].desc = ct->ad;
		}
		i++;
		if (!ads[i].name) break;
	}

	/* set up the objectclasses */
	for (i=0;cf_ocs[i].def;i++) {
		LDAPObjectClass *oc;
		int code;
		const char *err;

		oc = ldap_str2objectclass( cf_ocs[i].def, &code, &err,
			LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			fprintf( stderr, "config_back_init: objectclass \"%s\": %s, %s\n",
				cf_ocs[i].def, ldap_scherr2str(code), err );
			return code;
		}
		code = oc_add(oc,0,&err);
		if ( code ) {
			fprintf( stderr, "config_back_init: objectclass \"%s\": %s, %s\n",
				cf_ocs[i].def, scherr2str(code), err );
			return code;
		}
		if ( cf_ocs[i].oc ) {
			*cf_ocs[i].oc = oc_find(oc->oc_names[0]);
		}
		ldap_memfree(oc);
	}
	return 0;
}
