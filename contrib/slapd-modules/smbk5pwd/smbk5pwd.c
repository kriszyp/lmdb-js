/* smbk5pwd.c - Overlay for managing Samba and Heimdal passwords */
/* $OpenLDAP$ */
/*
 * Copyright 2004 by Howard Chu, Symas Corp.
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

#include <portable.h>

#ifndef SLAPD_OVER_SMBK5PWD
#define SLAPD_OVER_SMBK5PWD SLAPD_MOD_DYNAMIC
#endif

#ifdef SLAPD_OVER_SMBK5PWD

#include <slap.h>
#include <ac/errno.h>

#ifdef DO_KRB5
/* make ASN1_MALLOC_ENCODE use our allocator */
#define malloc	ch_malloc

#include <krb5.h>
#include <kadm5/admin.h>
#include <hdb.h>

static krb5_context context;
static void *kadm_context;
static kadm5_config_params conf;
static HDB *db;

static AttributeDescription *ad_krb5Key;
static AttributeDescription *ad_krb5KeyVersionNumber;
static AttributeDescription *ad_krb5PrincipalName;
static ObjectClass *oc_krb5KDCEntry;
#endif

#ifdef DO_SAMBA
#include <openssl/des.h>
#include <openssl/md4.h>

static AttributeDescription *ad_sambaLMPassword;
static AttributeDescription *ad_sambaNTPassword;
static AttributeDescription *ad_sambaPwdLastSet;
static ObjectClass *oc_sambaSamAccount;
#endif

#if 0
static void smbk5pwd_destroy() {
	kadm5_destroy(kadm_context);
	krb5_free_context(context);
}
#endif

#ifdef DO_SAMBA
static const char hex[] = "0123456789abcdef";

/* From liblutil/passwd.c... */
static void lmPasswd_to_key(
        const unsigned char *lmPasswd,
        des_cblock *key)
{
        /* make room for parity bits */
        ((char *)key)[0] = lmPasswd[0];
        ((char *)key)[1] = ((lmPasswd[0]&0x01)<<7) | (lmPasswd[1]>>1);
        ((char *)key)[2] = ((lmPasswd[1]&0x03)<<6) | (lmPasswd[2]>>2);
        ((char *)key)[3] = ((lmPasswd[2]&0x07)<<5) | (lmPasswd[3]>>3);
        ((char *)key)[4] = ((lmPasswd[3]&0x0F)<<4) | (lmPasswd[4]>>4);
        ((char *)key)[5] = ((lmPasswd[4]&0x1F)<<3) | (lmPasswd[5]>>5);
        ((char *)key)[6] = ((lmPasswd[5]&0x3F)<<2) | (lmPasswd[6]>>6);
        ((char *)key)[7] = ((lmPasswd[6]&0x7F)<<1);

        des_set_odd_parity( key );
}

#define MAX_PWLEN 256
#define	HASHLEN	16

static void hexify(
	const char in[HASHLEN],
	struct berval *out
)
{
	int i;
	char *a;
	unsigned char *b;

	out->bv_val = ch_malloc(HASHLEN*2 + 1);
	out->bv_len = HASHLEN*2;

	a = out->bv_val;
	b = (unsigned char *)in;
	for (i=0; i<HASHLEN; i++) {
		*a++ = hex[*b >> 4];
		*a++ = hex[*b++ & 0x0f];
	}
	*a++ = '\0';
}

static void lmhash(
	struct berval *passwd,
	struct berval *hash
)
{
        char UcasePassword[15];
        des_cblock key;
        des_key_schedule schedule;
        des_cblock StdText = "KGS!@#$%";
	des_cblock hbuf[2];

        strncpy( UcasePassword, passwd->bv_val, 14 );
        UcasePassword[14] = '\0';
        ldap_pvt_str2upper( UcasePassword );

        lmPasswd_to_key( UcasePassword, &key );
        des_set_key_unchecked( &key, schedule );
        des_ecb_encrypt( &StdText, &hbuf[0], schedule , DES_ENCRYPT );

        lmPasswd_to_key( &UcasePassword[7], &key );
        des_set_key_unchecked( &key, schedule );
        des_ecb_encrypt( &StdText, &hbuf[1], schedule , DES_ENCRYPT );

	hexify( (char *)hbuf, hash );
}

static void nthash(
	struct berval *passwd,
	struct berval *hash
)
{
        /* Windows currently only allows 14 character passwords, but
         * may support up to 256 in the future. We assume this means
	 * 256 UCS2 characters, not 256 bytes...
         */
	char hbuf[HASHLEN];
        int i;
        MD4_CTX ctx;

	if (passwd->bv_len > MAX_PWLEN*2)
		passwd->bv_len = MAX_PWLEN*2;
		
        MD4_Init( &ctx );
        MD4_Update( &ctx, passwd->bv_val, passwd->bv_len );
        MD4_Final( hbuf, &ctx );

	hexify( hbuf, hash );
}
#endif /* DO_SAMBA */

int smbk5pwd_exop_passwd(
	Operation *op,
	SlapReply *rs )
{
	int i, rc;
	req_pwdexop_s *qpw = &op->oq_pwdexop;
	Entry *e;
	Attribute *a;
	Modifications *ml;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;

	/* Not the operation we expected, pass it on... */
	if ( ber_bvcmp( &slap_EXOP_MODIFY_PASSWD, &op->ore_reqoid ) ) {
		return SLAP_CB_CONTINUE;
	}

	op->o_bd->bd_info = (BackendInfo *)on->on_info;
	rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) return rc;

#ifdef DO_KRB5
	/* Kerberos stuff */
	do {
		krb5_error_code ret;
		hdb_entry ent;
		struct berval *keys;
		int kvno;

		if ( !is_entry_objectclass(e, oc_krb5KDCEntry, 0 ) ) break;

		a = attr_find( e->e_attrs, ad_krb5PrincipalName );
		if ( !a ) break;

		memset( &ent, 0, sizeof(ent) );
		ret = krb5_parse_name(context, a->a_vals[0].bv_val, &ent.principal);
		if ( ret ) break;

		a = attr_find( e->e_attrs, ad_krb5KeyVersionNumber );
		if ( a ) {
			kvno = atoi(a->a_vals[0].bv_val);
		} else {
			/* shouldn't happen, this is a required attr */
			kvno = 0;
		}

		ret = _kadm5_set_keys(kadm_context, &ent, qpw->rs_new.bv_val);
		hdb_seal_keys(context, db, &ent);
		krb5_free_principal( context, ent.principal );

		keys = ch_malloc( (ent.keys.len + 1) * sizeof(struct berval));

		for (i = 0; i < ent.keys.len; i++) {
			unsigned char *buf;
			size_t len;

			ASN1_MALLOC_ENCODE(Key, buf, len, &ent.keys.val[i], &len, ret);
			if (ret != 0)
				break;
			
			keys[i].bv_val = buf;
			keys[i].bv_len = len;
		}
		keys[i].bv_val = NULL;
		keys[i].bv_len = 0;

		if ( i != ent.keys.len ) {
			ber_bvarray_free( keys );
			break;
		}

		ml = ch_malloc(sizeof(Modifications));
		if (!qpw->rs_modtail) qpw->rs_modtail = &ml->sml_next;
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		ml->sml_desc = ad_krb5Key;
		ml->sml_op = LDAP_MOD_REPLACE;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;
		
		ml = ch_malloc(sizeof(Modifications));
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;
		
		ml->sml_desc = ad_krb5KeyVersionNumber;
		ml->sml_op = LDAP_MOD_REPLACE;
		ml->sml_values = ch_malloc( 2 * sizeof(struct berval));
		ml->sml_values[0].bv_val = ch_malloc( 64 );
		ml->sml_values[0].bv_len = sprintf(ml->sml_values[0].bv_val,
			"%d", kvno+1 );
		ml->sml_values[1].bv_val = NULL;
		ml->sml_values[1].bv_len = 0;
		ml->sml_nvalues = NULL;
	} while(0);
#endif /* DO_KRB5 */

#ifdef DO_SAMBA
	/* Samba stuff */
	if ( is_entry_objectclass(e, oc_sambaSamAccount, 0 ) ) {
		struct berval *keys;
		ber_len_t j,l;
		wchar_t *wcs, wc;
		char *c, *d;
		struct berval pwd;
		
		/* Expand incoming UTF8 string to UCS4 */
		l = ldap_utf8_chars(qpw->rs_new.bv_val);
		wcs = ch_malloc((l+1) * sizeof(wchar_t));

		ldap_x_utf8s_to_wcs( wcs, qpw->rs_new.bv_val, l );
		
		/* Truncate UCS4 to UCS2 */
		c = (char *)wcs;
		for (j=0; j<l; j++) {
			wc = wcs[j];
			*c++ = wc & 0xff;
			*c++ = (wc >> 8) & 0xff;
		}
		*c++ = 0;
		pwd.bv_val = (char *)wcs;
		pwd.bv_len = l * 2;

		ml = ch_malloc(sizeof(Modifications));
		if (!qpw->rs_modtail) qpw->rs_modtail = &ml->sml_next;
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		keys[1].bv_val = NULL;
		keys[1].bv_len = 0;
		nthash( &pwd, keys );
		
		ml->sml_desc = ad_sambaNTPassword;
		ml->sml_op = LDAP_MOD_REPLACE;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;

		/* Truncate UCS2 to 8-bit ASCII */
		c = pwd.bv_val+1;
		d = pwd.bv_val+2;
		for (j=1; j<l; j++) {
			*c++ = *d++;
			d++;
		}

		ml = ch_malloc(sizeof(Modifications));
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		keys[1].bv_val = NULL;
		keys[1].bv_len = 0;
		lmhash( &pwd, keys );
		
		ml->sml_desc = ad_sambaLMPassword;
		ml->sml_op = LDAP_MOD_REPLACE;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;

		ch_free(wcs);

		ml = ch_malloc(sizeof(Modifications));
		ml->sml_next = qpw->rs_mods;
		qpw->rs_mods = ml;

		keys = ch_malloc( 2 * sizeof(struct berval) );
		keys[1].bv_val = NULL;
		keys[1].bv_len = 0;
		keys[0].bv_val = ch_malloc(16);
		keys[0].bv_len = sprintf(keys[0].bv_val, "%d",
			slap_get_time());
		
		ml->sml_desc = ad_sambaPwdLastSet;
		ml->sml_op = LDAP_MOD_REPLACE;
		ml->sml_values = keys;
		ml->sml_nvalues = NULL;
	}
#endif /* DO_SAMBA */
	be_entry_release_r( op, e );

	return SLAP_CB_CONTINUE;
}

static slap_overinst smbk5pwd;

int smbk5pwd_init() {
	int rc;
	const char *text;

#ifdef DO_KRB5
	krb5_error_code ret;
	extern HDB * _kadm5_s_get_db(void *);

	/* Make sure all of our necessary schema items are loaded */
	oc_krb5KDCEntry = oc_find("krb5KDCEntry");
	if ( !oc_krb5KDCEntry ) return -1;

	rc = slap_str2ad( "krb5Key", &ad_krb5Key, &text );
	if ( rc ) return rc;
	rc = slap_str2ad( "krb5KeyVersionNumber", &ad_krb5KeyVersionNumber, &text );
	if ( rc ) return rc;
	rc = slap_str2ad( "krb5PrincipalName", &ad_krb5PrincipalName, &text );
	if ( rc ) return rc;

	/* Initialize Kerberos context */
	ret = krb5_init_context(&context);
	if (ret) {
		return -1;
	}

	ret = kadm5_s_init_with_password_ctx( context,
		KADM5_ADMIN_SERVICE,
		NULL,
		KADM5_ADMIN_SERVICE,
		&conf, 0, 0, &kadm_context );
	
	db = _kadm5_s_get_db(kadm_context);
#endif /* DO_KRB5 */

#ifdef DO_SAMBA
	oc_sambaSamAccount = oc_find("sambaSamAccount");
	if ( !oc_sambaSamAccount ) return -1;

	rc = slap_str2ad( "sambaLMPassword", &ad_sambaLMPassword, &text );
	if ( rc ) return rc;
	rc = slap_str2ad( "sambaNTPassword", &ad_sambaNTPassword, &text );
	if ( rc ) return rc;
	rc = slap_str2ad( "sambaPwdLastSet", &ad_sambaPwdLastSet, &text );
	if ( rc ) return rc;
#endif /* DO_SAMBA */

	smbk5pwd.on_bi.bi_type = "smbk5pwd";
	smbk5pwd.on_bi.bi_extended = smbk5pwd_exop_passwd;

	return overlay_register( &smbk5pwd );
}

#if SLAPD_OVER_SMBK5PWD == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return smbk5pwd_init();
}
#endif

#endif /* defined(SLAPD_OVER_SMBK5PWD) */
