/* slapd-totp.c - Password module and overlay for TOTP */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2015 The OpenLDAP Foundation.
 * Portions Copyright 2015 by Howard Chu, Symas Corp.
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

#include <lber.h>
#include <lber_pvt.h>
#include "lutil.h"
#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/string.h>
/* include socket.h to get sys/types.h and/or winsock2.h */
#include <ac/socket.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "slap.h"
#include "config.h"

static LUTIL_PASSWD_CHK_FUNC chk_totp1, chk_totp256, chk_totp512;
static LUTIL_PASSWD_HASH_FUNC hash_totp1, hash_totp256, hash_totp512;
static const struct berval scheme_totp1 = BER_BVC("{TOTP1}");
static const struct berval scheme_totp256 = BER_BVC("{TOTP256}");
static const struct berval scheme_totp512 = BER_BVC("{TOTP512}");

static AttributeDescription *ad_authTimestamp;

/* RFC3548 base32 encoding/decoding */

static const char Base32[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char Pad32 = '=';

static int
totp_b32_ntop(
	u_char const *src,
	size_t srclength,
	char *target,
	size_t targsize)
{
	size_t datalength = 0;
	u_char input0;
	u_int input1;	/* assumed to be at least 32 bits */
	u_char output[8];
	int i;

	while (4 < srclength) {
		if (datalength + 8 > targsize)
			return (-1);
		input0 = *src++;
		input1 = *src++;
		input1 <<= 8;
		input1 |= *src++;
		input1 <<= 8;
		input1 |= *src++;
		input1 <<= 8;
		input1 |= *src++;
		srclength -= 5;

		for (i=7; i>1; i--) {
			output[i] = input1 & 0x1f;
			input1 >>= 5;
		}
		output[0] = input0 >> 3;
		output[1] = (input0 & 0x07) << 2 | input1;

		for (i=0; i<8; i++)
			target[datalength++] = Base32[output[i]];
	}
    
	/* Now we worry about padding. */
	if (0 != srclength) {
		static const int outlen[] = { 2,4,5,7 };
		int n;
		if (datalength + 8 > targsize)
			return (-1);

		/* Get what's left. */
		input1 = *src++;
		for (i = 1; i < srclength; i++) {
			input1 <<= 8;
			input1 |= *src++;
		}
		input1 <<= 8 * (4-srclength);
		n = outlen[srclength-1];
		for (i=0; i<n; i++) {
			target[datalength++] = Base32[(input1 & 0xf8000000) >> 27];
			input1 <<= 5;
		}
		for (; i<8; i++)
			target[datalength++] = Pad32;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';	/* Returned value doesn't count \0. */
	return (datalength);
}

/* converts characters, eight at a time, starting at src
   from base - 32 numbers into five 8 bit bytes in the target area.
   it returns the number of data bytes stored at the target, or -1 on error.
 */

static int
totp_b32_pton(
	char const *src,
	u_char *target, 
	size_t targsize)
{
	int tarindex, state, ch;
	char *pos;

	state = 0;
	tarindex = 0;

	while ((ch = *src++) != '\0') {
		if (ch == Pad32)
			break;

		pos = strchr(Base32, ch);
		if (pos == 0) 		/* A non-base32 character. */
			return (-1);

		switch (state) {
		case 0:
			if (target) {
				if ((size_t)tarindex >= targsize)
					return (-1);
				target[tarindex] = (pos - Base32) << 3;
			}
			state = 1;
			break;
		case 1:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex]   |=  (pos - Base32) >> 2;
				target[tarindex+1]  = ((pos - Base32) & 0x3)
							<< 6 ;
			}
			tarindex++;
			state = 2;
			break;
		case 2:
			if (target) {
				target[tarindex]   |=  (pos - Base32) << 1;
			}
			state = 3;
			break;
		case 3:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base32) >> 4;
				target[tarindex+1]  = ((pos - Base32) & 0xf)
							<< 4 ;
			}
			tarindex++;
			state = 4;
			break;
		case 4:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base32) >> 1;
				target[tarindex+1]  = ((pos - Base32) & 0x1)
							<< 7 ;
			}
			tarindex++;
			state = 5;
			break;
		case 5:
			if (target) {
				target[tarindex]   |=  (pos - Base32) << 2;
			}
			state = 6;
			break;
		case 6:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base32) >> 3;
				target[tarindex+1]  = ((pos - Base32) & 0x7)
							<< 5 ;
			}
			tarindex++;
			state = 7;
			break;
		case 7:
			if (target) {
				target[tarindex]   |=  (pos - Base32);
			}
			state = 0;
			tarindex++;
			break;

		default:
			abort();
		}
	}

	/*
	 * We are done decoding Base-32 chars.  Let's see if we ended
	 * on a byte boundary, and/or with erroneous trailing characters.
	 */

	if (ch == Pad32) {		/* We got a pad char. */
		int i = 1;

		/* count pad chars */
		for (; ch; ch = *src++) {
			if (ch != Pad32)
				return (-1);
			i++;
		}
		/* there are only 4 valid ending states with a
		 * pad character, make sure the number of pads is valid.
		 */
		switch(state) {
		case 2:	if (i != 6) return -1;
			break;
		case 4: if (i != 4) return -1;
			break;
		case 5: if (i != 3) return -1;
			break;
		case 7: if (i != 1) return -1;
			break;
		default:
			return -1;
		}
		/*
		 * Now make sure that the "extra" bits that slopped past
		 * the last full byte were zeros.  If we don't check them,
		 * they become a subliminal channel.
		 */
		if (target && target[tarindex] != 0)
			return (-1);
	} else {
		/*
		 * We ended by seeing the end of the string.  Make sure we
		 * have no partial bytes lying around.
		 */
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}

/* RFC6238 TOTP */

#define HMAC_setup(ctx, key, len, hash)	HMAC_CTX_init(&ctx); HMAC_Init_ex(&ctx, key, len, hash, 0)
#define HMAC_crunch(ctx, buf, len)	HMAC_Update(&ctx, buf, len)
#define HMAC_finish(ctx, dig, dlen)	HMAC_Final(&ctx, dig, &dlen); HMAC_CTX_cleanup(&ctx)

typedef struct myval {
	ber_len_t mv_len;
	void *mv_val;
} myval;

static void do_hmac(
	const void *hash,
	myval *key,
	myval *data,
	myval *out)
{
	HMAC_CTX ctx;
	unsigned int digestLen;

	HMAC_setup(ctx, key->mv_val, key->mv_len, hash);
	HMAC_crunch(ctx, data->mv_val, data->mv_len);
	HMAC_finish(ctx, out->mv_val, digestLen);
	out->mv_len = digestLen;
}

static const int DIGITS_POWER[] = {
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

static void generate(
	myval *key,
	unsigned long tval,
	int digits,
	myval *out,
	const void *mech)
{
	unsigned char digest[SHA512_DIGEST_LENGTH];
	myval digval;
	myval data;
	unsigned char msg[8];
	int i, offset, res, otp;

#if !WORDS_BIGENDIAN
	/* only needed on little-endian, can just use tval directly on big-endian */
	for (i=7; i>=0; i--) {
		msg[i] = tval & 0xff;
		tval >>= 8;
	}
#endif

	data.mv_val = msg;
	data.mv_len = sizeof(msg);

	digval.mv_val = digest;
	digval.mv_len = sizeof(digest);
	do_hmac(mech, key, &data, &digval);

	offset = digest[digval.mv_len-1] & 0xf;
	res = ((digest[offset] & 0x7f) << 24) |
			((digest[offset+1] & 0xff) << 16) |
			((digest[offset+2] & 0xff) << 8) |
			(digest[offset+3] & 0xff);

	otp = res % DIGITS_POWER[digits];
	out->mv_len = snprintf(out->mv_val, out->mv_len, "%0*d", digits, otp);
}

static int totp_op_cleanup( Operation *op, SlapReply *rs );

#define TIME_STEP	30
#define DIGITS	6

static int chk_totp(
	const struct berval *passwd,
	const struct berval *cred,
	const void *mech,
	const char **text)
{
	void *ctx, *op_tmp;
	Operation *op;
	Entry *e;
	Attribute *a;
	long t = time(0L) / TIME_STEP;
	int rc;
	myval out, key;
	char outbuf[32];

	/* Find our thread context, find our Operation */
	ctx = ldap_pvt_thread_pool_context();
	if (ldap_pvt_thread_pool_getkey(ctx, totp_op_cleanup, &op_tmp, NULL) ||
		!op_tmp)
		return LUTIL_PASSWD_ERR;
	op = op_tmp;

	rc = be_entry_get_rw(op, &op->o_req_ndn, NULL, NULL, 0, &e);
	if (rc != LDAP_SUCCESS) return LUTIL_PASSWD_ERR;

	/* Make sure previous login is older than current time */
	a = attr_find(e->e_attrs, ad_authTimestamp);
	if (a) {
		struct lutil_tm tm;
		struct lutil_timet tt;
		if (lutil_parsetime(a->a_vals[0].bv_val, &tm) == 0 &&
			lutil_tm2time(&tm, &tt) == 0) {
			long told = tt.tt_sec / TIME_STEP;
			if (told >= t)
				rc = LUTIL_PASSWD_ERR;
		}
	}	/* else no previous login, 1st use is OK */

	be_entry_release_r(op, e);
	if (rc) return rc;

	/* Key is stored in base32 */
	key.mv_len = passwd->bv_len * 5 / 8;
	key.mv_val = ber_memalloc(key.mv_len+1);

	if (!key.mv_val)
		return LUTIL_PASSWD_ERR;

	rc = totp_b32_pton(passwd->bv_val, key.mv_val, key.mv_len);
	if (rc < 1) {
		rc = LUTIL_PASSWD_ERR;
		goto out;
	}

	out.mv_val = outbuf;
	out.mv_len = sizeof(outbuf);
	generate(&key, t, DIGITS, &out, mech);
	memset(key.mv_val, 0, key.mv_len);

	/* compare */
	if (out.mv_len != cred->bv_len)
		return LUTIL_PASSWD_ERR;

	rc = memcmp(out.mv_val, cred->bv_val, out.mv_len) ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;

out:
	ber_memfree(key.mv_val);
	return rc;
}

static int chk_totp1(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	return chk_totp(passwd, cred, EVP_sha1(), text);
}

static int chk_totp256(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	return chk_totp(passwd, cred, EVP_sha256(), text);
}

static int chk_totp512(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
	return chk_totp(passwd, cred, EVP_sha512(), text);
}

static int passwd_string32(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *hash)
{
	int b32len = (passwd->bv_len + 4)/5 * 8;
	int rc;
	hash->bv_len = scheme->bv_len + b32len;
	hash->bv_val = ber_memalloc(hash->bv_len + 1);
	AC_MEMCPY(hash->bv_val, scheme->bv_val, scheme->bv_len);
	rc = totp_b32_ntop((unsigned char *)passwd->bv_val, passwd->bv_len,
		hash->bv_val + scheme->bv_len, b32len+1);
	if (rc < 0) {
		ber_memfree(hash->bv_val);
		hash->bv_val = NULL;
		return LUTIL_PASSWD_ERR;
	}
	return LUTIL_PASSWD_OK;
}

static int hash_totp1(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *hash,
	const char **text)
{
#if 0
	if (passwd->bv_len != SHA_DIGEST_LENGTH) {
		*text = "invalid key length";
		return LUTIL_PASSWD_ERR;
	}
#endif
	return passwd_string32(scheme, passwd, hash);
}

static int hash_totp256(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *hash,
	const char **text)
{
#if 0
	if (passwd->bv_len != SHA256_DIGEST_LENGTH) {
		*text = "invalid key length";
		return LUTIL_PASSWD_ERR;
	}
#endif
	return passwd_string32(scheme, passwd, hash);
}

static int hash_totp512(
	const struct berval *scheme,
	const struct berval *passwd,
	struct berval *hash,
	const char **text)
{
#if 0
	if (passwd->bv_len != SHA512_DIGEST_LENGTH) {
		*text = "invalid key length";
		return LUTIL_PASSWD_ERR;
	}
#endif
	return passwd_string32(scheme, passwd, hash);
}

static int totp_op_cleanup(
	Operation *op,
	SlapReply *rs )
{
	slap_callback *cb;

	/* clear out the current key */
	ldap_pvt_thread_pool_setkey( op->o_threadctx, totp_op_cleanup,
		NULL, 0, NULL, NULL );

	/* free the callback */
	cb = op->o_callback;
	op->o_callback = cb->sc_next;
	op->o_tmpfree( cb, op->o_tmpmemctx );
	return 0;
}

static int totp_op_bind(
	Operation *op,
	SlapReply *rs )
{
	/* If this is a simple Bind, stash the Op pointer so our chk
	 * function can find it. Set a cleanup callback to clear it
	 * out when the Bind completes.
	 */
	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE ) {
		slap_callback *cb;
		ldap_pvt_thread_pool_setkey( op->o_threadctx,
			totp_op_cleanup, op, 0, NULL, NULL );
		cb = op->o_tmpcalloc( 1, sizeof(slap_callback), op->o_tmpmemctx );
		cb->sc_cleanup = totp_op_cleanup;
		cb->sc_next = op->o_callback;
		op->o_callback = cb;
	}
	return SLAP_CB_CONTINUE;
}

static int totp_db_open(
	BackendDB *be,
	ConfigReply *cr
)
{
	int rc = 0;

	if (!ad_authTimestamp) {
		const char *text = NULL;
		rc = slap_str2ad("authTimestamp", &ad_authTimestamp, &text);
		if (rc) {
			snprintf(cr->msg, sizeof(cr->msg), "unable to find authTimestamp attribute: %s (%d)",
				text, rc);
			Debug(LDAP_DEBUG_ANY, "totp: %s.\n", cr->msg, 0, 0);
		}
	}
	return rc;
}

static slap_overinst totp;

int
totp_initialize(void)
{
	int rc;

	totp.on_bi.bi_type = "totp";

	totp.on_bi.bi_db_open = totp_db_open;
	totp.on_bi.bi_op_bind = totp_op_bind;

	rc = lutil_passwd_add((struct berval *) &scheme_totp1, chk_totp1, hash_totp1);
	if (!rc)
		rc = lutil_passwd_add((struct berval *) &scheme_totp256, chk_totp256, hash_totp256);
	if (!rc)
		rc = lutil_passwd_add((struct berval *) &scheme_totp512, chk_totp512, hash_totp512);
	if (rc)
		return rc;

	return overlay_register(&totp);
}

int init_module(int argc, char *argv[]) {
	return totp_initialize();
}
