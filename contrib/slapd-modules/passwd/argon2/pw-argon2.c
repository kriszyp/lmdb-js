/* pw-argon2.c - Password module for argon2 */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2017 The OpenLDAP Foundation.
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

#define _GNU_SOURCE

#include "portable.h"
#include "ac/string.h"
#include "lber_pvt.h"
#include "lutil.h"

#include <argon2.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * For now, we hardcode the default values from the argon2 command line tool
 * (as of argon2 release 20161029)
 */
#define SLAPD_ARGON2_ITERATIONS 3
#define SLAPD_ARGON2_MEMORY 12
#define SLAPD_ARGON2_PARALLELISM 1
#define SLAPD_ARGON2_SALT_LENGTH 16
#define SLAPD_ARGON2_HASH_LENGTH 32

const struct berval slapd_argon2_scheme = BER_BVC("{ARGON2}");

static int slapd_argon2_hash(
  const struct berval *scheme,
  const struct berval *passwd,
  struct berval *hash,
  const char **text) {

  /*
   * Duplicate these values here so future code which allows
   * configuration has an easier time.
   */
  uint32_t iterations = SLAPD_ARGON2_ITERATIONS;
  uint32_t memory = (1 << SLAPD_ARGON2_MEMORY);
  uint32_t parallelism = SLAPD_ARGON2_PARALLELISM;
  uint32_t salt_length = SLAPD_ARGON2_SALT_LENGTH;
  uint32_t hash_length = SLAPD_ARGON2_HASH_LENGTH;

  size_t encoded_length = argon2_encodedlen(iterations, memory, parallelism,
                            salt_length, hash_length, Argon2_i);

  /*
   * Gather random bytes for our salt
   */
  struct berval salt;
  salt.bv_len = salt_length;
  salt.bv_val = ber_memalloc(salt.bv_len);

  int rc = lutil_entropy((unsigned char*)salt.bv_val, salt.bv_len);

  if(rc) {
    ber_memfree(salt.bv_val);
    return LUTIL_PASSWD_ERR;
  }

  struct berval encoded;
  encoded.bv_len = encoded_length;
  encoded.bv_val = ber_memalloc(encoded.bv_len);
  /*
   * Do the actual heavy lifting
   */
  rc = argon2i_hash_encoded(iterations, memory, parallelism,
            passwd->bv_val, passwd->bv_len, salt.bv_val, salt_length, hash_length,
            encoded.bv_val, encoded_length);
  ber_memfree(salt.bv_val);

  if(rc) {
    ber_memfree(encoded.bv_val);
    return LUTIL_PASSWD_ERR;
  }

  hash->bv_len = scheme->bv_len + encoded_length;
  hash->bv_val = ber_memalloc(hash->bv_len);

  AC_MEMCPY(hash->bv_val, scheme->bv_val, scheme->bv_len);
  AC_MEMCPY(hash->bv_val + scheme->bv_len, encoded.bv_val, encoded.bv_len);

  ber_memfree(encoded.bv_val);

  return LUTIL_PASSWD_OK;
}

static int slapd_argon2_verify(
  const struct berval *scheme,
  const struct berval *passwd,
  const struct berval *cred,
  const char **text) {

  int rc = argon2i_verify(passwd->bv_val, cred->bv_val, cred->bv_len);

  if (rc) {
    return LUTIL_PASSWD_ERR;
  }
  return LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
  return lutil_passwd_add((struct berval *)&slapd_argon2_scheme,
              slapd_argon2_verify, slapd_argon2_hash);
}
