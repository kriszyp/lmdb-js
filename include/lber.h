/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/* Portions
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

#ifndef _LBER_H
#define _LBER_H

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/* Overview of LBER tag construction
 *
 *	Bits
 *	______
 *	8 7 | CLASS
 *	0 0 = UNIVERSAL
 *	0 1 = APPLICATION
 *	1 0 = CONTEXT-SPECIFIC
 *	1 1 = PRIVATE
 *		_____
 *		| 6 | DATA-TYPE
 *		  0 = PRIMITIVE
 *		  1 = CONSTRUCTED
 *			___________
 *			| 5 ... 1 | TAG-NUMBER
 */

/* BER classes and mask */
#define LBER_CLASS_UNIVERSAL	0x00UL
#define LBER_CLASS_APPLICATION	0x40UL
#define LBER_CLASS_CONTEXT	0x80UL
#define LBER_CLASS_PRIVATE	0xc0UL
#define LBER_CLASS_MASK		0xc0UL

/* BER encoding type and mask */
#define LBER_PRIMITIVE		0x00UL
#define LBER_CONSTRUCTED	0x20UL
#define LBER_ENCODING_MASK	0x20UL

#define LBER_BIG_TAG_MASK	0x1fUL
#define LBER_MORE_TAG_MASK	0x80UL

/*
 * Note that LBER_ERROR and LBER_DEFAULT are values that can never appear
 * as valid BER tags, and so it is safe to use them to report errors.  In
 * fact, any tag for which the following is true is invalid:
 *     (( tag & 0x00000080 ) != 0 ) && (( tag & 0xFFFFFF00 ) != 0 )
 */
#define LBER_INVALID(tag) ( ( (tag) & 0xFFFFFF80UL ) != 0 )
#define LBER_ERROR		0xffffffffUL
#define LBER_DEFAULT		0xffffffffUL

/* general BER types we know about */
#define LBER_BOOLEAN		0x01UL
#define LBER_INTEGER		0x02UL
#define LBER_BITSTRING		0x03UL
#define LBER_OCTETSTRING	0x04UL
#define LBER_NULL		0x05UL
#define LBER_ENUMERATED		0x0aUL
#define LBER_SEQUENCE		0x30UL	/* constructed */
#define LBER_SET		0x31UL	/* constructed */

#define OLD_LBER_SEQUENCE	0x10UL	/* w/o constructed bit - broken */
#define OLD_LBER_SET		0x11UL	/* w/o constructed bit - broken */

typedef int (*BERTranslateProc) LDAP_P((
	char **bufp,
	unsigned long *buflenp,
	int free_input ));

/* LBER BerElement options */
#define LBER_USE_DER		0x01
#define LBER_USE_INDEFINITE_LEN	0x02
#define LBER_TRANSLATE_STRINGS	0x04

/* get/set options for BerElement */
#define LBER_OPT_BER_OPTIONS	0x01
#define LBER_OPT_BER_DEBUG		0x02

#define LBER_OPT_DEBUG_LEVEL	LBER_OPT_BER_DEBUG

#define LBER_OPT_LOG_PRINT_FN	0x8001
#define LBER_OPT_MEMORY_FNS		0x8002

typedef void (*BER_LOG_PRINT_FN) LDAP_P(( char *buf ));

typedef void* (*BER_MEMALLOC_FN)	LDAP_P(( size_t size ));
typedef void* (*BER_MEMCALLOC_FN)	LDAP_P(( size_t n, size_t size ));
typedef void* (*BER_MEMREALLOC_FN)	LDAP_P(( void *p, size_t size ));
typedef void  (*BER_MEMFREE_FN)		LDAP_P(( void *p ));

typedef struct lber_memory_fns {
	BER_MEMALLOC_FN	bmf_malloc;
	BER_MEMCALLOC_FN bmf_calloc;
	BER_MEMREALLOC_FN bmf_realloc;
	BER_MEMFREE_FN bmf_free;
} BerMemoryFunctions;

/* LBER Sockbuf options */ 
#define LBER_TO_FILE           0x01	/* to a file referenced by sb_fd   */
#define LBER_TO_FILE_ONLY      0x02	/* only write to file, not network */
#define LBER_MAX_INCOMING_SIZE 0x04	/* impose limit on incoming stuff  */
#define LBER_NO_READ_AHEAD     0x08	/* read only as much as requested  */

/* get/set options for Sockbuf */
#define LBER_OPT_SOCKBUF_DESC		0x1000
#define LBER_OPT_SOCKBUF_OPTIONS	0x1001
#define LBER_OPT_SOCKBUF_DEBUG		0x1002

/* on/off values */
#define LBER_OPT_ON		((void *) 1)
#define LBER_OPT_OFF	((void *) 0)

#define LBER_OPT_SUCCESS	0
#define LBER_OPT_ERROR		(-1)

typedef struct berelement BerElement;
typedef struct sockbuf Sockbuf;
typedef struct seqorset Seqorset;

/* structure for returning a sequence of octet strings + length */
typedef struct berval {
	unsigned long	bv_len;
	char		*bv_val;
} BerValue;

/*
 * in bprint.c:
 */
LDAP_F( void )
ber_print_error LDAP_P((
	LDAP_CONST char *data ));

LDAP_F( void )
ber_bprint LDAP_P((
	LDAP_CONST char *data, int len ));

LDAP_F( void )
ber_dump LDAP_P((
	LDAP_CONST BerElement *ber, int inout ));

LDAP_F( void )
ber_sos_dump LDAP_P((
	LDAP_CONST Seqorset *sos ));


/*
 * in decode.c:
 */
typedef int (*BERDecodeCallback) LDAP_P((
	BerElement *ber,
	void *data,
	int mode ));

LDAP_F( unsigned long )
ber_get_tag LDAP_P((
	BerElement *ber ));

LDAP_F( unsigned long )
ber_skip_tag LDAP_P((
	BerElement *ber,
	unsigned long *len ));

LDAP_F( unsigned long )
ber_peek_tag LDAP_P((
	LDAP_CONST BerElement *ber,
	unsigned long *len ));

LDAP_F( unsigned long )
ber_get_int LDAP_P((
	BerElement *ber,
	long *num ));

LDAP_F( unsigned long )
ber_get_stringb LDAP_P((
	BerElement *ber,
	char *buf,
	unsigned long *len ));

LDAP_F( unsigned long )
ber_get_stringa LDAP_P((
	BerElement *ber, char **buf ));

LDAP_F( unsigned long )
ber_get_stringal LDAP_P((
	BerElement *ber,
	struct berval **bv ));

LDAP_F( unsigned long )
ber_get_bitstringa LDAP_P((
	BerElement *ber,
	char **buf,
	unsigned long *len ));

LDAP_F( unsigned long )
ber_get_null LDAP_P((
	BerElement *ber ));

LDAP_F( unsigned long )
ber_get_boolean LDAP_P((
	BerElement *ber,
	int *boolval ));

LDAP_F( unsigned long )
ber_first_element LDAP_P((
	BerElement *ber,
	unsigned long *len,
	char **last ));

LDAP_F( unsigned long )
ber_next_element LDAP_P((
	BerElement *ber,
	unsigned long *len,
	char *last ));

LDAP_F( unsigned long )
ber_scanf LDAP_P((								  
	BerElement *ber,
	LDAP_CONST char *fmt,
	... ));

LDAP_F( void )
ber_set_string_translators LDAP_P((
	BerElement *ber,
	BERTranslateProc encode_proc,
	BERTranslateProc decode_proc ));

/*
 * in encode.c
 */
typedef int (*BEREncodeCallback) LDAP_P((
	BerElement *ber,
	void *data ));

LDAP_F( int )
ber_put_enum LDAP_P((
	BerElement *ber,
	long num,
	unsigned long tag ));

LDAP_F( int )
ber_put_int LDAP_P((
	BerElement *ber,
	long num,
	unsigned long tag ));

LDAP_F( int )
ber_put_ostring LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	unsigned long len,
	unsigned long tag ));

LDAP_F( int )
ber_put_berval LDAP_P((
	BerElement *ber,
	LDAP_CONST struct berval *bv,
	unsigned long tag ));

LDAP_F( int )
ber_put_string LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	unsigned long tag ));

LDAP_F( int )
ber_put_bitstring LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	unsigned long bitlen,
	unsigned long tag ));

LDAP_F( int )
ber_put_null LDAP_P((
	BerElement *ber,
	unsigned long tag ));

LDAP_F( int )
ber_put_boolean LDAP_P((
	BerElement *ber,
	int boolval,
	unsigned long tag ));

LDAP_F( int )
ber_start_seq LDAP_P((
	BerElement *ber,
	unsigned long tag ));

LDAP_F( int )
ber_start_set LDAP_P((
	BerElement *ber,
	unsigned long tag ));

LDAP_F( int )
ber_put_seq LDAP_P((
	BerElement *ber ));

LDAP_F( int )
ber_put_set LDAP_P((
	BerElement *ber ));

LDAP_F( int )
ber_printf LDAP_P((
	BerElement *ber,
	LDAP_CONST char *fmt,
	... ));
/*
 * in io.c:
 */

LDAP_F( long )
ber_read LDAP_P((
	BerElement *ber,
	char *buf,
	unsigned long len ));

LDAP_F( long )
ber_write LDAP_P((
	BerElement *ber,
	LDAP_CONST char *buf,
	unsigned long len,
	int nosos ));

LDAP_F( void )
ber_free LDAP_P((
	BerElement *ber,
	int freebuf ));

LDAP_F( int )
ber_flush LDAP_P((
	Sockbuf *sb, BerElement *ber, int freeit ));

LDAP_F( BerElement * )
ber_alloc LDAP_P(( void )); /* DEPRECATED */

LDAP_F( BerElement * )
der_alloc LDAP_P(( void )); /* DEPRECATED */

LDAP_F( BerElement * )
ber_alloc_t LDAP_P((
	int beroptions ));

LDAP_F( BerElement * )
ber_dup LDAP_P((
	LDAP_CONST BerElement *ber ));

LDAP_F( unsigned long )
ber_get_next LDAP_P((
	Sockbuf *sb,
	unsigned long *len,
	BerElement *ber ));

LDAP_F( void )
ber_init_w_nullc LDAP_P((
	BerElement *ber,
	int options ));

LDAP_F( void )
ber_reset LDAP_P((
	BerElement *ber,
	int was_writing ));

/*
 * LBER draft-ietf-ldapext-ldap-c-api-01 routines
 */
LDAP_F( BerElement * )
ber_init LDAP_P((
	struct berval *bv ));

LDAP_F( int )
ber_flatten LDAP_P((
	LDAP_CONST BerElement *ber,
	struct berval **bvPtr ));

/*
 * LBER ber accessor functions
 */

LDAP_F( int )
ber_get_option LDAP_P((
	void *item,
	int option,
	void *outvalue));

LDAP_F( int )
ber_set_option LDAP_P((
	void *item,
	int option,
	LDAP_CONST void *invalue));

/*
 * LBER sockbuf.c
 */

LDAP_F( Sockbuf * )
ber_sockbuf_alloc( void );

LDAP_F( Sockbuf *  )
ber_sockbuf_alloc_fd(
	int fd );

LDAP_F( void )
ber_sockbuf_free(
	Sockbuf *sb );

/*
 * LBER memory.c
 */
LDAP_F( void * )
ber_memalloc LDAP_P((
	size_t s ));

LDAP_F( void * )
ber_memrealloc LDAP_P((
	void* p,
	size_t s ));

LDAP_F( void * )
ber_memcalloc LDAP_P((
	size_t n,
	size_t s ));

LDAP_F( void )
ber_memfree LDAP_P((
	void* p ));

LDAP_F( void )
ber_memvfree LDAP_P((
	void** vector ));

LDAP_F( void )
ber_bvfree LDAP_P((
	struct berval *bv ));

LDAP_F( void )
ber_bvecfree LDAP_P((
	struct berval **bv ));

LDAP_F( struct berval * )
ber_bvdup LDAP_P((
	LDAP_CONST struct berval *bv ));

LDAP_END_DECL

#endif /* _LBER_H */
