/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
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

#include <lber_types.h>

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
#define LBER_CLASS_UNIVERSAL	((ber_tag_t) 0x00U)
#define LBER_CLASS_APPLICATION	((ber_tag_t) 0x40U)
#define LBER_CLASS_CONTEXT		((ber_tag_t) 0x80U)
#define LBER_CLASS_PRIVATE		((ber_tag_t) 0xc0U)
#define LBER_CLASS_MASK			((ber_tag_t) 0xc0U)

/* BER encoding type and mask */
#define LBER_PRIMITIVE			((ber_tag_t) 0x00U)
#define LBER_CONSTRUCTED		((ber_tag_t) 0x20U)
#define LBER_ENCODING_MASK		((ber_tag_t) 0x20U)

#define LBER_BIG_TAG_MASK		((ber_tag_t) 0x1fU)
#define LBER_MORE_TAG_MASK		((ber_tag_t) 0x80U)

/*
 * Note that LBER_ERROR and LBER_DEFAULT are values that can never appear
 * as valid BER tags, and so it is safe to use them to report errors.  In
 * fact, any tag for which the following is true is invalid:
 */
#define LBER_INVALID(t)     (((t) & (ber_tag_t) 0x080UL) \
	&& (((t) & (ber_tag_t) ~ 0x0FF))

#define LBER_ERROR			((ber_tag_t) -1)
#define LBER_DEFAULT		((ber_tag_t) -1)

/* general BER types we know about */
#define LBER_BOOLEAN		((ber_tag_t) 0x01UL)
#define LBER_INTEGER		((ber_tag_t) 0x02UL)
#define LBER_BITSTRING		((ber_tag_t) 0x03UL)
#define LBER_OCTETSTRING	((ber_tag_t) 0x04UL)
#define LBER_NULL			((ber_tag_t) 0x05UL)
#define LBER_ENUMERATED		((ber_tag_t) 0x0aUL)
#define LBER_SEQUENCE		((ber_tag_t) 0x30UL)	/* constructed */
#define LBER_SET			((ber_tag_t) 0x31UL)	/* constructed */

/* LBER BerElement options */
#define LBER_USE_DER		0x01
#define LBER_USE_INDEFINITE_LEN	0x02

/* get/set options for BerElement */
#define LBER_OPT_BER_OPTIONS			0x01
#define LBER_OPT_BER_DEBUG				0x02
#define LBER_OPT_BER_REMAINING_BYTES	0x03
#define LBER_OPT_BER_TOTAL_BYTES		0x04
#define LBER_OPT_BER_BYTES_TO_WRITE		0x05

#define LBER_OPT_DEBUG_LEVEL	LBER_OPT_BER_DEBUG
#define LBER_OPT_REMAINING_BYTES	LBER_OPT_BER_REMAINING_BYTES
#define LBER_OPT_TOTAL_BYTES		LBER_OPT_BER_TOTAL_BYTES
#define LBER_OPT_BYTES_TO_WRITE		LBER_OPT_BER_BYTES_TO_WRITE

#define LBER_OPT_LOG_PRINT_FN	0x8001
#define LBER_OPT_MEMORY_FNS		0x8002
#define LBER_OPT_ERROR_FN		0x8003
#define LBER_OPT_LOG_PRINT_FILE		0x8004

typedef int* (*BER_ERRNO_FN) LDAP_P(( void ));

typedef void (*BER_LOG_PRINT_FN) LDAP_P(( char *buf ));

typedef void* (*BER_MEMALLOC_FN)	LDAP_P(( ber_len_t size ));
typedef void* (*BER_MEMCALLOC_FN)	LDAP_P(( ber_len_t n, ber_len_t size ));
typedef void* (*BER_MEMREALLOC_FN)	LDAP_P(( void *p, ber_len_t size ));
typedef void  (*BER_MEMFREE_FN)		LDAP_P(( void *p ));

typedef struct lber_memory_fns {
	BER_MEMALLOC_FN	bmf_malloc;
	BER_MEMCALLOC_FN bmf_calloc;
	BER_MEMREALLOC_FN bmf_realloc;
	BER_MEMFREE_FN bmf_free;
} BerMemoryFunctions;

/* LBER Sockbuf_IO options */ 
#define LBER_SB_OPT_GET_FD		1
#define LBER_SB_OPT_SET_FD		2
#define LBER_SB_OPT_HAS_IO		3
#define LBER_SB_OPT_SET_NONBLOCK	4
#define LBER_SB_OPT_UDP_GET_SRC		5
#define LBER_SB_OPT_UDP_SET_DST		6
#define LBER_SB_OPT_GET_SSL		7
#define LBER_SB_OPT_DATA_READY		8
#define LBER_SB_OPT_SET_READAHEAD	9
#define LBER_SB_OPT_DRAIN		10
#define LBER_SB_OPT_NEEDS_READ		11
#define LBER_SB_OPT_NEEDS_WRITE		12
/* Largest option used by the library */
#define LBER_SB_OPT_OPT_MAX		12

/* LBER IO operations stacking levels */
#define LBER_SBIOD_LEVEL_PROVIDER	10
#define LBER_SBIOD_LEVEL_TRANSPORT	20
#define LBER_SBIOD_LEVEL_APPLICATION	30

/* get/set options for Sockbuf */
#define LBER_OPT_SOCKBUF_DESC		0x1000
#define LBER_OPT_SOCKBUF_OPTIONS	0x1001
#define LBER_OPT_SOCKBUF_DEBUG		0x1002

/* on/off values */
#define LBER_OPT_ON		((void *) 1)
#define LBER_OPT_OFF	((void *) 0)

#define LBER_OPT_SUCCESS	(0)
#define LBER_OPT_ERROR		(-1)

typedef struct berelement BerElement;
typedef struct sockbuf Sockbuf;
typedef struct seqorset Seqorset;

typedef struct sockbuf_io Sockbuf_IO;

/* Structure for LBER IO operarion descriptor */
typedef struct sockbuf_io_desc {
	int			sbiod_level;
	Sockbuf			*sbiod_sb;
	Sockbuf_IO		*sbiod_io;
	void 			*sbiod_pvt;
	struct sockbuf_io_desc	*sbiod_next;
} Sockbuf_IO_Desc;

/* Structure for LBER IO operation functions */
struct sockbuf_io {
	int (*sbi_setup)( Sockbuf_IO_Desc *sbiod, void *arg );
	int (*sbi_remove)( Sockbuf_IO_Desc *sbiod );
	int (*sbi_ctrl)( Sockbuf_IO_Desc *sbiod, int opt, void *arg);
	
	ber_slen_t (*sbi_read)( Sockbuf_IO_Desc *sbiod, void *buf,
		ber_len_t len );
	ber_slen_t (*sbi_write)( Sockbuf_IO_Desc *sbiod, void *buf,
		ber_len_t len );
	
	int (*sbi_close)( Sockbuf_IO_Desc *sbiod );
};

/* Helper macros for LBER IO functions */
#define LBER_SBIOD_READ_NEXT( sbiod, buf, len ) \
	( (sbiod)->sbiod_next->sbiod_io->sbi_read( (sbiod)->sbiod_next, \
		buf, len ) )
#define LBER_SBIOD_WRITE_NEXT( sbiod, buf, len ) \
	( (sbiod)->sbiod_next->sbiod_io->sbi_write( (sbiod)->sbiod_next, \
		buf, len ) )
#define LBER_SBIOD_CTRL_NEXT( sbiod, opt, arg ) \
	( (sbiod)->sbiod_next ? \
		( (sbiod)->sbiod_next->sbiod_io->sbi_ctrl( \
		(sbiod)->sbiod_next, opt, arg ) ) : 0 )

/* structure for returning a sequence of octet strings + length */
typedef struct berval {
	ber_len_t	bv_len;
	char		*bv_val;
} BerValue;

/* this should be moved to lber-int.h */

/*
 * in bprint.c:
 */
LIBLBER_F( void )
ber_print_error LDAP_P((
	LDAP_CONST char *data ));

LIBLBER_F( void )
ber_bprint LDAP_P((
	LDAP_CONST char *data, ber_len_t len ));

LIBLBER_F( void )
ber_dump LDAP_P((
	BerElement *ber, int inout ));

LIBLBER_F( void )
ber_sos_dump LDAP_P((
	Seqorset *sos ));


/*
 * in decode.c:
 */
typedef int (*BERDecodeCallback) LDAP_P((
	BerElement *ber,
	void *data,
	int mode ));

LIBLBER_F( ber_tag_t )
ber_get_tag LDAP_P((
	BerElement *ber ));

LIBLBER_F( ber_tag_t )
ber_skip_tag LDAP_P((
	BerElement *ber,
	ber_len_t *len ));

LIBLBER_F( ber_tag_t )
ber_peek_tag LDAP_P((
	BerElement *ber,
	ber_len_t *len ));

LIBLBER_F( ber_tag_t )
ber_get_int LDAP_P((
	BerElement *ber,
	ber_int_t *num ));

LIBLBER_F( ber_tag_t )
ber_get_enum LDAP_P((
	BerElement *ber,
	ber_int_t *num ));

LIBLBER_F( ber_tag_t )
ber_get_stringb LDAP_P((
	BerElement *ber,
	char *buf,
	ber_len_t *len ));

LIBLBER_F( ber_tag_t )
ber_get_stringa LDAP_P((
	BerElement *ber,
	char **buf ));

LIBLBER_F( ber_tag_t )
ber_get_stringal LDAP_P((
	BerElement *ber,
	struct berval **bv ));

LIBLBER_F( ber_tag_t )
ber_get_bitstringa LDAP_P((
	BerElement *ber,
	char **buf,
	ber_len_t *len ));

LIBLBER_F( ber_tag_t )
ber_get_null LDAP_P((
	BerElement *ber ));

LIBLBER_F( ber_tag_t )
ber_get_boolean LDAP_P((
	BerElement *ber,
	ber_int_t *boolval ));

LIBLBER_F( ber_tag_t )
ber_first_element LDAP_P((
	BerElement *ber,
	ber_len_t *len,
	char **last ));

LIBLBER_F( ber_tag_t )
ber_next_element LDAP_P((
	BerElement *ber,
	ber_len_t *len,
	LDAP_CONST char *last ));

LIBLBER_F( ber_tag_t )
ber_scanf LDAP_P((								  
	BerElement *ber,
	LDAP_CONST char *fmt,
	... ));

/*
 * in encode.c
 */
typedef int (*BEREncodeCallback) LDAP_P((
	BerElement *ber,
	void *data ));

LIBLBER_F( int )
ber_put_enum LDAP_P((
	BerElement *ber,
	ber_int_t num,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_int LDAP_P((
	BerElement *ber,
	ber_int_t num,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_ostring LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	ber_len_t len,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_berval LDAP_P((
	BerElement *ber,
	LDAP_CONST struct berval *bv,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_string LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_bitstring LDAP_P((
	BerElement *ber,
	LDAP_CONST char *str,
	ber_len_t bitlen,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_null LDAP_P((
	BerElement *ber,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_boolean LDAP_P((
	BerElement *ber,
	ber_int_t boolval,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_start_seq LDAP_P((
	BerElement *ber,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_start_set LDAP_P((
	BerElement *ber,
	ber_tag_t tag ));

LIBLBER_F( int )
ber_put_seq LDAP_P((
	BerElement *ber ));

LIBLBER_F( int )
ber_put_set LDAP_P((
	BerElement *ber ));

LIBLBER_F( int )
ber_printf LDAP_P((
	BerElement *ber,
	LDAP_CONST char *fmt,
	... ));


/*
 * in io.c:
 */

LIBLBER_F( ber_slen_t )
ber_read LDAP_P((
	BerElement *ber,
	char *buf,
	ber_len_t len ));

LIBLBER_F( ber_slen_t )
ber_write LDAP_P((
	BerElement *ber,
	LDAP_CONST char *buf,
	ber_len_t len,
	int nosos ));

LIBLBER_F( void )
ber_free LDAP_P((
	BerElement *ber,
	int freebuf ));

LIBLBER_F( int )
ber_flush LDAP_P((
	Sockbuf *sb,
	BerElement *ber,
	int freeit ));

LIBLBER_F( BerElement * )
ber_alloc LDAP_P(( void )); /* DEPRECATED */

LIBLBER_F( BerElement * )
der_alloc LDAP_P(( void )); /* DEPRECATED */

LIBLBER_F( BerElement * )
ber_alloc_t LDAP_P((
	int beroptions ));

LIBLBER_F( BerElement * )
ber_dup LDAP_P((
	BerElement *ber ));

LIBLBER_F( ber_tag_t )
ber_get_next LDAP_P((
	Sockbuf *sb,
	ber_len_t *len,
	BerElement *ber ));

LIBLBER_F( void )
ber_init_w_nullc LDAP_P((
	BerElement *ber,
	int options ));

LIBLBER_F( void )
ber_reset LDAP_P((
	BerElement *ber,
	int was_writing ));

LIBLBER_F( BerElement * )
ber_init LDAP_P((
	struct berval *bv ));

LIBLBER_F( int )
ber_flatten LDAP_P((
	BerElement *ber,
	struct berval **bvPtr ));

/*
 * LBER ber accessor functions
 */

LIBLBER_F( int )
ber_get_option LDAP_P((
	void *item,
	int option,
	void *outvalue));

LIBLBER_F( int )
ber_set_option LDAP_P((
	void *item,
	int option,
	LDAP_CONST void *invalue));

/*
 * LBER sockbuf.c
 */

LIBLBER_F( Sockbuf *  )
ber_sockbuf_alloc LDAP_P((
	void ));

LIBLBER_F( void )
ber_sockbuf_free LDAP_P((
	Sockbuf *sb ));

LIBLBER_F( int )
ber_sockbuf_add_io LDAP_P((
	Sockbuf *sb,
	Sockbuf_IO *sbio,
	int layer,
	void *arg ));

LIBLBER_F( int )
ber_sockbuf_remove_io LDAP_P((
	Sockbuf *sb,
	Sockbuf_IO *sbio,
	int layer ));

LIBLBER_F( int )
ber_sockbuf_ctrl LDAP_P((
	Sockbuf *sb,
	int opt,
	void *arg ));

LIBLBER_F( Sockbuf_IO ) ber_sockbuf_io_tcp;
LIBLBER_F( Sockbuf_IO ) ber_sockbuf_io_udp;
LIBLBER_F( Sockbuf_IO ) ber_sockbuf_io_readahead;
LIBLBER_F( Sockbuf_IO ) ber_sockbuf_io_fd;
LIBLBER_F( Sockbuf_IO ) ber_sockbuf_io_debug;

/*
 * LBER memory.c
 */
LIBLBER_F( void * )
ber_memalloc LDAP_P((
	ber_len_t s ));

LIBLBER_F( void * )
ber_memrealloc LDAP_P((
	void* p,
	ber_len_t s ));

LIBLBER_F( void * )
ber_memcalloc LDAP_P((
	ber_len_t n,
	ber_len_t s ));

LIBLBER_F( void )
ber_memfree LDAP_P((
	void* p ));

LIBLBER_F( void )
ber_memvfree LDAP_P((
	void** vector ));

LIBLBER_F( void )
ber_bvfree LDAP_P((
	struct berval *bv ));

LIBLBER_F( void )
ber_bvecfree LDAP_P((
	struct berval **bv ));

LIBLBER_F( int )
ber_bvecadd LDAP_P((
	struct berval ***bvec,
	struct berval *bv ));

LIBLBER_F( struct berval * )
ber_bvdup LDAP_P((
	LDAP_CONST struct berval *bv ));

LIBLBER_F( struct berval * )
ber_bvstr LDAP_P((
	LDAP_CONST char * ));

LIBLBER_F( struct berval * )
ber_bvstrdup LDAP_P((
	LDAP_CONST char * ));

LIBLBER_F( char * )
ber_strdup LDAP_P((
	LDAP_CONST char * ));

/*
 * error.c
 */
LIBLBER_F( int * ) ber_errno_addr LDAP_P((void));
#define ber_errno (*(ber_errno_addr)())

#define LBER_ERROR_NONE		0
#define LBER_ERROR_PARAM	0x1
#define LBER_ERROR_MEMORY	0x2

LDAP_END_DECL

#endif /* _LBER_H */
