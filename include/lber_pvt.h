/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */
/*
 * lber_pvt.h - Header for ber_pvt_ functions. These are meant to be used
 * 		by the OpenLDAP distribution only.
 */

#ifndef _LBER_PVT_H
#define _LBER_PVT_H 1

#include <lber.h>

LDAP_BEGIN_DECL

typedef struct sockbuf_buf {
	ber_len_t		buf_size;
	ber_len_t		buf_ptr;
	ber_len_t		buf_end;
	char			*buf_base;
} Sockbuf_Buf;

/*
 * bprint.c
 */
LBER_V( BER_LOG_PRINT_FN ) ber_pvt_log_print;

LBER_F( int )
ber_pvt_log_printf LDAP_P((
	int errlvl,
	int loglvl,
	const char *fmt,
	... )) LDAP_GCCATTR((format(printf, 3, 4)));

/*
 * sockbuf.c
 */
LBER_F( ber_slen_t )
ber_pvt_sb_do_write LDAP_P(( Sockbuf_IO_Desc *sbiod, Sockbuf_Buf *buf_out ));

LBER_F( void )
ber_pvt_sb_buf_init LDAP_P(( Sockbuf_Buf *buf ));

LBER_F( void )
ber_pvt_sb_buf_destroy LDAP_P(( Sockbuf_Buf *buf ));

LBER_F( int )
ber_pvt_sb_grow_buffer LDAP_P(( Sockbuf_Buf *buf, ber_len_t minsize ));

LBER_F( ber_len_t )
ber_pvt_sb_copy_out LDAP_P(( Sockbuf_Buf *sbb, char *buf, ber_len_t len ));

LBER_F( int )
ber_pvt_socket_set_nonblock LDAP_P(( ber_socket_t sd, int nb ));


#if 0
#define ber_bvstrcmp(v1,v2) \
	((v1)->bv_len < (v2)->bv_len \
		? -1 : ((v1)->bv_len > (v2)->bv_len \
			? 1 : strncmp((v1)->bv_val, (v2)->bv_val, (v1)->bv_len) ))
#else
	/* avoid strncmp() */
#define ber_bvstrcmp(v1,v2)	ber_bvcmp((v1),(v2))
#endif

#define ber_bvstrcasecmp(v1,v2) \
	((v1)->bv_len < (v2)->bv_len \
		? -1 : ((v1)->bv_len > (v2)->bv_len \
			? 1 : strncasecmp((v1)->bv_val, (v2)->bv_val, (v1)->bv_len) ))

#define ber_bvccmp(v1,c) \
	( (v1)->bv_len == 1 && (v1)->bv_val[0] == (c) )

#define ber_strccmp(s,c) \
	( (s)[0] == (c) && (s)[1] == '\0' )

#define ber_bvchr(bv,c) \
	memchr( (bv)->bv_val, (c), (bv)->bv_len )

#define BER_BVC(x)	{ sizeof( (x) ) - 1, (x) }
#define BER_BVNULL	{ 0L, NULL }

LDAP_END_DECL

#endif

