/* $OpenLDAP$ */
/*
 * Copyright 2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * Basic T.61 <-> UTF-8 conversion
 *
 * These routines will perform a lossless translation from T.61 to UTF-8
 * and a lossy translation from UTF-8 to T.61.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_utf8.h"

#include "ldap_defaults.h"

/*
 * T.61 is somewhat braindead; even in the 7-bit space it is not
 * completely equivalent to 7-bit US-ASCII. Our definition of the
 * character set comes from RFC 1345 with a slightly more readable
 * rendition at http://std.dkuug.dk/i18n/charmaps/T.61-8BIT.
 *
 * Even though '#' and '$' are present in the 7-bit US-ASCII space,
 * (x23 and x24, resp.) in T.61 they are mapped to 8-bit characters
 * xA6 and xA4. 
 *
 * Also T.61 lacks
 *	backslash 	\	(x5C)
 *	caret		^	(x5E)
 *	backquote	`	(x60)
 *	left brace	{	(x7B)
 *	right brace	}	(x7D)
 *	tilde		~	(x7E)
 *
 * In T.61, the codes xC1 to xCF (excluding xC9, unused) are non-spacing
 * accents of some form or another. There are predefined combinations
 * for certain characters, but they can also be used arbitrarily. The
 * table at dkuug.dk maps these accents to the E000 "private use" range
 * of the Unicode space, but I believe they more properly belong in the
 * 0300 range (non-spacing accents). The transformation is complicated
 * slightly because Unicode wants the non-spacing character to follow
 * the base character, while T.61 has the non-spacing character leading.
 * Also, T.61 specifically recognizes certain combined pairs as "characters"
 * but doesn't specify how to treat unrecognized pairs. This code will
 * always attempt to combine pairs when a known Unicode composite exists.
 */

const wchar_t ldap_t61_tab[] = {
	0x000, 0x001, 0x002, 0x003, 0x004, 0x005, 0x006, 0x007,
	0x008, 0x009, 0x00a, 0x00b, 0x00c, 0x00d, 0x00e, 0x00f,
	0x010, 0x011, 0x012, 0x013, 0x014, 0x015, 0x016, 0x017,
	0x018, 0x019, 0x01a, 0x01b, 0x01c, 0x01d, 0x01e, 0x01f,
	0x020, 0x021, 0x022, 0x000, 0x000, 0x025, 0x026, 0x027,
	0x028, 0x029, 0x02a, 0x02b, 0x02c, 0x02d, 0x02e, 0x02f,
	0x030, 0x031, 0x032, 0x033, 0x034, 0x035, 0x036, 0x037,
	0x038, 0x039, 0x03a, 0x03b, 0x03c, 0x03d, 0x03e, 0x03f,
	0x040, 0x041, 0x042, 0x043, 0x044, 0x045, 0x046, 0x047,
	0x048, 0x049, 0x04a, 0x04b, 0x04c, 0x04d, 0x04e, 0x04f,
	0x050, 0x051, 0x052, 0x053, 0x054, 0x055, 0x056, 0x057,
	0x058, 0x059, 0x05a, 0x05b, 0x000, 0x05d, 0x000, 0x05f,
	0x000, 0x061, 0x062, 0x063, 0x064, 0x065, 0x066, 0x067,
	0x068, 0x069, 0x06a, 0x06b, 0x06c, 0x06d, 0x06e, 0x06f,
	0x070, 0x071, 0x072, 0x073, 0x074, 0x075, 0x076, 0x077,
	0x078, 0x079, 0x07a, 0x000, 0x07c, 0x000, 0x000, 0x07f,
	0x080, 0x081, 0x082, 0x083, 0x084, 0x085, 0x086, 0x087,
	0x088, 0x089, 0x08a, 0x08b, 0x08c, 0x08d, 0x08e, 0x08f,
	0x090, 0x091, 0x092, 0x093, 0x094, 0x095, 0x096, 0x097,
	0x098, 0x099, 0x09a, 0x09b, 0x09c, 0x09d, 0x09e, 0x09f,
	0x0a0, 0x0a1, 0x0a2, 0x0a3, 0x024, 0x0a5, 0x023, 0x0a7,
	0x0a4, 0x000, 0x000, 0x0ab, 0x000, 0x000, 0x000, 0x000,
	0x0b0, 0x0b1, 0x0b2, 0x0b3, 0x0d7, 0x0b5, 0x0b6, 0x0b7,
	0x0f7, 0x000, 0x000, 0x0bb, 0x0bc, 0x0bd, 0x0be, 0x0bf,
	0x000, 0x300, 0x301, 0x302, 0x303, 0x304, 0x306, 0x307,
	0x308, 0x000, 0x30a, 0x327, 0x332, 0x30b, 0x328, 0x30c,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
	0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000, 0x000,
	0x2126, 0xc6, 0x0d0, 0x0aa, 0x126, 0x000, 0x132, 0x13f,
	0x141, 0x0d8, 0x152, 0x0ba, 0x0de, 0x166, 0x14a, 0x149,
	0x138, 0x0e6, 0x111, 0x0f0, 0x127, 0x131, 0x133, 0x140,
	0x142, 0x0f8, 0x153, 0x0df, 0x0fe, 0x167, 0x14b, 0x000
};

typedef wchar_t wvec16[16];
typedef wchar_t wvec32[32];
typedef wchar_t wvec64[64];

/* Substitutions when 0xc1-0xcf appears by itself or with space 0x20 */
static const wvec16 accents = {
	0x000, 0x060, 0x0b4, 0x05e, 0x07e, 0x0af, 0x2d8, 0x2d9,
	0x0a8, 0x000, 0x2da, 0x0b8, 0x000, 0x2dd, 0x2db, 0x2c7};

/* In the following tables, base characters commented in (parentheses)
 * are not defined by T.61 but are mapped anyway since their Unicode
 * composite exists.
 */

/* Grave accented chars AEIOU (NWY) */
static const wvec32 c1_vec1 = {
	/* Upper case */
	0, 0xc0, 0, 0, 0, 0xc8, 0, 0, 0, 0xcc, 0, 0, 0, 0, 0x1f8, 0xd2,
	0, 0, 0, 0, 0, 0xd9, 0, 0x1e80, 0, 0x1ef2, 0, 0, 0, 0, 0, 0};
static const wvec32 c1_vec2 = {
	/* Lower case */
	0, 0xe0, 0, 0, 0, 0xe8, 0, 0, 0, 0xec, 0, 0, 0, 0, 0x1f9, 0xf2,
	0, 0, 0, 0, 0, 0xf9, 0, 0x1e81, 0, 0x1ef3, 0, 0, 0, 0, 0, 0};
	
static const wvec32 *c1_grave[] = {
	NULL, NULL, &c1_vec1, &c1_vec2, NULL, NULL, NULL, NULL
};

/* Acute accented chars AEIOUYCLNRSZ (GKMPW) */
static const wvec32 c2_vec1 = {
	/* Upper case */
	0, 0xc1, 0, 0x106, 0, 0xc9, 0, 0x1f4,
	0, 0xcd, 0, 0x1e30, 0x139, 0x1e3e, 0x143, 0xd3,
	0x1e54, 0, 0x154, 0x15a, 0, 0xda, 0, 0x1e82,
	0, 0xdd, 0x179, 0, 0, 0, 0, 0};
static const wvec32 c2_vec2 = {
	/* Lower case */
	0, 0xe1, 0, 0x107, 0, 0xe9, 0, 0x1f5,
	0, 0xed, 0, 0x1e31, 0x13a, 0x1e3f, 0x144, 0xf3,
	0x1e55, 0, 0x155, 0x15b, 0, 0xfa, 0, 0x1e83,
	0, 0xfd, 0x17a, 0, 0, 0, 0, 0};
static const wvec32 c2_vec3 = {
	/* (AE and ae) */
	0, 0x1fc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0x1fd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static const wvec32 *c2_acute[] = {
	NULL, NULL, &c2_vec1, &c2_vec2, NULL, NULL, NULL, &c2_vec3
};

/* Circumflex AEIOUYCGHJSW (Z) */
static const wvec32 c3_vec1 = {
	/* Upper case */
	0, 0xc2, 0, 0x108, 0, 0xca, 0, 0x11c,
	0x124, 0xce, 0x134, 0, 0, 0, 0, 0xd4,
	0, 0, 0, 0x15c, 0, 0xdb, 0, 0x174,
	0, 0x176, 0x1e90, 0, 0, 0, 0, 0};
static const wvec32 c3_vec2 = {
	/* Lower case */
	0, 0xe2, 0, 0x109, 0, 0xea, 0, 0x11d,
	0x125, 0xee, 0x135, 0, 0, 0, 0, 0xf4,
	0, 0, 0, 0x15d, 0, 0xfb, 0, 0x175,
	0, 0x177, 0x1e91, 0, 0, 0, 0, 0};
static const wvec32 *c3_circumflex[] = {
	NULL, NULL, &c3_vec1, &c3_vec2, NULL, NULL, NULL, NULL
};

/* Tilde AIOUN (EVY) */
static const wvec32 c4_vec1 = {
	/* Upper case */
	0, 0xc5, 0, 0, 0, 0x1ebc, 0, 0, 0, 0x128, 0, 0, 0, 0, 0xd1, 0xd5,
	0, 0, 0, 0, 0, 0x168, 0x1e7c, 0, 0, 0x1ef8, 0, 0, 0, 0, 0, 0};
static const wvec32 c4_vec2 = {
	/* Lower case */
	0, 0xe5, 0, 0, 0, 0x1ebd, 0, 0, 0, 0x129, 0, 0, 0, 0, 0xf1, 0xf5,
	0, 0, 0, 0, 0, 0x169, 0x1e7d, 0, 0, 0x1ef9, 0, 0, 0, 0, 0, 0};
static const wvec32 *c4_tilde[] = {
	NULL, NULL, &c4_vec1, &c4_vec2, NULL, NULL, NULL, NULL
};

/* Macron AEIOU (YG) */
static const wvec32 c5_vec1 = {
	/* Upper case */
	0, 0x100, 0, 0, 0, 0x112, 0, 0x1e20, 0, 0x12a, 0, 0, 0, 0, 0, 0x14c,
	0, 0, 0, 0, 0, 0x16a, 0, 0, 0, 0x232, 0, 0, 0, 0, 0, 0};
static const wvec32 c5_vec2 = {
	/* Lower case */
	0, 0x101, 0, 0, 0, 0x113, 0, 0x1e21, 0, 0x12b, 0, 0, 0, 0, 0, 0x14d,
	0, 0, 0, 0, 0, 0x16b, 0, 0, 0, 0x233, 0, 0, 0, 0, 0, 0};
static const wvec32 c5_vec3 = {
	/* (AE and ae) */
	0, 0x1e2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0x1e3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *c5_macron[] = {
	NULL, NULL, &c5_vec1, &c5_vec2, NULL, NULL, NULL, &c5_vec3
};

/* Breve AUG (EIO) */
static const wvec32 c6_vec1 = {
	/* Upper case */
	0, 0x102, 0, 0, 0, 0x114, 0, 0x11e, 0, 0x12c, 0, 0, 0, 0, 0, 0x14e,
	0, 0, 0, 0, 0, 0x16c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 c6_vec2 = {
	/* Lower case */
	0, 0x103, 0, 0, 0, 0x115, 0, 0x11f, 0, 0x12d, 0, 0, 0, 0, 0, 0x14f,
	0, 0, 0, 0, 0, 0x16d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *c6_breve[] = {
	NULL, NULL, &c6_vec1, &c6_vec2, NULL, NULL, NULL, NULL
};

/* Dot Above CEGIZ (AOBDFHMNPRSTWXY) */
static const wvec32 c7_vec1 = {
	/* Upper case */
	0, 0x226, 0x1e02, 0x10a, 0x1e0a, 0x116, 0x1e1e, 0x120,
	0x1e22, 0x130, 0, 0, 0, 0x1e40, 0x1e44, 0x22e,
	0x1e56, 0, 0x1e58, 0x1e60, 0x1e6a, 0, 0, 0x1e86,
	0x1e8a, 0x1e8e, 0x17b, 0, 0, 0, 0, 0};
static const wvec32 c7_vec2 = {
	/* Lower case */
	0, 0x227, 0x1e03, 0x10b, 0x1e0b, 0x117, 0x1e1f, 0x121,
	0x1e23, 0, 0, 0, 0, 0x1e41, 0x1e45, 0x22f,
	0x1e57, 0, 0x1e59, 0x1e61, 0x1e6b, 0, 0, 0x1e87,
	0x1e8b, 0x1e8f, 0x17c, 0, 0, 0, 0, 0};
static const wvec32 *c7_dotabove[] = {
	NULL, NULL, &c7_vec1, &c7_vec2, NULL, NULL, NULL, NULL
};

/* Diaeresis AEIOUY (HWXt) */
static const wvec32 c8_vec1 = {
	/* Upper case */
	0, 0xc4, 0, 0, 0, 0xcb, 0, 0, 0x1e26, 0xcf, 0, 0, 0, 0, 0, 0xd6,
	0, 0, 0, 0, 0, 0xdc, 0, 0x1e84, 0x1e8c, 0x178, 0, 0, 0, 0, 0, 0};
static const wvec32 c8_vec2 = {
	/* Lower case */
	0, 0xe4, 0, 0, 0, 0xeb, 0, 0, 0x1e27, 0xef, 0, 0, 0, 0, 0, 0xf6,
	0, 0, 0, 0, 0x1e97, 0xfc, 0, 0x1e85, 0x1e8d, 0xff, 0, 0, 0, 0, 0, 0};
static const wvec32 *c8_diaeresis[] = {
	NULL, NULL, &c8_vec1, &c8_vec2, NULL, NULL, NULL, NULL
};

/* Ring Above AU (wy) */
static const wvec32 ca_vec1 = {
	/* Upper case */
	0, 0xc5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0x16e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 ca_vec2 = {
	/* Lower case */
	0, 0xe5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0x16f, 0, 0x1e98, 0, 0x1e99, 0, 0, 0, 0, 0, 0};
static const wvec32 *ca_ringabove[] = {
	NULL, NULL, &ca_vec1, &ca_vec2, NULL, NULL, NULL, NULL
};

/* Cedilla CGKLNRST (EDH) */
static const wvec32 cb_vec1 = {
	/* Upper case */
	0, 0, 0, 0xc7, 0x1e10, 0x228, 0, 0x122,
	0x1e28, 0, 0, 0x136, 0x13b, 0, 0x145, 0,
	0, 0, 0x156, 0x15e, 0x162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 cb_vec2 = {
	/* Lower case */
	0, 0, 0, 0xe7, 0x1e11, 0x229, 0, 0x123,
	0x1e29, 0, 0, 0x137, 0x13c, 0, 0x146, 0,
	0, 0, 0x157, 0x15f, 0x163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *cb_cedilla[] = {
	NULL, NULL, &cb_vec1, &cb_vec2, NULL, NULL, NULL, NULL
};

/* Double Acute Accent OU */
static const wvec32 cd_vec1 = {
	/* Upper case */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x150,
	0, 0, 0, 0, 0, 0x170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 cd_vec2 = {
	/* Lower case */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x151,
	0, 0, 0, 0, 0, 0x171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *cd_doubleacute[] = {
	NULL, NULL, &cd_vec1, &cd_vec2, NULL, NULL, NULL, NULL
};

/* Ogonek AEIU (O) */
static const wvec32 ce_vec1 = {
	/* Upper case */
	0, 0x104, 0, 0, 0, 0x118, 0, 0, 0, 0x12e, 0, 0, 0, 0, 0, 0x1ea,
	0, 0, 0, 0, 0, 0x172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 ce_vec2 = {
	/* Lower case */
	0, 0x105, 0, 0, 0, 0x119, 0, 0, 0, 0x12f, 0, 0, 0, 0, 0, 0x1eb,
	0, 0, 0, 0, 0, 0x173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const wvec32 *ce_ogonek[] = {
	NULL, NULL, &ce_vec1, &ce_vec2, NULL, NULL, NULL, NULL
};

/* Caron CDELNRSTZ (AIOUGKjH) */
static const wvec32 cf_vec1 = {
	/* Upper case */
	0, 0x1cd, 0, 0x10c, 0x10e, 0x11a, 0, 0x1e6,
	0x21e, 0x1cf, 0, 0x1e8, 0x13d, 0, 0x147, 0x1d1,
	0, 0, 0x158, 0x160, 0x164, 0x1d3, 0, 0,
	0, 0, 0x17d, 0, 0, 0, 0, 0};
static const wvec32 cf_vec2 = {
	/* Lower case */
	0, 0x1ce, 0, 0x10d, 0x10f, 0x11b, 0, 0x1e7,
	0x21f, 0x1d0, 0x1f0, 0x1e9, 0x13e, 0, 0x148, 0x1d2,
	0, 0, 0x159, 0x161, 0x165, 0x1d4, 0, 0,
	0, 0, 0x17e, 0, 0, 0, 0, 0};
static const wvec32 *cf_caron[] = {
	NULL, NULL, &cf_vec1, &cf_vec2, NULL, NULL, NULL, NULL
};

static const wvec32 **cx_tab[] = {
	NULL, c1_grave, c2_acute, c3_circumflex, c4_tilde, c5_macron,
	c6_breve, c7_dotabove, c8_diaeresis, NULL, ca_ringabove,
	cb_cedilla, NULL, cd_doubleacute, ce_ogonek, cf_caron };

int ldap_t61s_valid( struct berval *str )
{
	unsigned char *c = (unsigned char *)str->bv_val;
	int i;

	for (i=0; i < str->bv_len; c++,i++)
		if (!ldap_t61_tab[*c])
			return 0;
	return 1;
}

/* Transform a T.61 string to UTF-8.
 */
int ldap_t61s_to_utf8s( struct berval *src, struct berval *dst )
{
	unsigned char *c;
	char *d;
	wchar_t tmp;
	int i, wlen = 0;

	/* Just count the length of the UTF-8 result first */
	for (i=0,c=(unsigned char *)src->bv_val; i < src->bv_len; c++,i++) {
		/* Invalid T.61 characters? */
		if (!ldap_t61_tab[*c]) 
			return LDAP_INVALID_SYNTAX;
		if (*c & 0xf0 == 0xc0) {
			int j = *c & 0x0f;
			/* If this is the end of the string, or if the base
			 * character is just a space, treat this as a regular
			 * spacing character.
			 */
			if ((!c[1] || c[1] == 0x20) && accents[j]) {
				wlen += ldap_x_wc_to_utf8(NULL, accents[j], 0);
			} else if (cx_tab[j] && cx_tab[j][c[1]>>5] &&
			/* We have a composite mapping for this pair */
				(*cx_tab[j][c[1]>>5])[c[1]&0x1f]) {
				wlen += ldap_x_wc_to_utf8( NULL,
					(*cx_tab[j][c[1]>>5])[c[1]&0x1f], 0);
			} else {
			/* No mapping, just swap it around so the base
			 * character comes first.
			 */
			 	wlen += ldap_x_wc_to_utf8(NULL, c[1], 0);
				wlen += ldap_x_wc_to_utf8(NULL,
					ldap_t61_tab[*c], 0);
			}
			c++; i++;
			continue;
		} else {
			wlen += ldap_x_wc_to_utf8(NULL, ldap_t61_tab[*c], 0);
		}
	}

	/* Now transform the string */
	dst->bv_len = wlen;
	dst->bv_val = LDAP_MALLOC( wlen+1 );
	d = dst->bv_val;
	if (!d)
		return LDAP_NO_MEMORY;

	for (i=0,c=(unsigned char *)src->bv_val; i < src->bv_len; c++,i++) {
		if (*c & 0xf0 == 0xc0) {
			int j = *c & 0x0f;
			/* If this is the end of the string, or if the base
			 * character is just a space, treat this as a regular
			 * spacing character.
			 */
			if ((!c[1] || c[1] == 0x20) && accents[j]) {
				d += ldap_x_wc_to_utf8(d, accents[j], 6);
			} else if (cx_tab[j] && cx_tab[j][c[1]>>5] &&
			/* We have a composite mapping for this pair */
				(*cx_tab[j][c[1]>>5])[c[1]&0x1f]) {
				d += ldap_x_wc_to_utf8(d, 
				(*cx_tab[j][c[1]>>5])[c[1]&0x1f], 6);
			} else {
			/* No mapping, just swap it around so the base
			 * character comes first.
			 */
				d += ldap_x_wc_to_utf8(d, c[1], 6);
				d += ldap_x_wc_to_utf8(d, ldap_t61_tab[*c], 6);
			}
			c++; i++;
			continue;
		} else {
			d += ldap_x_wc_to_utf8(d, ldap_t61_tab[*c], 6);
		}
	}
	*d = 0;
	return LDAP_SUCCESS;
}

int ldap_utf8s_to_t61s( struct berval *src, struct berval *dst )
{
}
