/* dn.c - routines for dealing with distinguished names */
/* $OpenLDAP$ */
/*
 * The functions normalize_unicode(), get_hexpair(), write_hex_pair(),
 * get_next_byte(), get_next_char(), get_ber_length(),
 * ber_parse_primitive_string(), ber_parse_string(), String_normalize(),
 * DirectoryString_normalize(), PrintableString_normalize(),
 * IA5String_normalize(), ber_parse_primitive_bitstring(),
 * ber_parse_bitstring(), getNext8bits(), bitString_normalize(), match_oid(),
 * match_key(), get_validated_av_in_dn(), get_validated_rdn_in_dn(),
 * and get_validated_dn() in this file were developed at the National Institute
 * of Standards and Technology by employees of the Federal Government in the
 * course of their official duties. Pursuant to title 17 Section 105 of the
 * United States Code the code in these functions is not subject to copyright
 * protection and is in the public domain. The copyright for all other code in
 * this file is as specified below.
 */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_pvt.h"

#include "slap.h"

#define B4LEADTYPE		0
#define B4TYPE			1
#define INOIDTYPE		2
#define INKEYTYPE		3
#define B4EQUAL			4
#define B4VALUE			5
#define INVALUE			6
#define INQUOTEDVALUE	7
#define B4SEPARATOR		8
#define	INBERENCODEDVALUE	9

#define UTF8DN 1

typedef int (*av_normalize_type)(char **, char **, int *, int, int, int, unsigned long *);

#define	PRINTABLE_STRING	1
#define	IA5_STRING		2
#define	TELETEX_STRING		3
#define	BMP_STRING		4
#define	UNIVERSAL_STRING	5
#define	UTF8_STRING		6
#define	DIRECTORY_STRING	7

/* unnormalized_unicode contains a string of ucs4 encoded unicode characters of length
 * len. Place in *d a normalized UTF8 encoded version of unnormalized_unicode. If firstchar is
 * true, then the first character output by uccanoncomp is the first character of the
 * attribute value. If successful, return 1 and advance *d to the end of the UTF8 encoded string.
 * Otherwise, return 0.
 */
static int
normalize_unicode(unsigned long *unnormalized_unicode, int len, char **d, int *av_length) {
	unsigned long *normalized_unicode;
	int i, normalized_len, char_len;
	char tmp;

#ifdef UTF8DN
	i = uccanondecomp(unnormalized_unicode, len, &normalized_unicode, &normalized_len);
	if ( (i == -1) || (normalized_unicode == NULL) )
		return 0;
	normalized_len = uccanoncomp(normalized_unicode, normalized_len);

	char_len = ldap_ucs4_to_utf8(normalized_unicode[0], *d);
	*d += char_len;

	for(i=1; i < normalized_len; i++) {
		char_len = ldap_ucs4_to_utf8(normalized_unicode[i], *d);
		tmp = **d;
		if ( RDN_NEEDSESCAPE( tmp ) || RDN_SPECIAL( tmp ) ) {
			**d = '\\';
			*d += 1;
			**d = tmp;
			*d+= 1;
		} else if ( ASCII_WHITESPACE( tmp ) && ASCII_SPACE( *(*d - 1) ) ) {
			 /* There should not be two consequtive space characters in the
			  * normalized string. */
			normalized_len--;
		} else {
			*d += char_len;
		}
	}
	*av_length += normalized_len;

	ch_free(normalized_unicode);
#endif

	return 1;
}

/* The next two bytes in the string beginning at *sec should be
 * a pair of hexadecimal characters. If they are, the value of that
 * hexpair is placed in *out and 1 is returned. Otherwise, 0 is returned.
 */
static int
get_hexpair(char **src, unsigned char *out)
{
	unsigned char ch;

	ch = **src;

	if ( !ASCII_XDIGIT(ch) ) {
		return 0;
	}

	if ( ASCII_DIGIT(ch) ) {
		*out = ch - '0';
	} else if ( ch >= 'A' && ch <= 'F' ) {
		*out = ch - 'A' + 10;
	} else {
		*out = ch - 'a' + 10;
	}

	*src += 1;

	ch = **src;

	if ( !ASCII_XDIGIT(ch) ) {
		return 0;
	}

	*out = *out << 4;

	if ( ASCII_DIGIT(ch) ) {
		*out += ch - '0';
	} else if ( ch >= 'A' && ch <= 'F' ) {
		*out += ch - 'A' + 10;
	} else {
		*out += ch - 'a' + 10;
	}

	*src += 1;

	return 1;
}


/* output in as a hexadecimal pair to the string pointed to be *d and advance *d to the end
 * of the hexpair.
 */
static void
write_hex_pair(char **d, unsigned char in) {
	unsigned char upper_nibble, lower_nibble;

	upper_nibble = (in & 0xF0) >> 4;
	lower_nibble = in & 0x0F;

	if (upper_nibble < 10)
		**d = upper_nibble + '0';
	else
		**d = upper_nibble - 10 + 'A';

	*d += 1;

	if (lower_nibble < 10)
		**d = lower_nibble + '0';
	else
		**d = lower_nibble - 10 + 'A';

	*d += 1;
}


/* The string beginning at *src represents a octet.
 * The octet is either represented by a single byte or
 * a '\' followed by a 2-byte hexpair or a single byte.
 * Place the octet in *out, increment *src to the beginning
 * of the next character. If the representation of the octet
 * began with a '\' then *is_escaped is set to 1. Otherwise,
 * *is_escaped is set to 0. If the string beginning at *src
 * does not represent a well formed octet, then 0 is returned.
 * Otherwise 1 is returned.
 */
static int
get_next_byte(char **src, unsigned char *out, int *is_escaped)
{
	unsigned char tmp;
	unsigned char s1, s2;

	s1 = **src;
	if (s1 == '\0')
		return 0;

	*src += 1;

	if ( s1 != '\\' ) {
		*out = s1;
		*is_escaped = 0;
		return 1;
	}

	*is_escaped = 1;

	s1 = **src;
	if ( s1 == '\0' )
		return 0;

	if ( !ASCII_XDIGIT( s1 ) ) {
		*src += 1;
		*out = s1;
		return 1;
	} else {
		if ( get_hexpair(src, &s2) ) {
			*out = s2;
			return 1;
		} else {
			return 0;
		}
	}
}


/* If the string beginning at *src is a well formed UTF8 character,
 * then the value of that character is placed in *out and 1 is returned.
 * If the string is not a well formed UTF8 character, 0 is returned.
 * If the character is an ASCII character, and its representation began
 * with a '\', then *is_escaped is set to 1. Otherwise *is_escaped is set to 0.
 * When the function returns, *src points to the first byte after the character.
 */
static int
get_next_char(char **src, unsigned long int *out, int *is_escaped)
{
	unsigned char tmp;
	int i, res, len;
	unsigned long int ch;

	static unsigned char mask[] = { 0, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

	res = get_next_byte( src, &tmp, is_escaped );

	*out = tmp;

#ifndef UTF8DN
	return res;
#else
	if ( ( res == 0 ) || ( tmp < 128 ) ) {
		return res;
	}

	/* This is a UTF8 encoded, non-ASCII character */
	len = ldap_utf8_charlen( &tmp );

	if ( len == 0 )
		return 0;

	ch = tmp & mask[len];

	for(i=1; i < len; i++) {
		res = get_next_byte( src, &tmp, is_escaped );
		if ( ( res == 0) || ( ( tmp & 0xc0 ) != 0x80 ) ) return 0;

		ch <<= 6;
		ch |= tmp & 0x3f;
	}

	*is_escaped = 0;
	*out = ch;
#endif
}


/* The string beginning at *s should be an ASCII-hex encoding of BER encoded
 * length data. If so, place the length in *length, add the length of the
 * length encoding to *encoded_length, advance *s to next byte after the end
 * of the length encoding, and return 1. Otherwise, return 0.
 */
static int
get_ber_length(
	char **s,
	unsigned int *encoded_length,
	unsigned long int *length
)
{
	int res;
	unsigned char ch, ch2;

	res = get_hexpair(s, &ch);
	if (res == 0)
		return 0;

	*encoded_length += 1;

	if ( (ch & 0x80) == 0) {
		/* Bit 8 is 0, so this byte gives the length */
		*length = ch;
	} else {
		/* This byte specifies the number of remaining length octets */
		ch = ch & 0x7F;

		if (ch > 4) {
			/* This assumes that length can hold up to a 32-bit
			 * integer and that bit strings will always be shorter
			 * than 2**32 bytes.
			 */
			return 0;
		}

		*length = 0;
		while (ch > 0) {
			*length = *length << 8;

			res = get_hexpair(s, &ch2);
			if (res == 0)
				return 0;

			*encoded_length += 1;
			*length = *length | ch2;

			ch--;
		}
	}

	return 1;
}


/* The string beginning at *s should be an ASCII-hex encoding of a BER
 * encoded string of type string_type (minus the "tag" octet) in which the
 * encoding is primitive, definite length. If it is, write a UTF8 encoding
 * of the string, according to RFC 2253, to *d, advance *s to one byte after
 * the end of the BER encoded string, advance *d to one byte after the UTF8
 * encoded string, add to *encoded_length the length of the BER encoding, add
 * to *av_length the number of UTF8 characters written to *d, set *firstchar
 * to 0 if any characters are written to *d, and return 1. Otherwise, return
 * 0. If make_uppercase is 1, write all of the characters in uppercase. If
 * not, write the characters as they occur in the BER encoding. If
 * normalize is 1, remove all leading and trailing whitespace, and
 * compress all whitespace between words to a single space. If not, transfer
 * whitespace from the BER encoding to the UTF8 encoding unchanged.
 */
static int
ber_parse_primitive_string(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int string_type,
	unsigned int *encoded_length,
	int *firstchar,
	unsigned long *unnormalized_unicode,
	int *unnormalized_unicode_len
)
{
	int i, len, res;
	unsigned char ch;
	unsigned long int uch;
	unsigned long int length;
	char tmp;

	static unsigned char mask[] = { 0, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

	res = get_ber_length(s, encoded_length, &length);
	if (res == 0)
		return 0;

	while (length > 0) {
		/* read in next character */
		if (string_type == PRINTABLE_STRING) {
			/* each character is one byte */
			res = get_hexpair(s, &ch);
			if (res == 0)
				return 0;

			*encoded_length += 1;
			length -= 1;

			if ( !SLAP_PRINTABLE(ch) )
				return 0;

			uch = ch;

		} else if (string_type == IA5_STRING) {
			/* each character is one byte */
			res = get_hexpair(s, &ch);
			if (res == 0)
				return 0;

			*encoded_length += 1;
			length -= 1;

			if ( !SLAP_IA5(ch) )
				return 0;

			uch = ch;

		} else if (string_type == TELETEX_STRING) {
			/* This code is not correct. Each character is one byte.
			 * However, the enocodings need to be transliterated to
			 * unicode.
			 */
			res = get_hexpair(s, &ch);
			if (res == 0)
				return 0;

			*encoded_length += 1;
			length -= 1;

			uch = ch;

		} else if (string_type == BMP_STRING) {
			/* This is a 2-byte unicode character */
			if (length < 2)
				return 0;

			uch = 0;

			for(i=0; i < 2; i++) {
				res = get_hexpair(s, &ch);
				if (res == 0)
					return 0;

				uch = uch << 8;
				uch = uch | ch;
			}

			*encoded_length += 2;
			length -= 2;
		} else if (string_type == UNIVERSAL_STRING) {
			/* This is a 4-byte unicode character */
			if (length < 4)
				return 0;

			uch = 0;

			for(i=0; i < 4; i++) {
				res = get_hexpair(s, &ch);
				if (res == 0)
					return 0;

				uch = uch << 8;
				uch = uch | ch;
			}

			*encoded_length += 4;
			length -= 4;
		} else if (string_type == UTF8_STRING) {
			res = get_hexpair(s, &ch);
			if (res == 0)
				return 0;

			*encoded_length += 1;

			#ifndef UTF8DN
				/* Not sure what to do here */
				uch = ch;
				length -= 1;
			#else
				len = ldap_utf8_charlen( &ch );
				if ( ( len == 0) || ( length < len ) )
					return 0;

				uch = ch & mask[len];

				for(i=1; i < len; i++) {
					res = get_hexpair(s, &ch);
					if ( ( res == 0) || ( ( ch & 0xc0 ) != 0x80 ) ) return 0;

					*encoded_length += 1;

					uch <<= 6;
					uch |= ch & 0x3f;
				}

				length -= len;
			#endif
		} else {
			/* Unknown string type */
			return 0;
		}

		/* Now add character to *d */

		#ifdef UTF8DN
			if (make_uppercase) {
				uch = uctoupper( uch );
			}

			if ( (uch < 128) && (*unnormalized_unicode_len > 0) ) {
				res = normalize_unicode(unnormalized_unicode, *unnormalized_unicode_len, d, av_length);
				if (res == 0)
					return 0;
				*unnormalized_unicode_len = 0;
			}

			if ( !normalize || !ASCII_WHITESPACE(uch) ) {
				if ( (*firstchar) && ASCII_SPACE(uch) ) {
					**d = '\\';
					*d += 1;
					**d = '2';
					*d += 1;
					**d = '0';
					*d += 1;
					*av_length += 1;
				} else {
					if ( normalize && (uch > 127) ) {
						if (*unnormalized_unicode_len == 0) {
							/* The previous output character must be ASCII
							 * and it should be normalized.
							 */
							*d -= 1;
							unnormalized_unicode[0] = **d;
							*unnormalized_unicode_len = 1;
							*av_length -= 1;
						}
						unnormalized_unicode[*unnormalized_unicode_len] = uch;
						*unnormalized_unicode_len += 1;
					} else {
						len = ldap_ucs4_to_utf8( uch, *d );
						tmp = **d;
						if ( RDN_NEEDSESCAPE( tmp ) || RDN_SPECIAL( tmp ) ) {
							**d = '\\';
							*d += 1;
							**d = tmp;
							*d += 1;
						} else if ( (*firstchar) && ( uch == '#' ) ) {
							**d = '\\';
							*d += 1;
							**d = tmp;
							*d += 1;
						} else {
							*d += len;
						}
						*av_length += 1;
					}
				}
				*firstchar = 0;
			} else if ( !(*firstchar) && !ASCII_SPACE( *(*d - 1) ) ) {
				**d = ' ';
				*d += 1;
				*av_length += 1;
			}
		#else
			/* Not sure what to do here either */
			if (uch > 127)
				return 0;

			if (make_uppercase) {
				uch = TOUPPER( uch );
			}

			if ( !normalize || !ASCII_WHITESPACE(uch) ) {
				if ( (*firstchar) && ASCII_SPACE(uch) ) {
					**d = '\\';
					*d += 1;
					**d = '2';
					*d += 1;
					**d = '0';
					*d += 1;
				} else {
					if ( RDN_NEEDSESCAPE( uch ) || RDN_SPECIAL( uch ) ) {
						**d = '\\';
						*d += 1;
					} else if ( (*firstchar) && ( uch == '#' ) ) {
						**d = '\\';
						*d += 1;
					}
					**d = uch;
					*d += 1;
				}
				*firstchar = 0;
				*av_length += 1;
			} else if ( !(*firstchar) && !ASCII_SPACE( *(*d - 1) ) ) {
				**d = ' ';
				*d += 1;
				*av_length += 1;
			}
		#endif
	}

	return 1;
}


/* The string beginning at *s should be an ASCII-hex encoding of a BER
 * encoded string of type string_type. If it is, write a UTF8 encoding
 * of the string, according to RFC 2253, to *d, advance *s to one byte after
 * the end of the BER encoded string, advance *d to one byte after the UTF8
 * encoded string, add to *encoded_length the length of the BER encoding, add
 * to *av_length the number of UTF8 characters written to *d, set *firstchar
 * to 0 if any characters are written to *d, and return 1. Otherwise, return
 * 0. If make_uppercase is 1, write all of the characters in uppercase. If
 * not, write the characters as they occur in the BER encoding. If
 * normalize is 1, remove all leading and trailing whitespace, and
 * compress all whitespace between words to a single space. If not, transfer
 * whitespace from the BER encoding to the UTF8 encoding unchanged.
 */
static int
ber_parse_string(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int string_type,
	unsigned int *encoded_length,
	int *firstchar,
	unsigned long *unnormalized_unicode,
	int *unnormalized_unicode_len
)
{
	int res;
	unsigned char ch, tag, encoding_method;
	int ber_string_type;
	unsigned long int length;
	unsigned int component_encoded_length;

	res = get_hexpair(s, &ch);
	if (res == 0)
		return 0;

	*encoded_length = 1;

	/* zero out bit 5 */
	tag = ch & 0xDF;

	if (tag == 12)
		ber_string_type = UTF8_STRING;
	else if (tag == 19)
		ber_string_type = PRINTABLE_STRING;
	else if (tag == 20)
		ber_string_type = TELETEX_STRING;
	else if (tag == 22)
		ber_string_type = IA5_STRING;
	else if (tag == 28)
		ber_string_type = UNIVERSAL_STRING;
	else if (tag == 30)
		ber_string_type = BMP_STRING;
	else {
		/* Unknown string type or not a string type */
		return 0;
	}

	/* Check that this is an acceptable string type */
	if ( ber_string_type == string_type ) {
		/* OK */
	} else if ( ( string_type == DIRECTORY_STRING ) &&
			( ( ber_string_type == PRINTABLE_STRING ) ||
			  ( ber_string_type == TELETEX_STRING ) ||
			  ( ber_string_type == BMP_STRING ) ||
			  ( ber_string_type == UNIVERSAL_STRING ) ||
			  ( ber_string_type == UTF8_STRING ) ) ) {
		/* OK */
	} else {
		/* Bad string type */
		return 0;
	}

	/* Bit 5 specifies the encoding method */
	encoding_method = ch & 0x20;

	if (encoding_method == 0) {
		/* Primitive, definite-length encoding */
		res = ber_parse_primitive_string(s, d, av_length, make_uppercase, normalize, ber_string_type, encoded_length, firstchar, unnormalized_unicode, unnormalized_unicode_len);
		if (res == 0)
			return 0;
	} else {
		/* Constructed encoding */

		res = get_hexpair(s, &ch);
		if (res == 0)
			return 0;

		if (ch == 128) {
			/* Constructed, indefinite-length */
			*encoded_length += 1;

			while (ch != 0) {
				res = ber_parse_string(s, d, av_length, make_uppercase, normalize, ber_string_type, &component_encoded_length, firstchar, unnormalized_unicode, unnormalized_unicode_len);
				if (res == 0)
					return 0;

				*encoded_length += component_encoded_length;

				/* Must end in "0000" */
				res = get_hexpair(s, &ch);
				if (res == 0)
					return 0;

				if (ch == 0) {
					res = get_hexpair(s, &ch);
					if ( (res == 0) || (ch != 0) )
						return 0;

					*encoded_length += 2;
				} else {
					*s -= 2;
				}
			}
		} else {
			/* Constructed, definite-length */
			*s -= 2;
			res = get_ber_length(s, encoded_length, &length);
			if (res == 0)
				return 0;

			while (length > 0) {
				res = ber_parse_string(s, d, av_length, make_uppercase, normalize, ber_string_type, &component_encoded_length, firstchar, unnormalized_unicode, unnormalized_unicode_len);
				if ( (res == 0) || (component_encoded_length > length) )
					return 0;

				length -= component_encoded_length;
				*encoded_length += component_encoded_length;
			}
		}
	}
}


/* The string beginning at *s should be a string of type string_type encoded
 * as described in RFC 2253. If it is, write a UTF8 encoding
 * of the string, according to RFC 2253, to *d, advance *s to one byte after
 * the end of the BER encoded string, advance *d to one byte after the UTF8
 * encoded string, set *av_length the number of UTF8 characters written to *d,
 * and return 1. Otherwise, return 0. If make_uppercase is 1, write all of the
 * characters in uppercase. If not, write the characters as they occur. If
 * normalize is 1, remove all leading and trailing whitespace, and
 * compress all whitespace between words to a single space. If not, transfer
 * whitespace from the BER encoding to the UTF8 encoding unchanged.
 * representation specifies whether the string is encoding as ASCII-hex BER,
 * within quotation marks, or as a plain string.
 */
static int
String_normalize(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int representation,
	int string_type,
	unsigned long *unnormalized_unicode
)
{
	int done = 0;
	int firstchar = 1;
	int first_dstchar = 0;
	char *lastchar;
	unsigned long int tmp;
	int res, len;
	int is_escaped;
	unsigned int encoded_length;
	int unnormalized_unicode_len = 0;

	*av_length = 0;
	lastchar = *d;

	switch ( representation ) {

	case INVALUE:
	case INQUOTEDVALUE:
		if ( representation == INQUOTEDVALUE ) {
			*s += 1;
			if ( !normalize )
				firstchar = 0;
		}

		while( !done ) {
			if ( **s == '\0' ) {
				if (unnormalized_unicode_len > 0) {
					res = normalize_unicode(unnormalized_unicode, unnormalized_unicode_len, d, av_length);
					if (res == 0)
						return 0;
				} else {
					*av_length -= (*d - lastchar);
					if ( !normalize && ( ASCII_SPACE(*(lastchar - 1)) ) ) {
						/* a space at the end of the string must be escaped */
						*(lastchar - 1) = '\\';
						*lastchar++ = '2';
						*lastchar++ = '0';
					}
					*d = lastchar;
				}
				
				if (representation == INQUOTEDVALUE) {
					/* Missing end quote */
					return 0;
				}
				done = 1;
			} else if ( representation == INVALUE && RDN_SEPARATOR( **s ) ) {
				if (unnormalized_unicode_len > 0) {
					res = normalize_unicode(unnormalized_unicode, unnormalized_unicode_len, d, av_length);
					if (res == 0)
						return 0;
				} else {
					*av_length -= (*d - lastchar);
					if ( !normalize && ( ASCII_SPACE(*(lastchar - 1)) ) ) {
						/* a space at the end of the string must be escaped */
						*(lastchar - 1) = '\\';
						*lastchar++ = '2';
						*lastchar++ = '0';
					}
					*d = lastchar;
				}
				done = 1;
			} else if ( representation == INQUOTEDVALUE  && **s == '"' ) {
				if (unnormalized_unicode_len > 0) {
					res = normalize_unicode(unnormalized_unicode, unnormalized_unicode_len, d, av_length);
					if (res == 0)
						return 0;
				} else {
					*av_length -= (*d - lastchar);
					if ( !normalize && ( ASCII_SPACE(*(lastchar - 1)) ) ) {
						/* a space at the end of the string must be escaped */
						*(lastchar - 1) = '\\';
						*lastchar++ = '2';
						*lastchar++ = '0';
					}
					*d = lastchar;
				}
				*s += 1;
				done = 1;
			} else {
				if ( !normalize && !ASCII_SPACE( **s ) )
					firstchar = 0;

				res = get_next_char( s, &tmp, &is_escaped );
				if (res == 0)
					return 0;

				if ( string_type == PRINTABLE_STRING ) {
					if ( !SLAP_PRINTABLE(tmp) )
						return 0;
				} else if (string_type == IA5_STRING ) {
					if ( !SLAP_IA5(tmp) )
						return 0;
				}

				if ( !ASCII_WHITESPACE( tmp ) )
					firstchar = 0;

				if ( (tmp < 128) && (unnormalized_unicode_len > 0) ) {
					res = normalize_unicode(unnormalized_unicode, unnormalized_unicode_len, d, av_length);
					if (res == 0)
						return 0;
					unnormalized_unicode_len = 0;
					lastchar = *d;
				}

				if ( RDN_NEEDSESCAPE( tmp ) ||
					    RDN_SPECIAL( tmp ) ) {
						if ( ( representation == INVALUE ) && !is_escaped ) {
							/* This character should have been escaped according to
							 * RFC 2253, but was not */
							return 0;
						}
						/* This must be an ASCII character */
						**d = '\\';
						*d += 1;
						**d = tmp;
						*d += 1;
						*av_length += 1;
						lastchar = *d;
						first_dstchar = 1;
				} else if ( tmp == 0 ) {
					strncpy(*d, "\\00", 3);
					*d += 3;
					*av_length += 1;
					lastchar = *d;
					first_dstchar = 1;
				} else if ( !first_dstchar && (tmp == '#') ) {
					**d = '\\';
					*d += 1;
					**d = tmp;
					*d += 1;
					*av_length += 1;
					lastchar = *d;
					first_dstchar = 1;
				} else if ( !normalize && !ASCII_SPACE( tmp ) ) {
					#ifdef UTF8DN
						if (make_uppercase) {
							tmp = uctoupper( tmp );
						}
						len = ldap_ucs4_to_utf8( tmp, *d );
						*d += len;
					#else
						if (make_uppercase) {
							**d = TOUPPER( tmp );
						} else {
							**d = tmp;
						}
						*d += 1;
					#endif
					*av_length += 1;
					lastchar = *d;
					first_dstchar = 1;
				} else if ( !ASCII_WHITESPACE( tmp ) ) {
					#ifdef UTF8DN
						if (make_uppercase) {
							tmp = uctoupper( tmp );
						}
						if ( normalize && (tmp > 127) ) {
							if ( (unnormalized_unicode_len == 0) && first_dstchar ) {
								/* The previous output character must be ASCII
								 * and it should be normalized.
								 */
								*d -= 1;
								unnormalized_unicode[unnormalized_unicode_len++] = **d;
								*av_length -= 1;
							}
							unnormalized_unicode[unnormalized_unicode_len++] = tmp;
						} else {
							len = ldap_ucs4_to_utf8( tmp, *d );
							*d += len;
							*av_length += 1;
						}
					#else
						if (make_uppercase) {
							**d = TOUPPER( tmp );
						} else {
							**d = tmp;
						}
						*d += 1;
						*av_length += 1;
					#endif
					lastchar = *d;
					first_dstchar = 1;
				} else if ( !firstchar && ( !normalize || !ASCII_SPACE( *(*d - 1) ) ) ) {
					if ( !first_dstchar ) {
						**d = '\\';
						*d += 1;
						**d = '2';
						*d += 1;
						**d = '0';
						*d += 1;
						first_dstchar = 1;
					} else {
						**d = ' ';
						*d +=1;
					}
					*av_length += 1;
					if ( !normalize && ( is_escaped || representation == INQUOTEDVALUE ) )
						lastchar = *d;
				}
			}
		}
		break;

	case INBERENCODEDVALUE:
		/* Skip over the '#' */
		*s += 1;
		
		encoded_length = 0;

		res = ber_parse_string(s, d, av_length, make_uppercase, normalize, string_type, &encoded_length, &firstchar, unnormalized_unicode, &unnormalized_unicode_len);
		if (res == 0)
			return 0;

		if (unnormalized_unicode_len > 0) {
			res = normalize_unicode(unnormalized_unicode, unnormalized_unicode_len, d, av_length);
			if (res == 0)
				return 0;
		} else if ( ASCII_SPACE( *(*d - 1) ) ) {
			if ( normalize ) {
				*d -= 1;
				*av_length -= 1;
			} else {
				*(*d - 1) = '\\';
				**d = '2';
				*d += 1;
				**d = '0';
				*d += 1;
			}
		}

		break;

	default:
		/* Something must be wrong, representation shouldn't
		 * have any other value.
		 */
		return 0;
		break;
	}

	return 1;
}


/* Normalize a directory string */
static int
DirectoryString_normalize(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int representation,
	unsigned long *unnormalized_unicode
)
{
	return String_normalize(s, d, av_length, make_uppercase, normalize, representation, DIRECTORY_STRING, unnormalized_unicode);
}


/* Normalize a printable string */
static int
PrintableString_normalize(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int representation,
	unsigned long *unnormalized_unicode
)
{
	return String_normalize(s, d, av_length, make_uppercase, normalize, representation, PRINTABLE_STRING, unnormalized_unicode);
}


/* Normalize an IA5 string */
static int
IA5String_normalize(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int representation,
	unsigned long *unnormalized_unicode
)
{
	return String_normalize(s, d, av_length, make_uppercase, normalize, representation, IA5_STRING, unnormalized_unicode);
}



/* The string beginning at *s represents an ASCII-hex encoding of a BER
 * encoded bitstring, where the encoding is primitive, definite-length.
 * If the string is properly encoded, place the string in *d, advance *s
 * and *d, add the number of bits in the string to *av_length, add
 * the length of the BER encoding to *encoded_length, and return 1. Otherwise,
 * return 0.
 */
static int
ber_parse_primitive_bitstring(
	char **s,
	char **d,
	int *av_length,
	unsigned int *encoded_length
)
{
	int res;
	unsigned char ch;
	unsigned long int length;
	unsigned char unused;
	int bit_pos;

	static unsigned char mask[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };

	res = get_ber_length(s, encoded_length, &length);
	if (res == 0)
		return 0;

	if (length < 1) {
		/* There must be a least one byte containing the number of
		 * unused bits.
		 */
		return 0;
	}

	/* get number of unused bits */
	res = get_hexpair(s, &unused);
	if ( ( res == 0 ) || ( unused > 7 ) )
		return 0;

	if ( (length == 0) && (unused != 0) ) {
		/* If there are no content bits, there can be no unused bits */
		return 0;
	}

	*encoded_length += 1;
	length--;

	while( length > 1 ) {
		res = get_hexpair(s, &ch);
		if (res == 0)
			return 0;

		*encoded_length += 1;
		length--;

		for(bit_pos = 7; bit_pos >= 0; bit_pos--) {
			if ( (ch & mask[bit_pos]) == 0 ) {
				**d = '0';
			} else {
				**d = '1';
			}
			*d += 1;
			*av_length += 1;
		}
	}

	if ( length == 1) {
		res = get_hexpair(s, &ch);
		if (res == 0)
			return 0;

		*encoded_length += 1;

		for(bit_pos = 7; bit_pos >= unused; bit_pos--) {
			if ( (ch & mask[bit_pos]) == 0 ) {
				**d = '0';
			} else {
				**d = '1';
			}
			*d += 1;
			*av_length += 1;
		}
	}

	return 1;
}


/* The string beginning at *s represents an ASCII-hex encoding of a BER
 * encoded bitstring. If the string is properly encoded, place the string
 * in *d, advance *s and *d, add the number of bits in the string to
 * *av_length, add the length of the BER encoding to *encoded_length, and
 * return 1. Otherwise, return 0.
 */
static int
ber_parse_bitstring(
	char **s,
	char **d,
	int *av_length,
	unsigned int *encoded_length
)
{
	int res;
	unsigned char ch;
	unsigned long int length;
	unsigned int component_encoded_length;

	res = get_hexpair(s, &ch);
	if (res == 0)
		return 0;

	*encoded_length = 1;

	if (ch == '\x03') {
		/* Primitive, definite-length encoding */
		res = ber_parse_primitive_bitstring(s, d, av_length, encoded_length);
		if (res == 0)
			return 0;
	} else if ( ch == '\x23' ) {
		/* Constructed encoding */

		res = get_hexpair(s, &ch);
		if (res == 0)
			return 0;

		if ( ch == 128 ) {
			/* Constructed, indefinite-length */
			*encoded_length += 1;

			while ( ch != 0 ) {
				res = ber_parse_bitstring(s, d, av_length, &component_encoded_length);
				if (res == 0)
					return 0;

				*encoded_length += component_encoded_length;

				/* Must end in "0000" */
				res = get_hexpair(s, &ch);
				if (res == 0)
					return 0;

				if (ch == 0) {
					res = get_hexpair(s, &ch);
					if ( (res == 0) || (ch != 0) )
						return 0;

					*encoded_length += 2;
				} else {
					*s -= 2;
				}
			}
		} else {
			/* Constructed, definite-length */
			*s -= 2;
			res = get_ber_length(s, encoded_length, &length);
			if (res == 0)
				return 0;

			while (length > 0) {
				res = ber_parse_bitstring(s, d, av_length, &component_encoded_length);
				if ( (res == 0) || (component_encoded_length > length) )
					return 0;

				length -= component_encoded_length;
				*encoded_length += component_encoded_length;
			}
		}
	} else {
		/* Not a valid bitstring */
		return 0;
	}
}


/* *s is a pointer to a string of zero or more 0's and 1's. Return a binary encoding of the next 8 bits of *s and advance
 * *s to the end of the parsed sub-string. If the string is less than 8-bytes long, pad the binary encoding with 0's.
 */
static unsigned char
getNext8bits(
	char **s
)
{
	static unsigned char mask[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
	int pos;
	unsigned char output;

	output = 0;
	pos = 8;

	while ( ( pos > 0 ) && ( ( **s == '0' ) || ( **s == '1' ) ) ) {
		pos--;

		if ( **s == '1' ) {
			output = output | mask[pos];
		}

		*s += 1;
	}

	return output;
}


/* The string beginning at *s represents a bitstring encoded according to
 * RFC 2253. If the string is properly encoded, place the string
 * in *d, advance *s and *d, place the length of the string representation of
 * the bitstring in *av_length, and return 1. Otherwise, return 0.
 * representation specifies whether the string is encoding as ASCII-hex BER,
 * within quotation marks, or as a plain string.
 *
 *   According to RFC 2252, the string representation for
 *   bit strings is described by the following BNF:
 *
 *    bitstring = "'" *binary-digit "'B"
 *
 *    binary-digit = "0" / "1"
 */
static int
bitString_normalize(
	char **s,
	char **d,
	int *av_length,
	int make_uppercase,
	int normalize,
	int representation,
	unsigned long *unnormalized_unicode /* not used in this function */
)
{
	int res;
	int is_escaped;
	unsigned char ch;
	unsigned int encoded_length;

	int DER_length;
	unsigned char unused_bits;
	unsigned char byte1, byte2, temp;
	char *src, *start_of_output;
	
	*av_length = 0;
	start_of_output = *d;

	switch ( representation ) {

	case INVALUE:
	case INQUOTEDVALUE:
		if ( representation == INQUOTEDVALUE ) {
			/* Skip over quotation mark */
			*s += 1;
		}

		/* First non-space character must be a "'" */
		res = get_next_byte(s, &ch, &is_escaped);
		if ( (res == 0) || (ch != '\'') )
			return 0;

		**d = '\'';
		*d += 1;
		*av_length += 1;

		/* Next should be a sequence of 0's and 1's followed by a "'" */
		res = get_next_byte(s, &ch, &is_escaped);
		if (res == 0)
			return 0;
		
		while ( ( ch == '0' ) || ( ch == '1' ) ) {
			**d = ch;
			*d += 1;
			*av_length += 1;

			res = get_next_byte(s, &ch, &is_escaped);
			if (res == 0)
				return 0;
		}

		if ( ch != '\'' )
			return 0;

		**d = '\'';
		*d += 1;
		*av_length += 1;

		/* The last character should be a 'B' */
		res = get_next_byte(s, &ch, &is_escaped);
		if ( (res == 0) || ( TOUPPER(ch) != 'B' ) )
			return 0;

		**d = 'B';
		*d += 1;
		*av_length += 1;

		if ( representation == INQUOTEDVALUE ) {
			if ( **s != '\"' )
				return 0;
			else
				*s += 1;
		}
		break;

	case INBERENCODEDVALUE:
		/* Skip over the '#' */
		*s += 1;
		
		**d = '\'';
		*d += 1;
		*av_length +=1;

		encoded_length = 0;

		ber_parse_bitstring(s, d, av_length, &encoded_length);
		if (res == 0)
			return 0;

		**d = '\'';
		*d += 1;
		**d = 'B';
		*d += 1;
		*av_length += 2;

		break;

	default:
		/* Something must be wrong, representation shouldn't
		 * have any other value.
		 */
		return 0;
		break;
	}

	if ( !normalize && (representation != INBERENCODEDVALUE) )
		return 1;

	*av_length -= 3;

	unused_bits = *av_length % 8;
	if ( unused_bits == 0 ) {
		DER_length = (*av_length / 8) + 1;
	} else {
		DER_length = (*av_length / 8) + 2;
		unused_bits = 8 - unused_bits;
	}

	*d = start_of_output;
	src = start_of_output + 1;

	if (DER_length > 1)
		byte1 = getNext8bits( &src );
	if (DER_length > 2)
		byte2 = getNext8bits( &src );

	**d = '#';
	*d += 1;
	**d = '0';
	*d += 1;
	**d = '3';
	*d += 1;

	/* Insert length into string */
	if (DER_length < 128) {
		temp = DER_length;
		write_hex_pair(d, temp);
		*av_length = 7 + 2 * DER_length;
	} else if (DER_length < 256) {
		**d = '8';
		*d += 1;
		**d = '1';
		*d += 1;
		temp = DER_length;
		write_hex_pair(d, temp);
		*av_length = 9 + 2 * DER_length;
	} else if (DER_length < 65536) {
		**d = '8';
		*d += 1;
		**d = '2';
		*d += 1;
		temp = (DER_length >> 8) & 0xFF;
		write_hex_pair(d, temp);
		temp = DER_length & 0xFF;
		write_hex_pair(d, temp);
		*av_length = 11 + 2 * DER_length;
	} else if (DER_length < 16777216) {
		**d = '8';
		*d += 1;
		**d = '3';
		*d += 1;
		temp = (DER_length >> 16) & 0xFF;
		write_hex_pair(d, temp);
		temp = (DER_length >> 8) & 0xFF;
		write_hex_pair(d, temp);
		temp = DER_length & 0xFF;
		write_hex_pair(d, temp);
		*av_length = 13 + 2 * DER_length;
	} else {
		/* NOTE: I am assuming that the length will always fit in 4 octets */
		**d = '8';
		*d += 1;
		**d = '4';
		*d += 1;
		temp = (DER_length >> 24) & 0xFF;
		write_hex_pair(d, temp);
		temp = (DER_length >> 16) & 0xFF;
		write_hex_pair(d, temp);
		temp = (DER_length >> 8) & 0xFF;
		write_hex_pair(d, temp);
		temp = DER_length & 0xFF;
		write_hex_pair(d, temp);
		*av_length = 15 + 2 * DER_length;
	}

	/* Insert number of unused bits into string */
	write_hex_pair(d, unused_bits);

	if (DER_length > 1)
		write_hex_pair(d, byte1);
	if (DER_length > 2)
		write_hex_pair(d, byte2);

	if (DER_length > 3) {
		DER_length -= 3;

		while (DER_length > 0) {
			byte1 = getNext8bits( &src );
			write_hex_pair(d, byte1);
			DER_length--;
		}
	}

	return 1;
}


/*
 * match_oid - determine if the OID represented by the string beginning
 * at *src and of length len is a known attribute type. If so, copy the
 * string representation to *dst and return a pointer to the normalization
 * function for the attribute value. If the attribute type places an
 * upper bound on the length of the attribute value, make *ub that
 * upper bound, otherwise set *ub to -1.
 * If the OID is unknown, copy the OID to *dst and return NULL.
 */
static av_normalize_type
match_oid(char **src, char **dst, int *ub, int len, int make_uppercase)
{
	int i;
	int dst_len = 0;
	av_normalize_type normalize_function = NULL;

	*ub = -1;

	switch( len ) {
		case 7:
			if (strncmp(*src, "2.5.4.6", len) == 0) {
				/* Country */
				**dst = 'c';
				dst_len = 1;
				*ub = 2;
				normalize_function = PrintableString_normalize;
			} else if (strncmp(*src, "2.5.4.3", len) == 0) {
				/* Common Name */
				strncpy(*dst, "cn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.8", len) == 0) {
				/* State or Province Name */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.7", len) == 0) {
				/* locality */
				**dst = 'l';
				dst_len = 1;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.5", len) == 0) {
				/* serial number */
				strncpy(*dst, "snu", 3);
				dst_len = 3;
				*ub = 64;
				normalize_function = PrintableString_normalize;
			} else if (strncmp(*src, "2.5.4.4", len) == 0) {
				/* surname */
				strncpy(*dst, "sn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.9", len) == 0) {
				/* street address */
				strncpy(*dst, "street", 6);
				dst_len = 6;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 8:
			if (strncmp(*src, "2.5.4.10", len) == 0) {
				/* Organization */
				**dst = 'o';
				dst_len = 1;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.11", len) == 0) {
				/* Organizational Unit */
				strncpy(*dst, "ou", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.12", len) == 0) {
				/* title */
				strncpy(*dst, "title", 5);
				dst_len = 5;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.42", len) == 0) {
				/* givenName */
				strncpy(*dst, "givenName", 9);
				dst_len = 9;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.43", len) == 0) {
				/* initials */
				strncpy(*dst, "initials", 8);
				dst_len = 8;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.44", len) == 0) {
				/* generationQualifier */
				strncpy(*dst, "generationQualifier", 19);
				dst_len = 19;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncmp(*src, "2.5.4.45", len) == 0) {
				/* uniqueIdentifier */
				strncpy(*dst, "uniqueIdentifier", 16);
				dst_len = 16;
				*ub = -1;
				normalize_function = bitString_normalize;
			} else if (strncmp(*src, "2.5.4.46", len) == 0) {
				/* dnQualifier */
				strncpy(*dst, "dnQualifier", 11);
				dst_len = 11;
				*ub = -1;
				normalize_function = PrintableString_normalize;
			} else if (strncmp(*src, "2.5.4.65", len) == 0) {
				/* Pseudonym */
				strncpy(*dst, "Pseudonym", 9);
				dst_len = 9;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 20:
			if (strncmp(*src, "1.2.840.113549.1.9.1", len) == 0) {
				/* email */
				**dst = 'e';
				dst_len = 1;
				*ub = 128;
				normalize_function = IA5String_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 17:
			if (strncmp(*src, "0.2.262.1.10.7.20", len) == 0) {
				/* name distinguisher */
				strncpy(*dst, "nameDistinguisher", 17);
				dst_len = 17;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 25:
			if (strncmp(*src, "0.9.2342.19200300.100.1.1", len) == 0) {
				/* userID */
				strncpy(*dst, "uid", 3);
				dst_len = 3;
				*ub = 256;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 26:
			if (strncmp(*src, "0.9.2342.19200300.100.1.25", len) == 0) {
				/* domainComponent */
				strncpy(*dst, "dc", 2);
				dst_len = 2;
				*ub = -1;
				normalize_function = IA5String_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		default:
			/* Unknown attributeType */
			strncpy(*dst, *src, len);
			dst_len = len;
				*ub = -1;
			normalize_function = NULL;
			break;
	}

	if (make_uppercase) {
		for(i=0; i < dst_len; i++) {
			**dst = TOUPPER( **dst );
			*dst += 1;
		}
	} else {
		*dst += dst_len;
	}
	*src += len;
	return normalize_function;
}


/*
 * match_key - determine if the attribute type represented by the string
 * beginning at *src and of length len is a known attribute type. If so,
 * copy the string representation to *dst and return a pointer to the
 * normalization function for the attribute value. If the attribute type
 * places an upper bound on the length of the attribute value, make *ub that
 * upper bound, otherwise set *ub to -1.
 * If the attribute type is unknown, copy the string representation of the
 * attribute type to *dst and return NULL.
 */
static av_normalize_type
match_key(char **src, char **dst, int *ub, int len, int make_uppercase)
{
	int i;
	int dst_len = 0;
	av_normalize_type normalize_function = NULL;

	*ub = -1;

	switch( len ) {
		case 1:
			if (strncasecmp(*src, "C", len) == 0) {
				/* country */
				**dst = 'c';
				dst_len = 1;
				*ub = 2;
				normalize_function = PrintableString_normalize;
			} else if (strncasecmp(*src, "O", len) == 0) {
				/* organization */
				**dst = 'o';
				dst_len = 1;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "T", len) == 0) {
				/* title */
				strncpy(*dst, "title", 5);
				dst_len = 5;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "S", len) == 0) {
				/* state or province */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "L", len) == 0) {
				/* locality */
				**dst = 'l';
				dst_len = 1;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "E", len) == 0) {
				/* e-mail */
				**dst = 'e';
				dst_len = 1;
				*ub = 255;
				normalize_function = IA5String_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 2:
			if (strncasecmp(*src, "CN", len) == 0) {
				/* common name */
				strncpy(*dst, "cn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "OU", len) == 0) {
				/* organizational unit */
				strncpy(*dst, "ou", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "DC", len) == 0) {
				/* domainComponent */
				strncpy(*dst, "dc", 2);
				dst_len = 2;
				*ub = -1;
				normalize_function = IA5String_normalize;
			} else if (strncasecmp(*src, "SN", len) == 0) {
				/* surname */
				strncpy(*dst, "sn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "ST", len) == 0) {
				/* state or province */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 3:
			if (strncasecmp(*src, "SNU", len) == 0) {
				/* serial number */
				strncpy(*dst, "snu", 3);
				dst_len = 3;
				*ub = 64;
				normalize_function = PrintableString_normalize;
			} else if (strncasecmp(*src, "UID", len) == 0) {
				/* userID */
				strncpy(*dst, "uid", 3);
				dst_len = 3;
				*ub = 256;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 5:
			if (strncasecmp(*src, "TITLE", len) == 0) {
				/* title */
				strncpy(*dst, "title", 5);
				dst_len = 5;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "STATE", len) == 0) {
				/* state or province */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 6:
			if (strncasecmp(*src, "USERID", len) == 0) {
				/* userID */
				strncpy(*dst, "uid", 3);
				dst_len = 3;
				*ub = 256;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "STREET", len) == 0) {
				/* street address */
				strncpy(*dst, "street", 6);
				dst_len = 6;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 7:
			if (strncasecmp(*src, "SURNAME", len) == 0) {
				/* surname */
				strncpy(*dst, "sn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 8:
			if (strncasecmp(*src, "INITIALS", len) == 0) {
				/* initials */
				strncpy(*dst, "initials", 8);
				dst_len = 8;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "PROVINCE", len) == 0) {
				/* state or province */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 9:
			if (strncasecmp(*src, "GIVENNAME", len) == 0) {
				/* givenName */
				strncpy(*dst, "givenName", 9);
				dst_len = 9;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "PSEUDONYM", len) == 0) {
				/* Pseudonym */
				strncpy(*dst, "Pseudonym", 9);
				dst_len = 9;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 10:
			if (strncasecmp(*src, "COMMONNAME", len) == 0) {
				/* common name */
				strncpy(*dst, "cn", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 11:
			if (strncasecmp(*src, "DNQUALIFIER", len) == 0) {
				/* Distinguished Name Quailifier */
				strncpy(*dst, "dnQualifier", 11);
				dst_len = 11;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "COUNTRYNAME", len) == 0) {
				/* country */
				**dst = 'c';
				dst_len = 1;
				*ub = 2;
				normalize_function = PrintableString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			
		case 12:
			if (strncasecmp(*src, "SERIALNUMBER", len) == 0) {
				/* serial number */
				strncpy(*dst, "snu", 3);
				dst_len = 3;
				*ub = 64;
				normalize_function = PrintableString_normalize;
			} else if (strncasecmp(*src, "LOCALITYNAME", len) == 0) {
				/* locality */
				**dst = 'l';
				dst_len = 1;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "EMAILADDRESS", len) == 0) {
				/* e-mail */
				**dst = 'e';
				dst_len = 1;
				*ub = 255;
				normalize_function = IA5String_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			
		case 13:
			if (strncasecmp(*src, "STREETADDRESS", len) == 0) {
				/* street address */
				strncpy(*dst, "street", 6);
				dst_len = 6;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			
		case 15:
			if (strncasecmp(*src, "DOMAINCOMPONENT", len) == 0) {
				/* domainComponent */
				strncpy(*dst, "dc", 2);
				dst_len = 2;
				*ub = -1;
				normalize_function = IA5String_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 16:
			if (strncasecmp(*src, "UNIQUEIDENTIFIER", len) == 0) {
				/* uniqueIdentifier */
				strncpy(*dst, "uniqueIdentifier", 16);
				dst_len = 16;
				*ub = -1;
				normalize_function = bitString_normalize;
			} else if (strncasecmp(*src, "ORGANIZATIONNAME", len) == 0) {
				/* organization */
				**dst = 'o';
				dst_len = 1;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			
		case 17:
			if (strncasecmp(*src, "NAMEDISTINGUISHER", len) == 0) {
				/* name distinguisher */
				strncpy(*dst, "nameDistinguisher", 17);
				dst_len = 17;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;

		case 19:
			if (strncasecmp(*src, "GENERATIONQUALIFIER", len) == 0) {
				/* Distinguished Name Quailifier */
				strncpy(*dst, "generationQualifier", 19);
				dst_len = 19;
				*ub = -1;
				normalize_function = DirectoryString_normalize;
			} else if (strncasecmp(*src, "STATEORPROVINCENAME", len) == 0) {
				/* state or province */
				strncpy(*dst, "st", 2);
				dst_len = 2;
				*ub = 128;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			

		case 22:
			if (strncasecmp(*src, "ORGANIZATIONALUNITNAME", len) == 0) {
				/* organizational unit */
				strncpy(*dst, "ou", 2);
				dst_len = 2;
				*ub = 64;
				normalize_function = DirectoryString_normalize;
			} else {
				/* Unknown attributeType */
				strncpy(*dst, *src, len);
				dst_len = len;
				*ub = -1;
				normalize_function = NULL;
			}
			break;
			
		default:
			/* Unknown attributeType */
			strncpy(*dst, *src, len);
			dst_len = len;
			*ub = -1;
			normalize_function = NULL;
			break;
	}

	if (make_uppercase) {
		for(i=0; i < dst_len; i++) {
			**dst = TOUPPER( **dst );
			*dst += 1;
		}
	} else {
		*dst += dst_len;
	}
	*src += len;
	return normalize_function;
}


static int
get_validated_av_in_dn(char **s, char **d, int make_uppercase, int normalize, unsigned long *unnormalized_unicode) {
	char *i;
	int status, av_ub, len, av_length;
	av_normalize_type av_normalize;

	/* First skip over any leading spaces */
	while ( ASCII_SPACE( **s ) )
		*s += 1;

	/* Next get the attribute type */
	if ( OID_LEADCHAR(**s) ) {
		i = *s;
		while ( *i != '\0' && OID_CHAR(*i) )
			i++;
		if ( *i == '\0' )
			return 0;

		len = i - *s;
		av_normalize = match_oid(s, d, &av_ub, len, make_uppercase);
	} else if ( DESC_LEADCHAR(**s) ) {
		if ( TOUPPER ( **s ) == 'O' &&
		     TOUPPER ( *(*s+1) ) == 'I' &&
		     TOUPPER ( *(*s+2) ) == 'D' &&
		     *(*s+3) == '.' ) {
			*s += 4;
			if ( !OID_LEADCHAR(**s) )
				return 0;

			i = *s;
			while ( *i != '\0' && OID_CHAR(*i) )
				i++;
			if ( *i == '\0' )
				return 0;

			len = i - *s;
			av_normalize = match_oid(s, d, &av_ub, len, make_uppercase);
		} else {
			i = *s;
			while ( *i != '\0' && DESC_CHAR(*i) )
				i++;
			if ( *i == '\0' )
				return 0;

			len = i - *s;
			av_normalize = match_key(s, d, &av_ub, len, make_uppercase);
		}
	} else {
		return 0;
	}


	/* Next should be the equal sign */

	while ( (**s != '=') && (**s != '\0') ) {
		if ( !ASCII_SPACE(**s) )
			return 0;

		*s += 1;
	}

	if (**s != '=')
		return 0;

	*s += 1;
	**d = '=';
	*d += 1;

	while ( ASCII_SPACE(**s) )
		*s += 1;

	/* The final part is the attribute value */
	if ( **s == '"' ) {
		if (av_normalize == NULL) {
			av_ub = -1;
			av_normalize = DirectoryString_normalize;
		}
		status = (*av_normalize)(s, d, &av_length, make_uppercase, normalize, INQUOTEDVALUE, unnormalized_unicode);
		if (status == 0)
			return 0;
		if ( ( av_ub != -1 ) && ( av_length > av_ub ) ) {
			/* attribute value too long */
			return 0;
		}
	} else if ( **s == '#' ) {
		if (av_normalize == NULL) {
			/* Unknown attribute type. Since we don't know its string representation,
			 * just leave it as a BER encoded value.
			 */
			**d = **s;
			*s += 1; *d += 1;
			av_length = 1;
			while ( ASCII_XDIGIT(**s) ) {
				**d = TOUPPER(**s);
				*s += 1; *d += 1;
				av_length++;
			}

			/* The length must be odd, since there must be an even number of
			 * hexadecimal charaters after the '#'.
			 */
			if ( (av_length & 1) == 0)
				return 0;
		} else {
			status = (*av_normalize)(s, d, &av_length, make_uppercase, normalize, INBERENCODEDVALUE, unnormalized_unicode);
			if (status == 0)
				return 0;
			if ( ( av_ub != -1 ) && ( av_length > av_ub ) ) {
				/* attribute value too long */
				return 0;
			}
		}
	} else {
		if (av_normalize == NULL) {
			av_ub = -1;
			av_normalize = DirectoryString_normalize;
		}
		status = (*av_normalize)(s, d, &av_length, make_uppercase, normalize, INVALUE, unnormalized_unicode);
		if (status == 0)
			return 0;
		if ( ( av_ub != -1 ) && ( av_length > av_ub ) ) {
			/* attribute value too long */
			return 0;
		}
	}

	return 1;
}

/* The string *s is a distinguished name encoded according to RFC 2253.
 * If the first RDN in *s is properly encoded, place in *d a normalized
 * version of the first RDN in *s, advance *d to the end of the normalized
 * RDN, advance *s to the end of the input string, and return 1.
 * If *s is not properly encoded, return 0.
 */
static int
get_validated_rdn_in_dn(char **s, char **d, int make_uppercase, int normalize, unsigned long *unnormalized_unicode) {
	char *av_pair[1001];	/* Assume there are less than 1000 attribute value pairs per RDN */
	int av_pair_len[1001];
	char *temp, *work_space;
	int i, j, num_av_pairs, status, state, len;

	/* An RDN is a set of 1 or more attribute/value pairs. Get the first AV pair */
	av_pair[0] = *d;
	status = get_validated_av_in_dn(s, d, make_uppercase, normalize, unnormalized_unicode);
	if (status == 0)
		return 0;

	num_av_pairs = 1;

	state = B4SEPARATOR;

	while ( ASCII_SPACE( **s ) ) {
		*s += 1;
	}

	if ( **s != '+') {
		/* This RDN contains only 1 attribute value pair */
		return 1;
	}

	/* Since RDNs with more than one attribute value pair are
	 * rare, the above code was optimized for the case of an
	 * RDN with only one AV pair. This RDN, however, contains
	 * two or more AV pairs and they must be sorted to ensure
	 * consistency when performing matches. The ordering does
	 * not matter as long as it is consistent.
	 */

	/* Create temporary space to hold the AV pairs before sorting */
	**d = '\0';

	/* Compute the length of the first AV pair */
	av_pair_len[0] = *d - av_pair[0];

	work_space = (char *)ch_malloc(4 * strlen( *s ) + av_pair_len[0] + 1000);

	/* Move *d back so that the whole RDN can be written in the proper order */
	*d = av_pair[0];

	av_pair[0] = work_space;
	bcopy(*d, av_pair[0], av_pair_len[0]+1);

	av_pair[1] = av_pair[0] + av_pair_len[0] + 1;
	while ( (num_av_pairs < 1000) && (**s != ',') && (**s != ';') && (**s != '\0') ) {
		if ( **s != '+' ) {
			ch_free(work_space);
			return 0;
		}
		*s += 1;
			
		temp = av_pair[num_av_pairs];
		status = get_validated_av_in_dn(s, &temp, make_uppercase, normalize, unnormalized_unicode);
		if (status == 0) {
			ch_free(work_space);
			return 0;
		}
		av_pair_len[num_av_pairs] = temp - av_pair[num_av_pairs];

		*temp++ = '\0';
		num_av_pairs++;
		av_pair[num_av_pairs] = temp;

		while ( ASCII_SPACE(**s) )
			*s += 1;
	}

	if (num_av_pairs == 1000) {
		ch_free(work_space);
		return 0;
	}

	if ( normalize ) {
		/* Sort the AV pairs. Since the number of AV pairs in an RDN should always
		 * be very small, bubblesort is used.
		 */
		for(i = 0; i < num_av_pairs; i++) {
			for(j = 1; j < num_av_pairs; j++) {
				if (strcasecmp(av_pair[j-1], av_pair[j]) > 0) {
					temp = av_pair[j-1];
					av_pair[j-1] = av_pair[j];
					av_pair[j] = temp;

					len = av_pair_len[j-1];
					av_pair_len[j-1] = av_pair_len[j];
					av_pair_len[j] = len;
				}
			}
		}
	}

	/* place the AV pairs in *d, separated by commas */
	for(i=0; i < num_av_pairs; i++) {
		bcopy(av_pair[i], *d, av_pair_len[i]);
		*d += av_pair_len[i];
		**d = '+';
		*d += 1;
	}
	*d -= 1;

	ch_free(work_space);

	return 1;
}

/* The string dn is a distinguished name encoded according to RFC 2253.
 * If dn is properly encoded, return a normalized version of the string.
 * If not, return NULL. If make_uppercase is 0, do not change the case of
 * characters in attribute values, otherwise make all characters in attribute
 * values uppercase. If normalize is 0, do not compress whitespace
 * within attribute values, otherwise remove any leading and trailing
 * whitespace characters from attribute values and replace any strings of
 * whitespace characters between "words" with a single space character.
 */
char *
get_validated_dn( char *dn, int make_uppercase, int normalize)
{
	char *ret_val, *s, *d;
	unsigned long *unnormalized_unicode;
	int dn_len, status, state;

	state = B4LEADTYPE;

	dn_len = strlen(dn);
	d = ret_val = (char *)ch_malloc(4 * dn_len + 1);
	s = dn;

	/* Create temporary workspace to hold unicode characters before
	 * they have been normalized.
	 */
	if ( normalize )
		unnormalized_unicode = (unsigned long *)ch_malloc(dn_len * sizeof(unsigned long));
	else
		unnormalized_unicode = NULL;

	/* A DN consists of a sequence of 0 or more RDNs */

	while ( ret_val != NULL && *s != '\0' ) {
		if ( ASCII_SPACE( *s ) ) {
			s++;
		} else if ( (state == B4SEPARATOR) && ( (*s == ',') || (*s == ';') ) ) {
			*d++ = ',';
			s++;
			state = B4VALUE;
		} else {
			status = get_validated_rdn_in_dn(&s, &d, make_uppercase, normalize, unnormalized_unicode);
			if (status == 0) {
				/* not a valid RDN */
				ch_free(ret_val);
				ret_val = NULL;
			}
			state = B4SEPARATOR;
		}
	}

	if (state == B4VALUE) {
		/* not a valid DN */
		ch_free(ret_val);
		ret_val = NULL;
	}

	*d = '\0';
	return ret_val;
}

/*
 * dn_validate - validate and compress dn.  the dn is
 * compressed in place are returned if valid.
 */

char *
dn_validate( char *dn_in )
{
	char *dn_out;
	int len;
 
	len = strlen(dn_in);
 
	if (len != 0) {
		dn_out = get_validated_dn(dn_in, 0, 0);
		if (dn_out == NULL) {
			return NULL;
		} else if (strlen(dn_out) <= len) {
			strcpy(dn_in, dn_out);
			ch_free(dn_out);
		} else {
			ch_free(dn_out);
			return NULL;
		}
	}
	return( dn_in );
}

/*
 * dn_normalize - put dn into a canonical form suitable for storing
 * in a hash database.	this involves normalizing the case as well as
 * the format.	the dn is normalized in place as well as returned if valid.
 */

char *
dn_normalize( char *dn )
{
	char *dn_out;
	int len;
 
	len = strlen(dn);
 
	if (len != 0) {
		dn_out = get_validated_dn(dn, 1, 1);
		if (dn_out == NULL) {
			return NULL;
		} else if (strlen(dn_out) <= len) {
			strcpy(dn, dn_out);
			ch_free(dn_out);
		} else {
			ch_free(dn_out);
			return NULL;
		}
	}
	return( dn );
}

/*
 * dn_parent - return a copy of the dn of dn's parent
 */

char *
dn_parent(
    Backend	*be,
    const char	*dn
)
{
	const char	*s;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn != '\0' && ASCII_SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
		return NULL;
	}

	/*
	 * assume it is an X.500-style name, which looks like
	 * foo=bar,sha=baz,...
	 */

	inquote = 0;
	for ( s = dn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *s ) ) {
				return ch_strdup( &s[1] );
			}
		}
	}

	return ch_strdup( "" );
}

char * dn_rdn( 
    Backend	*be,
    const char	*dn_in )
{
	char	*dn, *s;
	int	inquote;

	if( dn_in == NULL ) {
		return NULL;
	}

	while(*dn_in && ASCII_SPACE(*dn_in)) {
		dn_in++;
	}

	if( *dn_in == '\0' ) {
		return( NULL );
	}

	if ( be != NULL && be_issuffix( be, dn_in ) ) {
		return( NULL );
	}

	dn = ch_strdup( dn_in );

	inquote = 0;

	for ( s = dn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *s ) ) {
				*s = '\0';
				return( dn );
			}
		}
	}

	return( dn );
}


/*
 * return a charray of all subtrees to which the DN resides in
 */
char **dn_subtree(
	Backend	*be,
    const char	*dn )
{
	char *child, *parent;
	char **subtree = NULL;
	
	child = ch_strdup( dn );

	do {
		charray_add( &subtree, child );

		parent = dn_parent( be, child );

		free( child );

		child = parent;
	} while ( child != NULL );

	return subtree;
}


/*
 * dn_issuffix - tells whether suffix is a suffix of dn.  both dn
 * and suffix must be normalized.
 */

int
dn_issuffix(
    const char	*dn,
    const char	*suffix
)
{
	int	dnlen, suffixlen;

	if ( dn == NULL ) {
		return( 0 );
	}

	suffixlen = strlen( suffix );
	dnlen = strlen( dn );

	if ( suffixlen > dnlen ) {
		return( 0 );
	}

	return( strcmp( dn + dnlen - suffixlen, suffix ) == 0 );
}

/*
 * get_next_substring(), rdn_attr_type(), rdn_attr_value(), and
 * build_new_dn().
 * 
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

/* get_next_substring:
 *
 * Gets next substring in s, using d (or the end of the string '\0') as a 
 * string delimiter, and places it in a duplicated memory space. Leading 
 * spaces are ignored. String s **must** be null-terminated.
 */ 

static char * 
get_next_substring( const char * s, char d )
{

	char	*str, *r;

	r = str = ch_malloc( strlen(s) + 1 );

	/* Skip leading spaces */
	
	while ( *s && ASCII_SPACE(*s) ) {
		s++;
	}
	
	/* Copy word */

	while ( *s && (*s != d) ) {

		/* Don't stop when you see trailing spaces may be a multi-word
		* string, i.e. name=John Doe!
		*/

		*str++ = *s++;
	    
	}
	
	*str = '\0';
	
	return r;
	
}


/* rdn_attr_type:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns the type of an attribute, that is the 
 * string "attribute_type" which is placed in newly allocated 
 * memory. The returned string will be null-terminated.
 */

char * rdn_attr_type( const char * s )
{
	return get_next_substring( s, '=' );
}


/* rdn_attr_value:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns "attribute_type" which is placed in newly allocated 
 * memory. The returned string will be null-terminated and may contain 
 * spaces (i.e. "John Doe\0").
 */

char * 
rdn_attr_value( const char * rdn )
{

	const char	*str;

	if ( (str = strchr( rdn, '=' )) != NULL ) {
		return get_next_substring(++str, '\0');
	}

	return NULL;

}


/* rdn_attrs:
 *
 * Given a string (i.e. an rdn) of the form:
 *       "attribute_type=attribute_value[+attribute_type=attribute_value[...]]"
 * this function stores the types of the attributes in ptypes, that is the 
 * array of strings "attribute_type" which is placed in newly allocated 
 * memory, and the values of the attributes in pvalues, that is the
 * array of strings "attribute_value" which is placed in newly allocated
 * memory. Returns 0 on success, -1 on failure.
 *
 * note: got part of the code from dn_validate
 */

int
rdn_attrs( const char * rdn_in, char ***ptypes, char ***pvalues)
{
	char **parts, **p;

	*ptypes = NULL;
	*pvalues = NULL;

	/*
	 * explode the rdn in parts
	 */
	parts = ldap_explode_rdn( rdn_in, 0 );

	if ( parts == NULL ) {
		return( -1 );
	}

	for ( p = parts; p[0]; p++ ) {
		char *s, *e, *d;
		
		/* split each rdn part in type value */
		s = strchr( p[0], '=' );
		if ( s == NULL ) {
			charray_free( *ptypes );
			charray_free( *pvalues );
			charray_free( parts );
			return( -1 );
		}
		
		/* type should be fine */
		charray_add_n( ptypes, p[0], ( s-p[0] ) );

		/* value needs to be unescaped 
		 * (maybe this should be moved to ldap_explode_rdn?) */
		for ( e = d = s + 1; e[0]; e++ ) {
			if ( *e != '\\' ) {
				*d++ = *e;
			}
		}
		d[0] = '\0';
		charray_add( pvalues, s + 1 );
	}

	/* free array */
	charray_free( parts );

	return( 0 );
}


/* rdn_validate:
 * 
 * 1 if rdn is a legal rdn; 
 * 0 otherwise (including a sequence of rdns)
 *
 * note: got it from dn_rdn; it should be rewritten 
 * according to dn_validate
 */
int
rdn_validate( const char * rdn )
{
	int	inquote;

	if ( rdn == NULL ) {
		return( 0 );
	}

	if ( strchr( rdn, '=' ) == NULL ) {
		return( 0 );
	}

	while ( *rdn && ASCII_SPACE( *rdn ) ) {
		rdn++;
	}

	if( *rdn == '\0' ) {
		return( 0 );
	}

	inquote = 0;

	for ( ; *rdn; rdn++ ) {
		if ( *rdn == '\\' ) {
			if ( *(rdn + 1) ) {
				rdn++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *rdn == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *rdn == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *rdn ) ) {
				return( 0 );
			}
		}
	}

	return( 1 );
}


/* build_new_dn:
 *
 * Used by ldbm/bdb2_back_modrdn to create the new dn of entries being
 * renamed.
 *
 * new_dn = parent (p_dn)  + separator(s) + rdn (newrdn) + null.
 */

void
build_new_dn( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn )
{

    if ( p_dn == NULL ) {
	*new_dn = ch_strdup( newrdn );
	return;
    }
    
    *new_dn = (char *) ch_malloc( strlen( p_dn ) + strlen( newrdn ) + 3 );

	strcpy( *new_dn, newrdn );
	strcat( *new_dn, "," );
	strcat( *new_dn, p_dn );
}
