/* $OpenLDAP$ */
#include "portable.h"

#if defined(HAVE_KERBEROS) && !defined(openbsd)
/*
 * Copyright 1985, 1986, 1987, 1988, 1989 by the Massachusetts Institute
 * of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * These routines perform encryption and decryption using the DES
 * private key algorithm, or else a subset of it-- fewer inner loops.
 * (AUTH_DES_ITER defaults to 16, may be less.)
 *
 * Under U.S. law, this software may not be exported outside the US
 * without license from the U.S. Commerce department.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext.  The cleartext and ciphertext should be in host order.
 *
 * These routines form the library interface to the DES facilities.
 *
 *	spm	8/85	MIT project athena
 */

#include <stdio.h>
#include <ac/krb.h>

#if defined( DEBUG ) && defined( HAVE_DES_DEBUG )
#define USE_DES_DEBUG
extern int des_debug;
#endif

extern void des_fixup_key_parity();

#ifndef HAVE_AFS_KERBEROS
#define WORLDPEACEINOURTIME
#endif

#if defined(WORLDPEACEINOURTIME) /* Use original, not ifs version */
#ifndef HAVE_KERBEROS_V
/*
 * convert an arbitrary length string to a DES key
 */
void
des_string_to_key( char *str, register des_cblock *key )
{
    register char *in_str;
    register unsigned temp,i;
    register int j;
    register long length;
    static unsigned char *k_p;
    static int forward;
    register char *p_char;
    static char k_char[64];
    static des_key_schedule key_sked;
    extern unsigned long des_cbc_cksum();

    in_str = str;
    forward = 1;
    p_char = k_char;
    length = strlen(str);

    /* init key array for bits */
    memset(k_char, 0, sizeof(k_char));

#ifdef USE_DES_DEBUG
    if (des_debug)
	fprintf(stdout,
		"\n\ninput str length = %d  string = %s\nstring = 0x ",
		length,str);
#endif

    /* get next 8 bytes, strip parity, xor */
    for (i = 1; i <= length; i++) {
	/* get next input key byte */
	temp = (unsigned int) *str++;
#ifdef USE_DES_DEBUG
	if (des_debug)
	    fprintf(stdout,"%02x ",temp & 0xff);
#endif
	/* loop through bits within byte, ignore parity */
	for (j = 0; j <= 6; j++) {
	    if (forward)
		*p_char++ ^= (int) temp & 01;
	    else
		*--p_char ^= (int) temp & 01;
	    temp = temp >> 1;
	} while (--j > 0);

	/* check and flip direction */
	if ((i%8) == 0)
	    forward = !forward;
    }

    /* now stuff into the key des_cblock, and force odd parity */
    p_char = k_char;
    k_p = (unsigned char *) key;

    for (i = 0; i <= 7; i++) {
	temp = 0;
	for (j = 0; j <= 6; j++)
	    temp |= *p_char++ << (1+j);
	*k_p++ = (unsigned char) temp;
    }

    /* fix key parity */
    des_fixup_key_parity(key);

    /* Now one-way encrypt it with the folded key */
    (void) des_key_sched(key,key_sked);
    (void) des_cbc_cksum((des_cblock *)in_str,key,length,key_sked,key);
    /* erase key_sked */
    memset((char *)key_sked, 0, sizeof(key_sked));

    /* now fix up key parity again */
    des_fixup_key_parity(key);

#ifdef USE_DES_DEBUG
    if (des_debug)
	fprintf(stdout,
		"\nResulting string_to_key = 0x%lx 0x%lx\n",
		*((unsigned long *) key),
		*((unsigned long *) key+1));
#endif
}

#endif /* HAVE_KERBEROS_V */
#else /* Use ifs version */

#if 0
#include <stdio.h>
    /* These two needed for rxgen output to work */
#include <sys/types.h>
#include <rx/xdr.h>
#include <afs/cellconfig.h>
#include <afs/auth.h>

#include "/usr/andy/kauth/kauth.h"
#include "/usr/andy/kauth/kautils.h"
#endif

/* This defines the Andrew string_to_key function.  It accepts a password
   string as input and converts its via a one-way encryption algorithm to a DES
   encryption key.  It is compatible with the original Andrew authentication
   service password database. */

static void
Andrew_StringToKey(
  char          *str,
  char          *cell,                  /* cell for password */
  des_cblock *key
)
{   char  password[8+1];                /* crypt is limited to 8 chars anyway */
    int   i;
    int   passlen;

    memset(key, 0, sizeof(des_cblock));
    memset(password, 0, sizeof(password));

    strncpy (password, cell, 8);
    passlen = strlen (str);
    if (passlen > 8) passlen = 8;

    for (i=0; i<passlen; i++)
        password[i] = str[i] ^ cell[i];

    for (i=0;i<8;i++)
        if (password[i] == '\0') password[i] = 'X';

    /* crypt only considers the first 8 characters of password but for some
       reason returns eleven characters of result (plus the two salt chars). */
    strncpy(key, crypt(password, "#~") + 2, sizeof(des_cblock));

    /* parity is inserted into the LSB so leftshift each byte up one bit.  This
       allows ascii characters with a zero MSB to retain as much significance
       as possible. */
    {   char *keybytes = (char *)key;
        unsigned int temp;

        for (i = 0; i < 8; i++) {
            temp = (unsigned int) keybytes[i];
            keybytes[i] = (unsigned char) (temp << 1);
        }
    }
    des_fixup_key_parity (key);
}

static void
StringToKey(
  char          *str,
  char          *cell,                  /* cell for password */
  des_cblock	*key
)
{   des_key_schedule schedule;
    char temp_key[8];
    char ivec[8];
    char password[BUFSIZ];
    int  passlen;

    strncpy (password, str, sizeof(password));
    if ((passlen = strlen (password)) < sizeof(password)-1)
        strncat (password, cell, sizeof(password)-passlen);
    if ((passlen = strlen(password)) > sizeof(password)) passlen = sizeof(password);

    memcpy(ivec, "kerberos", 8);
    memcpy(temp_key, "kerberos", 8);
    des_fixup_key_parity (temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, ivec, passlen, schedule, ivec);

    memcpy(temp_key, ivec, 8);
    des_fixup_key_parity (temp_key);
    des_key_sched (temp_key, schedule);
    des_cbc_cksum (password, key, passlen, schedule, ivec);

    des_fixup_key_parity (key);
}

void
ka_StringToKey (
  char          *str,
  char          *cell,                  /* cell for password */
  des_cblock	*key
)
{   char  realm[REALM_SZ];

#if NOWAYOUTTODAY
    long  code;
#if 0
    code = ka_CellToRealm (cell, realm, 0/*local*/);
#endif
    if (code) strcpy (realm, "");
    else lcstring (realm, realm, sizeof(realm)); /* for backward compatibility */
#else
	(void)strcpy(realm, cell);
#endif

    if (strlen(str) > 8) StringToKey (str, realm, key);
    else Andrew_StringToKey (str, realm, key);
}

/*
 * convert an arbitrary length string to a DES key
 */
int
des_string_to_key( char *str, register des_cblock *key )
{
	/* NB: i should probably call routine to get local cell here */
	ka_StringToKey(str, "umich.edu", key);
	return 0;
}

#endif /* Use IFS Version */

#endif /* kerberos */
