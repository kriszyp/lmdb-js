/*
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Include file for the Data Encryption Standard library.
 */

/* only do the whole thing once  */
#ifndef DES_DEFS
#define DES_DEFS

#include <mit_copy.h>

typedef unsigned char des_cblock[8];    /* crypto-block size */
/* Key schedule */
typedef struct des_ks_struct { des_cblock _; } des_key_schedule[16];

#define DES_KEY_SZ      (sizeof(des_cblock))
#define DES_ENCRYPT     1
#define DES_DECRYPT     0

#ifndef NCOMPAT
#define C_Block des_cblock
#define Key_schedule des_key_schedule
#define ENCRYPT DES_ENCRYPT
#define DECRYPT DES_DECRYPT
#define KEY_SZ DES_KEY_SZ
#define string_to_key des_string_to_key
#define read_pw_string des_read_pw_string
#define random_key des_random_key
#define pcbc_encrypt des_pcbc_encrypt
#define key_sched des_key_sched
#define cbc_encrypt des_cbc_encrypt
#define cbc_cksum des_cbc_cksum
#define C_Block_print des_cblock_print
#define quad_cksum des_quad_cksum
typedef struct des_ks_struct bit_64;
#endif

#define des_cblock_print(x) des_cblock_print_file(x, stdout)

int des_check_key_parity(des_cblock);
int des_is_weak_key(des_cblock);

/* Function prototypes */
int des_key_sched(des_cblock,des_key_schedule);
int des_ecb_encrypt(unsigned long*,unsigned long*,des_key_schedule,int);
int des_pcbc_encrypt(des_cblock*,des_cblock*,long,des_key_schedule,
                                                des_cblock*,int);

unsigned long des_cbc_cksum(des_cblock*,des_cblock*,long,
                              des_key_schedule,des_cblock*);

int des_is_weak_key(des_cblock);
void des_fixup_key_parity(des_cblock);
int des_check_key_parity(des_cblock);
#endif  /* DES_DEFS */
