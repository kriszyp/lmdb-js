#ifndef _H_SLAPD_COMPONENT
#define _H_SLAPD_COMPONENT

#include "portable.h"
#include <ac/string.h>
#include <ac/socket.h>
#include "ldap_pvt.h"
#include "lutil.h"
#include <ldap.h>
#include "slap.h"

typedef enum {ASN_BASIC, ASN_COMPOSITE } AsnType;
/*
 * Decoder Modes
 * Different operation is required to handle Decoding(2), Extracted Component
 * decoding(0), ANY DEFINED TYPe(2)
 * b0 : Component Alloc(yes)
 *      Constructed type : Component Alloc (Yes)
 *      Primitive type : Component Alloc (Yes)
 *      set to mode 2 in inner decoders
 * b1 : Component Alloc (No)
 *      Constructed type : Component Alloc (No)
 *      Primitive type : Component Alloc (No)
 *      set to mode 2 in inner decoders
 * b2 : Default Mode
 *      Constructed type : Component Alloc (Yes)
 *      Primitive type : Component Alloc (No)
 * in addition to above modes, the 4th bit has special meaning,
 * b4 : if the 4th bit is clear, DecxxxContent is called
 * b4 : if the 4th bit is set, Decxxx is called, then it is cleared.
 */
#define DEC_ALLOC_MODE_0        0x01
#define DEC_ALLOC_MODE_1        0x02
#define DEC_ALLOC_MODE_2        0x04
#define CALL_TAG_DECODER        0x08
#define CALL_CONTENT_DECODER    ~0x08

#endif
