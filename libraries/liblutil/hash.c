/* $OpenLDAP$ */
/* This implements the Fowler / Noll / Vo (FNV-1) hash algorithm.
 * A summary of the algorithm can be found at:
 *   http://www.isthe.com/chongo/tech/comp/fnv/index.html
 */

#include "portable.h"

#include <lutil_hash.h>

/* offset and prime for 32-bit FNV-1 */
#define HASH_OFFSET	0x811c9dc5U
#define HASH_PRIME	16777619


/*
 * Initialize context
 */
void
lutil_HASHInit( struct lutil_HASHContext *ctx )
{
	ctx->hash = HASH_OFFSET;
}

/*
 * Update hash
 */
void
lutil_HASHUpdate(
    struct lutil_HASHContext	*ctx,
    const unsigned char		*buf,
    ber_len_t		len
)
{
	const unsigned char *p, *e;
	ber_uint_t h;

	p = buf;
	e = &buf[len];

	h = ctx->hash;

	while( p < e ) {
		h *= HASH_PRIME;
		h ^= *p++;
	}

	ctx->hash = h;
}

/*
 * Save hash
 */
void
lutil_HASHFinal( unsigned char *digest, struct lutil_HASHContext *ctx )
{
	ber_uint_t h = ctx->hash;

	digest[0] = h & 0xffU;
	digest[1] = (h>>8) & 0xffU;
	digest[2] = (h>>16) & 0xffU;
	digest[3] = (h>>24) & 0xffU;
}
