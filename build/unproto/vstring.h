/* @(#) vstring.h 1.2 92/01/15 21:53:19 */

struct vstring {
    char   *str;			/* string value */
    char   *last;			/* last position */
};

extern struct vstring *vs_alloc();	/* initial allocation */
extern char *vs_realloc();		/* string extension */
extern char *vs_strcpy();		/* copy string */

/* macro to add one character to auto-resized string */

#define	VS_ADDCH(vs,wp,c) \
    ((wp < (vs)->last || (wp = vs_realloc(vs,wp))) ? (*wp++ = c) : 0)
