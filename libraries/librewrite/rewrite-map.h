/******************************************************************************
 *
 * Copyright (C) 2000 Pierangelo Masarati, <ando@sys-net.it>
 * All rights reserved.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 * software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 * explicit claim or by omission.  Since few users ever read sources,
 * credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 * misrepresented as being the original software.  Since few users
 * ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 ******************************************************************************/

#ifndef MAP_H
#define MAP_H

/*
 * Retrieves a builtin map
 */
LDAP_REWRITE_F (struct rewrite_builtin_map *)
rewrite_builtin_map_find(
                struct rewrite_info *info,
                const char *name
);


/*
 * LDAP map
 */
LDAP_REWRITE_F (void  *)
map_ldap_parse(
		struct rewrite_info *info,
		const char *fname,
		int lineno,
	       	int argc,
	       	char **argv
);

LDAP_REWRITE_F (int)
map_ldap_apply( struct rewrite_builtin_map *map,
		const char *filter,
		struct berval *val
);

#endif /* MAP_H */
