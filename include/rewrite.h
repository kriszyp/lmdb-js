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

#ifndef REWRITE_H
#define REWRITE_H

/*
 * Default rewrite context
 */
#define REWRITE_DEFAULT_CONTEXT		"default"

/*
 * Rewrite engine states
 */
#define REWRITE_OFF			0x0000
#define REWRITE_ON			0x0001
#define REWRITE_DEFAULT			REWRITE_OFF

/*
 * Rewrite internal status returns
 */
#define REWRITE_SUCCESS			LDAP_SUCCESS
#define REWRITE_ERR			LDAP_OPERATIONS_ERROR
#define REWRITE_NO_SUCH_OBJECT		LDAP_NO_SUCH_OBJECT

/*
 * Rewrite modes (input values for rewrite_info_init); determine the
 * behavior in case a null or non existent context is required:
 *
 * 	REWRITE_MODE_ERR		error
 * 	REWRITE_MODE_OK			no error but no rewrite
 * 	REWRITE_MODE_COPY_INPUT		a copy of the input is returned
 * 	REWRITE_MODE_USE_DEFAULT	the default context is used.
 */
#define REWRITE_MODE_ERR		0x0010
#define REWRITE_MODE_OK			0x0011
#define REWRITE_MODE_COPY_INPUT		0x0012
#define REWRITE_MODE_USE_DEFAULT	0x0013

/*
 * Rewrite status returns
 *
 * 	REWRITE_REGEXEC_OK		success (result may be empty in case
 * 					of no match)
 * 	REWRITE_REGEXEC_ERR		error (internal error,
 * 					misconfiguration, map not working ...)
 * 	REWRITE_REGEXEC_STOP		internal use; never returned
 * 	REWRITE_REGEXEC_UNWILLING	the server should issue an 'unwilling
 * 					to perform' error
 */
#define REWRITE_REGEXEC_OK              0x0000
#define REWRITE_REGEXEC_ERR             0x0001
#define REWRITE_REGEXEC_STOP            0x0002
#define REWRITE_REGEXEC_UNWILLING       0x0004

/*
 * Rewrite info
 */
struct rewrite_info;

struct berval; /* avoid include */

LDAP_BEGIN_DECL

/*
 * Inits the info
 */
LDAP_REWRITE_F (struct rewrite_info *)
rewrite_info_init(
		int mode
);

/*
 * Cleans up the info structure
 */
LDAP_REWRITE_F (int)
rewrite_info_delete(
                struct rewrite_info *info
);


/*
 * Parses a config line and takes actions to fit content in rewrite structure;
 * lines handled are of the form:
 *
 *      rewriteEngine 		{on|off}
 *      rewriteMaxPasses	numPasses
 *      rewriteContext 		contextName [alias aliasedRewriteContex]
 *      rewriteRule 		pattern substPattern [ruleFlags]
 *      rewriteMap 		mapType mapName [mapArgs]
 *      rewriteParam		paramName paramValue
 */
LDAP_REWRITE_F (int)
rewrite_parse(
		struct rewrite_info *info,
                const char *fname,
                int lineno,
                int argc,
                char **argv
);

/*
 * process a config file that was already opened. Uses rewrite_parse.
 */
LDAP_REWRITE_F (int)
rewrite_read(
		FILE *fin,
		struct rewrite_info *info
);

/*
 * Rewrites a string according to context.
 * If the engine is off, OK is returned, but the return string will be NULL.
 * In case of 'unwilling to perform', UNWILLING is returned, and the
 * return string will also be null. The same in case of error.
 * Otherwise, OK is returned, and result will hold a newly allocated string
 * with the rewriting.
 *
 * What to do in case of non-existing rewrite context is still an issue.
 * Four possibilities:
 *      - error,
 *      - ok with NULL result,
 *      - ok with copy of string as result,
 *      - use the default rewrite context.
 */
LDAP_REWRITE_F (int)
rewrite(
		struct rewrite_info *info,
		const char *rewriteContext,
		const char *string,
		char **result
);

/*
 * Same as above; the cookie relates the rewrite to a session
 */
LDAP_REWRITE_F (int)
rewrite_session(
		struct rewrite_info *info,
		const char *rewriteContext,
		const char *string,
		const void *cookie,
		char **result
);

/*
 * Inits a session
 */
LDAP_REWRITE_F (struct rewrite_session *)
rewrite_session_init(
                struct rewrite_info *info,
                const void *cookie
);

/*
 * Defines and inits a variable with session scope
 */
LDAP_REWRITE_F (int)
rewrite_session_var_set(
		struct rewrite_info *info,
		const void *cookie,
		const char *name,
		const char *value
);

/*
 * Deletes a session
 */
LDAP_REWRITE_F (int)
rewrite_session_delete(
		struct rewrite_info *info,
		const void *cookie
);


/*
 * Params
 */

/*
 * Defines and inits a variable with global scope
 */
LDAP_REWRITE_F (int)
rewrite_param_set(
                struct rewrite_info *info,
                const char *name,
                const char *value
);

/*
 * Gets a var with global scope
 */
LDAP_REWRITE_F (int)
rewrite_param_get(
                struct rewrite_info *info,
                const char *name,
                struct berval *value
);

/*
 * Destroys the parameter tree
 */
LDAP_REWRITE_F (int)
rewrite_param_destroy(
                struct rewrite_info *info
);

LDAP_END_DECL

#endif /* REWRITE_H */
