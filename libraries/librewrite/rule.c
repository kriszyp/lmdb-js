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

#include <portable.h>

#include "rewrite-int.h"

/*
 * Appends a rule to the double linked list of rules
 * Helper for rewrite_rule_compile
 */
static int
append_rule(
		struct rewrite_context *context,
		struct rewrite_rule *rule
)
{
	struct rewrite_rule *r;

	assert( context != NULL );
	assert( context->lc_rule != NULL );
	assert( rule != NULL );

	for ( r = context->lc_rule; r->lr_next != NULL; r = r->lr_next );
	r->lr_next = rule;
	rule->lr_prev = r;
	
	return REWRITE_SUCCESS;
}

/*
 * Appends an action to the linked list of actions
 * Helper for rewrite_rule_compile
 */
static int
append_action(
		struct rewrite_action *base,
		struct rewrite_action *action
)
{
	struct rewrite_action *a;

	assert( base != NULL );
	assert( action != NULL );
	
	for ( a = base; a->la_next != NULL; a = a->la_next );
	a->la_next = action;
	
	return REWRITE_SUCCESS;
}

/*
 * In case of error it returns NULL and does not free all the memory
 * it allocated; as this is a once only phase, and an error at this stage
 * would require the server to stop, there is no need to be paranoid
 * about memory allocation
 */
int
rewrite_rule_compile(
		struct rewrite_info *info,
		struct rewrite_context *context,
		const char *pattern,
		const char *result,
		const char *flagstring
)
{
	int flags = REWRITE_REGEX_EXTENDED | REWRITE_REGEX_ICASE;
	int mode = REWRITE_RECURSE;

	struct rewrite_rule *rule = NULL;
	struct rewrite_subst *subst = NULL;
	struct rewrite_action *action = NULL, *first_action = NULL;

	const char *p;

	assert( info != NULL );
	assert( context != NULL );
	assert( pattern != NULL );
	assert( result != NULL );

	/*
	 * A null flagstring should be allowed
	 */

	/*
	 * Take care of substitution string
	 */
	subst = rewrite_subst_compile( info, result );
	if ( subst == NULL ) {
		return REWRITE_ERR;
	}

	/*
	 * Take care of flags
	 */
	for ( p = flagstring; p[ 0 ] != '\0'; p++ ) {
		switch( p[ 0 ] ) {
			
		/*
		 * REGEX flags
		 */
		case REWRITE_FLAG_HONORCASE: 		/* 'C' */
			/*
			 * Honor case (default is case insensitive)
			 */
			flags &= ~REWRITE_REGEX_ICASE;
			break;
			
		case REWRITE_FLAG_BASICREGEX: 		/* 'R' */
			/*
			 * Use POSIX Basic Regular Expression syntax
			 * instead of POSIX Extended Regular Expression 
			 * syntax (default)
			 */
			flags &= ~REWRITE_REGEX_EXTENDED;
			break;
			
		/*
		 * Execution mode flags
		 */
		case REWRITE_FLAG_EXECONCE: 		/* ':' */
			/*
			 * Apply rule once only
			 */
			mode &= ~REWRITE_RECURSE;
			mode |= REWRITE_EXEC_ONCE;
			break;
		
		/*
		 * Special action flags
		 */
		case REWRITE_FLAG_STOP:	 		/* '@' */
			/*
			 * Bail out after applying rule
			 */
			action = calloc( sizeof( struct rewrite_action ), 1 );
			if ( action == NULL ) {
				/* cleanup ... */
				return REWRITE_ERR;
			}
			
			mode &= ~REWRITE_RECURSE;
			mode |= REWRITE_EXEC_ONCE;
			action->la_type = REWRITE_ACTION_STOP;
			break;
			
		case REWRITE_FLAG_UNWILLING: 		/* '#' */
			/*
			 * Matching objs will be marked as gone!
			 */
			action = calloc( sizeof( struct rewrite_action ), 1 );
			if ( action == NULL ) {
				/* cleanup ... */
				return REWRITE_ERR;
			}
			
			mode &= ~REWRITE_RECURSE;
			mode |= REWRITE_EXEC_ONCE;
			action->la_type = REWRITE_ACTION_UNWILLING;
			break;

		case REWRITE_FLAG_GOTO: {			/* 'G' */
			/*
			 * After applying rule, jump N rules
			 */

			char buf[16], *q;
			size_t l;
			int *d;
			
			if ( p[ 1 ] != '{' ) {
				/* XXX Need to free stuff */
				return REWRITE_ERR;
			}

			q = strchr( p + 2, '}' );
			if ( q == NULL ) {
				/* XXX Need to free stuff */
				return REWRITE_ERR;
			}

			l = q - p + 2;
			if ( l >= sizeof( buf ) ) {
				/* XXX Need to free stuff */
				return REWRITE_ERR;
			}
			AC_MEMCPY( buf, p + 2, l );
			buf[ l ] = '\0';

			d = malloc( sizeof( int ) );
			if ( d == NULL ) {
				/* XXX Need to free stuff */
				return REWRITE_ERR;
			}
			d[ 0 ] = atoi( buf );

			action = calloc( sizeof( struct rewrite_action ), 1 );
			if ( action == NULL ) {
				/* cleanup ... */       
				return REWRITE_ERR;
			}
			action->la_type = REWRITE_ACTION_GOTO;
			action->la_args = (void *)d;

			p = q;	/* p is incremented by the for ... */
		
			break;
		}

		case REWRITE_FLAG_IGNORE_ERR:               /* 'I' */
			/*
			 * Ignore errors!
			 */
			action = calloc( sizeof( struct rewrite_action ), 1 );
			if ( action == NULL ) {
				/* cleanup ... */
				return REWRITE_ERR;
			}
			
			action->la_type = REWRITE_ACTION_IGNORE_ERR;
			break;
			
		/*
		 * Other flags ...
		 */
		default:
			/*
			 * Unimplemented feature (complain only)
			 */
			break;
		}
		
		/*
		 * Stupid way to append to a list ...
		 */
		if ( action != NULL ) {
			if ( first_action == NULL ) {
				first_action = action;
			} else {
				append_action( first_action, action );
			}
			action = NULL;
		}
	}
	
	/*
	 * Finally, rule allocation
	 */
	rule = calloc( sizeof( struct rewrite_rule ), 1 );
	if ( rule == NULL ) {
		/* charray_free( res ); */
		/*
		 * XXX need to free the value subst stuff!
		 */
		return REWRITE_ERR;
	}
	
	/*
	 * REGEX compilation (luckily I don't need to take care of this ...)
	 */
	if ( regcomp( &rule->lr_regex, ( char * )pattern, flags ) != 0 ) {
		/* charray_free( res ); */
		/*
		 *XXX need to free the value subst stuff!
		 */
		free( rule );
		return REWRITE_ERR;
	}
	
	/*
	 * Just to remember them ...
	 */
	rule->lr_pattern = strdup( pattern );
	rule->lr_subststring = strdup( result );
	rule->lr_flagstring = strdup( flagstring );
	
	/*
	 * Load compiled data into rule
	 */
	rule->lr_subst = subst;

	/*
	 * Set various parameters
	 */
	rule->lr_flags = flags;		/* don't really need any longer ... */
	rule->lr_mode = mode;
	rule->lr_action = first_action;
	
	/*
	 * Append rule at the end of the rewrite context
	 */
	append_rule( context, rule );

	return REWRITE_SUCCESS;
}

/*
 * Rewrites string according to rule; may return:
 *      OK:     fine; if *result != NULL rule matched and rewrite succeeded.
 *      STOP:   fine, rule matched; stop processing following rules
 *      UNWILL: rule matched; force 'unwilling to perform'
 */
int
rewrite_rule_apply(
		struct rewrite_info *info,
		struct rewrite_op *op,
		struct rewrite_rule *rule,
		const char *arg,
		char **result
		)
{
	size_t nmatch = REWRITE_MAX_MATCH;
	regmatch_t match[ REWRITE_MAX_MATCH ];

	int rc = REWRITE_SUCCESS;

	char *string;
	struct berval val;

	assert( info != NULL );
	assert( op != NULL );
	assert( rule != NULL );
	assert( arg != NULL );
	assert( result != NULL );

	*result = NULL;

	string = strdup( arg );
	if ( string == NULL ) {
		return REWRITE_REGEXEC_ERR;
	}
	
	/*
	 * In case recursive match is required (default)
	 */
recurse:;

	Debug( LDAP_DEBUG_TRACE, "==> rewrite_rule_apply"
			" rule='%s' string='%s'\n%s", 
			rule->lr_pattern, string, "" );
	
	op->lo_num_passes++;
	if ( regexec( &rule->lr_regex, string, nmatch, match, 0 ) != 0 ) {
		if ( *result == NULL ) {
			free( string );
		}

		/*
		 * No match is OK; *result = NULL means no match
		 */
		return REWRITE_REGEXEC_OK;
	}

	rc = rewrite_subst_apply( info, op, rule->lr_subst, string,
			match, &val );

	*result = val.bv_val;
	free( string );

	if ( rc != REWRITE_REGEXEC_OK ) {
		return rc;
	}

	if ( ( rule->lr_mode & REWRITE_RECURSE ) == REWRITE_RECURSE 
			&& op->lo_num_passes <= info->li_max_passes ) {
		string = *result;
		goto recurse;
	}

	return REWRITE_REGEXEC_OK;
}

