/*
 * Copyright 1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * schema.c:  parsing routines used by servers and clients to process
 *	schema definitions
 */

#include "portable.h"

#include <ac/ctype.h>
#include <ac/string.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <lber.h>
#include <ldap.h>
#include <ldap_schema.h>
#include <stdio.h>

/*
 * When pretty printing the entities we will be appending to a buffer.
 * Since checking for overflow, realloc'ing and checking if no error
 * is extremely boring, we will use a pretection layer that will let
 * us blissfully ignore the error until the end.  This layer is
 * implemented with the help of the next type.
 */

typedef struct safe_string {
	char * val;
	int size;
	int pos;
	int at_whsp;
} safe_string;

static safe_string *
new_safe_string(int size)
{
	safe_string * ss;
	
	ss = malloc(sizeof(safe_string));
	if ( !ss )
		return(NULL);
	ss->size = size;
	ss->pos = 0;
	ss->val = malloc(size);
	ss->at_whsp = 0;
	if ( !ss->val ) {
		free(ss);
		return(NULL);
	}
	return ss;
}

void
safe_string_free(safe_string * ss)
{
	if ( !ss )
		return;
	ldap_memfree(ss->val);
	ldap_memfree(ss);
}

static char *
safe_string_val(safe_string * ss)
{
	return(ss->val);
}

static int
append_to_safe_string(safe_string * ss, char * s)
{
	int l = strlen(s);
	char * temp;

	/*
	 * Some runaway process is trying to append to a string that
	 * overflowed and we could not extend.
	 */
	if ( !ss->val )
		return -1;

	/* We always make sure there is at least one position available */
	if ( ss->pos + l >= ss->size-1 ) {
		ss->size *= 2;
		temp = realloc(ss->val, ss->size);
		if ( !temp ) {
			/* Trouble, out of memory */
			free(ss->val);
			return -1;
		}
		ss->val = temp;
	}
	strncpy(&ss->val[ss->pos], s, l);
	ss->pos += l;
	if ( ss->pos > 0 && ss->val[ss->pos-1] == ' ' )
		ss->at_whsp = 1;
	else
		ss->at_whsp = 0;

	return 0;
}

static int
print_literal(safe_string *ss, char *s)
{
	return(append_to_safe_string(ss,s));
}

static int
print_whsp(safe_string *ss)
{
	if ( ss->at_whsp )
		return(append_to_safe_string(ss,""));
	else
		return(append_to_safe_string(ss," "));
}

static int
print_numericoid(safe_string *ss, char *s)
{
	return(append_to_safe_string(ss,s));
}

/* This one is identical to print_qdescr */
static int
print_qdstring(safe_string *ss, char *s)
{
	print_whsp(ss);
	print_literal(ss,"'");
	append_to_safe_string(ss,s);
	print_literal(ss,"'");
	return(print_whsp(ss));
}

static int
print_qdescr(safe_string *ss, char *s)
{
	print_whsp(ss);
	print_literal(ss,"'");
	append_to_safe_string(ss,s);
	print_literal(ss,"'");
	return(print_whsp(ss));
}

static int
print_qdescrlist(safe_string *ss, char **sa)
{
	char **sp;
	int ret = 0;
	
	for (sp=sa; *sp; sp++) {
		ret = print_qdescr(ss,*sp);
	}
	/* If the list was empty, we return zero that is potentially
	 * incorrect, but since we will still appending things, the
	 * overflow will be detected later.  Maybe FIX.
	 */
	return(ret);
}

static int
print_qdescrs(safe_string *ss, char **sa)
{
	/* The only way to represent an empty list is as a qdescrlist
	 * so, if the list is empty we treat it as a long list.
	 * Really, this is what the syntax mandates.
	 */
	if ( !sa[0] || ( sa[0] && sa[1] ) ) {
		print_whsp(ss);
		print_literal(ss,"(");
		print_qdescrlist(ss,sa);
		print_literal(ss,")");
		return(print_whsp(ss));
	} else {
	  return(print_qdescr(ss,*sa));
	}
}

static int
print_woid(safe_string *ss, char *s)
{
	print_whsp(ss);
	append_to_safe_string(ss,s);
	return print_whsp(ss);
}

static int
print_oidlist(safe_string *ss, char **sa)
{
	char **sp;

	for (sp=sa; *(sp+1); sp++) {
		print_woid(ss,*sp);
		print_literal(ss,"$");
	}
	return(print_woid(ss,*sp));
}

static int
print_oids(safe_string *ss, char **sa)
{
	if ( sa[0] && sa[1] ) {
		print_literal(ss,"(");
		print_oidlist(ss,sa);
		print_whsp(ss);
		return(print_literal(ss,")"));
	} else {
		return(print_woid(ss,*sa));
	}
}

static int
print_noidlen(safe_string *ss, char *s, int l)
{
	char buf[64];
	int ret;

	ret = print_numericoid(ss,s);
	if ( l ) {
		sprintf(buf,"{%d}",l);
		ret = print_literal(ss,buf);
	}
	return(ret);
}

char *
ldap_objectclass2str( LDAP_OBJECT_CLASS * oc )
{
	safe_string * ss;
	char * retstring;
	
	ss = new_safe_string(256);
	if ( !ss )
		return NULL;

	print_literal(ss,"(");
	print_whsp(ss);

	print_numericoid(ss, oc->oc_oid);
	print_whsp(ss);

	if ( oc->oc_names ) {
		print_literal(ss,"NAME");
		print_qdescrs(ss,oc->oc_names);
	}

	if ( oc->oc_desc ) {
		print_literal(ss,"DESC");
		print_qdstring(ss,oc->oc_desc);
	}

	if ( oc->oc_obsolete ) {
		print_literal(ss, "OBSOLETE");
		print_whsp(ss);
	}

	if ( oc->oc_sup_oids ) {
		print_literal(ss,"SUP");
		print_oids(ss,oc->oc_sup_oids);
	}

	switch (oc->oc_kind) {
	case 0:
		print_literal(ss,"ABSTRACT");
		break;
	case 1:
		print_literal(ss,"STRUCTURAL");
		break;
	case 2:
		print_literal(ss,"AUXILIARY");
		break;
	default:
		print_literal(ss,"KIND-UNKNOWN");
		break;
	}
	print_whsp(ss);
	
	if ( oc->oc_at_oids_must ) {
		print_literal(ss,"MUST");
		print_whsp(ss);
		print_oids(ss,oc->oc_at_oids_must);
		print_whsp(ss);
	}

	if ( oc->oc_at_oids_may ) {
		print_literal(ss,"MAY");
		print_whsp(ss);
		print_oids(ss,oc->oc_at_oids_may);
		print_whsp(ss);
	}

	print_whsp(ss);
	print_literal(ss,")");

	retstring = safe_string_val(ss);
	safe_string_free(ss);
	return(retstring);
}

char *
ldap_attributetype2str( LDAP_ATTRIBUTE_TYPE * at )
{
	safe_string * ss;
	char * retstring;
	
	ss = new_safe_string(256);
	if ( !ss )
		return NULL;

	print_literal(ss,"(");
	print_whsp(ss);

	print_numericoid(ss, at->at_oid);
	print_whsp(ss);

	if ( at->at_names ) {
		print_literal(ss,"NAME");
		print_qdescrs(ss,at->at_names);
	}

	if ( at->at_desc ) {
		print_literal(ss,"DESC");
		print_qdstring(ss,at->at_desc);
	}

	if ( at->at_obsolete ) {
		print_literal(ss, "OBSOLETE");
		print_whsp(ss);
	}

	if ( at->at_sup_oid ) {
		print_literal(ss,"SUP");
		print_woid(ss,at->at_sup_oid);
	}

	if ( at->at_equality_oid ) {
		print_literal(ss,"EQUALITY");
		print_woid(ss,at->at_equality_oid);
	}

	if ( at->at_ordering_oid ) {
		print_literal(ss,"ORDERING");
		print_woid(ss,at->at_ordering_oid);
	}

	if ( at->at_substr_oid ) {
		print_literal(ss,"SUBSTR");
		print_woid(ss,at->at_substr_oid);
	}

	if ( at->at_syntax_oid ) {
		print_literal(ss,"SYNTAX");
		print_noidlen(ss,at->at_syntax_oid,at->at_syntax_len);
	}

	if ( at->at_single_value ) {
		print_literal(ss,"SINGLE-VALUE");
		print_whsp(ss);
	}

	if ( at->at_collective ) {
		print_literal(ss,"COLLECTIVE");
		print_whsp(ss);
	}

	if ( at->at_no_user_mod ) {
		print_literal(ss,"NO-USER-MODIFICATION");
		print_whsp(ss);
	}

	if ( at->at_usage ) {
		print_literal(ss,"USAGE");
		print_whsp(ss);
		switch (at->at_usage) {
		case 1:
			print_literal(ss,"directoryOperation");
			break;
		case 2:
			print_literal(ss,"distributedOperation");
			break;
		case 3:
			print_literal(ss,"dSAOperation");
			break;
		default:
			print_literal(ss,"UNKNOWN");
			break;
		}
	}
	
	print_whsp(ss);
	print_literal(ss,")");

	retstring = safe_string_val(ss);
	safe_string_free(ss);
	return(retstring);
}

/*
 * This is ripped from servers/slapd/charray.c that should be promoted
 * to -lldap or something so that it is used everywhere.
 */
static void
charray_free( char **array )
{
	char	**a;

	if ( array == NULL ) {
		return;
	}

	for ( a = array; *a != NULL; a++ ) {
		if ( *a != NULL ) {
			free( *a );
		}
	}
	free( (char *) array );
}

/*
 * Now come the parsers.  There is one parser for each entity type:
 * objectclasses, attributetypes, etc.
 *
 * Each of them is written as a recursive-descent parser, except that
 * none of them is really recursive.  But the idea is kept: there
 * is one routine per non-terminal that eithers gobbles lexical tokens
 * or calls lower-level routines, etc.
 *
 * The scanner is implemented in the routine get_token.  Actually,
 * get_token is more than a scanner and will return tokens that are
 * in fact non-terminals in the grammar.  So you can see the whole
 * approach as the combination of a low-level bottom-up recognizer
 * combined with a scanner and a number of top-down parsers.  Or just
 * consider that the real grammars recognized by the parsers are not
 * those of the standards.  As a matter of fact, our parsers are more
 * liberal than the spec when there is no ambiguity.
 *
 * The difference is pretty academic (modulo bugs or incorrect
 * interpretation of the specs).
 */

#define TK_NOENDQUOTE	-2
#define TK_OUTOFMEM	-1
#define TK_EOS		0
#define TK_UNEXPCHAR	1
#define TK_BAREWORD	2
#define TK_QDSTRING	3
#define TK_LEFTPAREN	4
#define TK_RIGHTPAREN	5
#define TK_DOLLAR	6
#define TK_QDESCR	TK_QDSTRING

struct token {
  int type;
  char *sval;
};

static int
get_token(char ** sp, char ** token_val)
{
	int kind;
	char * p;
	char * q;
	char * res;

	switch (**sp) {
	case '\0':
		kind = TK_EOS;
		(*sp)++;
		break;
	case '(':
		kind = TK_LEFTPAREN;
		(*sp)++;
		break;
	case ')':
		kind = TK_RIGHTPAREN;
		(*sp)++;
		break;
	case '$':
		kind = TK_DOLLAR;
		(*sp)++;
		break;
	case '\'':
		kind = TK_QDSTRING;
		(*sp)++;
		p = *sp;
		while ( **sp != '\'' && **sp != '\0' )
			(*sp)++;
		if ( **sp == '\'' ) {
			q = *sp;
			res = malloc(q-p+1);
			if ( !res ) {
				kind = TK_OUTOFMEM;
			} else {
				strncpy(res,p,q-p);
				res[q-p] = '\0';
				*token_val = res;
			}
			(*sp)++;
		} else {
			kind = TK_NOENDQUOTE;
		}
		break;
	default:
		kind = TK_BAREWORD;
		p = *sp;
		while ( !isspace(**sp) && **sp != '\0' )
			(*sp)++;
		q = *sp;
		res = malloc(q-p+1);
		if ( !res ) {
			kind = TK_OUTOFMEM;
		} else {
			strncpy(res,p,q-p);
			res[q-p] = '\0';
			*token_val = res;
		}
		break;
/*  		kind = TK_UNEXPCHAR; */
/*  		break; */
	}
	
	return kind;
}

/* Gobble optional whitespace */
static void
parse_whsp(char **sp)
{
	while (isspace(**sp))
		(*sp)++;
}

/* TBC:!!
 * General note for all parsers: to guarantee the algorithm halts they
 * must always advance the pointer even when an error is found.  For
 * this one is not that important since an error here is fatal at the
 * upper layers, but it is a simple strategy that will not get in
 * endless loops.
 */

/* Parse a sequence of dot-separated decimal strings */
static char *
parse_numericoid(char **sp, int *code)
{
	char * res;
	char * start = *sp;
	int len;

	/* Each iteration of this loops gets one decimal string */
	while (**sp) {
		if ( !isdigit(**sp) ) {
			/* Initial char is not a digit or char after dot is not a digit */
			*code = LDAP_SCHERR_NODIGIT;
			return NULL;
		}
		(*sp)++;
		while ( isdigit(**sp) )
			(*sp)++;
		if ( **sp != '.' )
			break;
		/* Otherwise, gobble the dot and loop again */
		(*sp)++;
	}
	/* At this point, *sp points at the char past the numericoid. Perfect. */
	len = *sp - start;
	res = malloc(len+1);
	if (!res) {
	  *code = LDAP_SCHERR_OUTOFMEM;
	  return(NULL);
	}
	strncpy(res,start,len);
	res[len] = '\0';
	return(res);
}

/* Parse a qdescr or a list of them enclosed in () */
static char **
parse_qdescrs(char **sp, int *code)
{
	char ** res;
	char ** res1;
	int kind;
	char * sval;
	int size;
	int pos;

	parse_whsp(sp);
	kind = get_token(sp,&sval);
	if ( kind == TK_LEFTPAREN ) {
		/* Let's presume there will be at least 2 entries */
		size = 3;
		res = calloc(3,sizeof(char *));
		if ( !res ) {
			*code = LDAP_SCHERR_OUTOFMEM;
			return NULL;
		}
		pos = 0;
		while (1) {
			parse_whsp(sp);
			kind = get_token(sp,&sval);
			if ( kind == TK_RIGHTPAREN )
				break;
			if ( kind == TK_QDESCR ) {
				if ( pos == size-2 ) {
					size++;
					res1 = realloc(res,size*sizeof(char *));
					if ( !res1 ) {
						charray_free(res);
						*code = LDAP_SCHERR_OUTOFMEM;
						return(NULL);
					}
					res = res1;
				}
				res[pos] = sval;
				pos++;
				parse_whsp(sp);
			} else {
				charray_free(res);
				*code = LDAP_SCHERR_UNEXPTOKEN;
				return(NULL);
			}
		}
		res[pos] = NULL;
		parse_whsp(sp);
		return(res);
	} else if ( kind == TK_QDESCR ) {
		res = calloc(2,sizeof(char *));
		if ( !res ) {
			*code = LDAP_SCHERR_OUTOFMEM;
			return NULL;
		}
		res[0] = sval;
		res[1] = NULL;
		parse_whsp(sp);
		return res;
	} else {
		*code = LDAP_SCHERR_BADNAME;
		return NULL;
	}
}

/* Parse a woid */
static char *
parse_woid(char **sp, int *code)
{
	char * sval;
	int kind;

	parse_whsp(sp);
	kind = get_token(sp, &sval);
	if ( kind != TK_BAREWORD ) {
		*code = LDAP_SCHERR_UNEXPTOKEN;
		return NULL;
	}
	parse_whsp(sp);
	return sval;
}

/* Parse a noidlen */
static char *
parse_noidlen(char **sp, int *code, int *len)
{
	char * sval;
	int kind;

	*len = 0;
	kind = get_token(sp, &sval);
	if ( kind != TK_BAREWORD ) {
		*code = LDAP_SCHERR_UNEXPTOKEN;
		return NULL;
	}
	if ( **sp == '{' ) {
		(*sp)++;
		*len = atoi(**sp);
		while ( isdigit(**sp) )
			(*sp)++;
		(*sp)++;
		if ( **sp != '}' ) {
			*code = LDAP_SCHERR_UNEXPTOKEN;
			ldap_memfree(sval);
			return NULL;
		}
		(*sp)++;
	}		
	return sval;
}

/* Parse a woid or a $-separated list of them enclosed in () */
static char **
parse_oids(char **sp, int *code)
{
	char ** res;
	char ** res1;
	int kind;
	char * sval;
	int size;
	int pos;

	/*
	 * Strictly speaking, doing this here accepts whsp before the
	 * ( at the begining of an oidlist, but his is harmless.  Also,
	 * we are very liberal in what we accept as an OID.  Maybe
	 * refine later.
	 */
	parse_whsp(sp);
	kind = get_token(sp,&sval);
	if ( kind == TK_LEFTPAREN ) {
		/* Let's presume there will be at least 2 entries */
		size = 3;
		res = calloc(3,sizeof(char *));
		if ( !res ) {
			*code = LDAP_SCHERR_OUTOFMEM;
			return NULL;
		}
		pos = 0;
		parse_whsp(sp);
		kind = get_token(sp,&sval);
		if ( kind == TK_BAREWORD ) {
			res[pos] = sval;
			pos++;
		} else {
			*code = LDAP_SCHERR_UNEXPTOKEN;
			charray_free(res);
			return NULL;
		}
		parse_whsp(sp);
		while (1) {
			kind = get_token(sp,&sval);
			if ( kind == TK_RIGHTPAREN )
				break;
			if ( kind == TK_DOLLAR ) {
				parse_whsp(sp);
				kind = get_token(sp,&sval);
				if ( kind == TK_BAREWORD ) {
					if ( pos == size-2 ) {
						size++;
						res1 = realloc(res,size*sizeof(char *));
						if ( !res1 ) {
						  charray_free(res);
						  *code = LDAP_SCHERR_OUTOFMEM;
						  return(NULL);
						}
						res = res1;
					}
					res[pos] = sval;
					pos++;
				} else {
					*code = LDAP_SCHERR_UNEXPTOKEN;
					charray_free(res);
					return NULL;
				}
				parse_whsp(sp);
			} else {
				*code = LDAP_SCHERR_UNEXPTOKEN;
				charray_free(res);
				return NULL;
			}
		}
		res[pos] = NULL;
		parse_whsp(sp);
		return(res);
	} else if ( kind == TK_BAREWORD ) {
		res = calloc(2,sizeof(char *));
		if ( !res ) {
			*code = LDAP_SCHERR_OUTOFMEM;
			return NULL;
		}
		res[0] = sval;
		res[1] = NULL;
		parse_whsp(sp);
		return res;
	} else {
		*code = LDAP_SCHERR_BADNAME;
		return NULL;
	}
}

static void
free_at(LDAP_ATTRIBUTE_TYPE * at)
{
	ldap_memfree(at->at_oid);
	charray_free(at->at_names);
	ldap_memfree(at->at_desc);
	ldap_memfree(at->at_sup_oid);
	ldap_memfree(at->at_equality_oid);
	ldap_memfree(at->at_ordering_oid);
	ldap_memfree(at->at_substr_oid);
	ldap_memfree(at->at_syntax_oid);
	ldap_memfree(at);
}

LDAP_ATTRIBUTE_TYPE *
ldap_str2attributetype( char * s, int * code, char ** errp )
{
	int kind;
	char * ss = s;
	char * sval;
	int seen_name = 0;
	int seen_desc = 0;
	int seen_obsolete = 0;
	int seen_sup = 0;
	int seen_equality = 0;
	int seen_ordering = 0;
	int seen_substr = 0;
	int seen_syntax = 0;
	int seen_usage = 0;
	int seen_kind = 0;
	int seen_must = 0;
	int seen_may = 0;
	LDAP_ATTRIBUTE_TYPE * at;

	*errp = s;
	at = calloc(1,sizeof(LDAP_ATTRIBUTE_TYPE));

	if ( !at ) {
		*code = LDAP_SCHERR_OUTOFMEM;
		return NULL;
	}

	kind = get_token(&ss,&sval);
	if ( kind != TK_LEFTPAREN ) {
		*code = LDAP_SCHERR_NOLEFTPAREN;
		free_at(at);
		return NULL;
	}

	parse_whsp(&ss);
	at->at_oid = parse_numericoid(&ss,code);
	if ( !at->at_oid ) {
		*errp = ss;
		free_at(at);
		return NULL;
	}
	parse_whsp(&ss);

	/*
	 * Beyond this point we will be liberal an accept the items
	 * in any order.
	 */
	while (1) {
		kind = get_token(&ss,&sval);
		switch (kind) {
		case TK_EOS:
			*code = LDAP_SCHERR_NORIGHTPAREN;
			*errp = ss;
			free_at(at);
			return NULL;
		case TK_RIGHTPAREN:
			return at;
		case TK_BAREWORD:
			if ( !strcmp(sval,"NAME") ) {
				if ( seen_name ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_name = 1;
				at->at_names = parse_qdescrs(&ss,code);
				if ( !at->at_names ) {
					if ( *code != LDAP_SCHERR_OUTOFMEM )
						*code = LDAP_SCHERR_BADNAME;
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"DESC") ) {
				if ( seen_desc ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_desc = 1;
				parse_whsp(&ss);
				kind = get_token(&ss,&sval);
				if ( kind != TK_QDSTRING ) {
					*code = LDAP_SCHERR_UNEXPTOKEN;
					*errp = ss;
					free_at(at);
					return NULL;
				}
				at->at_desc = sval;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"OBSOLETE") ) {
				if ( seen_obsolete ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_obsolete = 1;
				at->at_obsolete = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"SUP") ) {
				if ( seen_sup ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_sup = 1;
				at->at_sup_oid = parse_woid(&ss,code);
				if ( !at->at_sup_oid ) {
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"EQUALITY") ) {
				if ( seen_equality ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_equality = 1;
				at->at_equality_oid = parse_woid(&ss,code);
				if ( !at->at_equality_oid ) {
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"ORDERING") ) {
				if ( seen_ordering ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_ordering = 1;
				at->at_ordering_oid = parse_woid(&ss,code);
				if ( !at->at_ordering_oid ) {
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"SUBSTR") ) {
				if ( seen_substr ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_substr = 1;
				at->at_substr_oid = parse_woid(&ss,code);
				if ( !at->at_substr_oid ) {
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"SYNTAX") ) {
				if ( seen_syntax ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_syntax = 1;
				parse_whsp(&ss);
				at->at_syntax_oid = parse_noidlen(&ss,code,&at->at_syntax_len);
				if ( !at->at_syntax_oid ) {
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else if ( !strcmp(sval,"SINGLE-VALUE") ) {
				if ( at->at_single_value ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				at->at_single_value = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"COLLECTIVE") ) {
				if ( at->at_collective ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				at->at_collective = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"NO-USER-MODIFICATION") ) {
				if ( at->at_no_user_mod ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				at->at_no_user_mod = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"USAGE") ) {
				if ( seen_usage ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_at(at);
					return(NULL);
				}
				seen_usage = 1;
				parse_whsp(&ss);
				kind = get_token(&ss,&sval);
				if ( kind != TK_BAREWORD ) {
					*code = LDAP_SCHERR_UNEXPTOKEN;
					*errp = ss;
					free_at(at);
					return NULL;
				}
				if ( !strcasecmp(sval,"userApplications") )
					at->at_usage = 0;
				else if ( !strcasecmp(sval,"directoryOperation") )
					at->at_usage = 1;
				else if ( !strcasecmp(sval,"distributedOperation") )
					at->at_usage = 2;
				else if ( !strcasecmp(sval,"dSAOperation") )
					at->at_usage = 3;
				else {
					*code = LDAP_SCHERR_UNEXPTOKEN;
					*errp = ss;
					free_at(at);
					return NULL;
				}
			} else {
				*code = LDAP_SCHERR_UNEXPTOKEN;
				*errp = ss;
				free_at(at);
				return NULL;
			}
			break;
		default:
			*code = LDAP_SCHERR_UNEXPTOKEN;
			*errp = ss;
			free_at(at);
			return NULL;
		}
	}
}

static void
free_oc(LDAP_OBJECT_CLASS * oc)
{
	ldap_memfree(oc->oc_oid);
	charray_free(oc->oc_names);
	ldap_memfree(oc->oc_desc);
	charray_free(oc->oc_sup_oids);
	charray_free(oc->oc_at_oids_must);
	charray_free(oc->oc_at_oids_may);
	ldap_memfree(oc);
}

LDAP_OBJECT_CLASS *
ldap_str2objectclass( char * s, int * code, char ** errp )
{
	int kind;
	char * ss = s;
	char * sval;
	int seen_name = 0;
	int seen_desc = 0;
	int seen_obsolete = 0;
	int seen_sup = 0;
	int seen_kind = 0;
	int seen_must = 0;
	int seen_may = 0;
	LDAP_OBJECT_CLASS * oc;

	*errp = s;
	oc = calloc(1,sizeof(LDAP_OBJECT_CLASS));

	if ( !oc ) {
		*code = LDAP_SCHERR_OUTOFMEM;
		return NULL;
	}

	kind = get_token(&ss,&sval);
	if ( kind != TK_LEFTPAREN ) {
		*code = LDAP_SCHERR_NOLEFTPAREN;
		free_oc(oc);
		return NULL;
	}

	parse_whsp(&ss);
	oc->oc_oid = parse_numericoid(&ss,code);
	if ( !oc->oc_oid ) {
		*errp = ss;
		free_oc(oc);
		return NULL;
	}
	parse_whsp(&ss);

	/*
	 * Beyond this point we will be liberal an accept the items
	 * in any order.
	 */
	while (1) {
		kind = get_token(&ss,&sval);
		switch (kind) {
		case TK_EOS:
			*code = LDAP_SCHERR_NORIGHTPAREN;
			*errp = ss;
			free_oc(oc);
			return NULL;
		case TK_RIGHTPAREN:
			return oc;
		case TK_BAREWORD:
			if ( !strcmp(sval,"NAME") ) {
				if ( seen_name ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_name = 1;
				oc->oc_names = parse_qdescrs(&ss,code);
				if ( !oc->oc_names ) {
					if ( *code != LDAP_SCHERR_OUTOFMEM )
						*code = LDAP_SCHERR_BADNAME;
					*errp = ss;
					free_oc(oc);
					return NULL;
				}
			} else if ( !strcmp(sval,"DESC") ) {
				if ( seen_desc ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_desc = 1;
				parse_whsp(&ss);
				kind = get_token(&ss,&sval);
				if ( kind != TK_QDSTRING ) {
					*code = LDAP_SCHERR_UNEXPTOKEN;
					*errp = ss;
					free_oc(oc);
					return NULL;
				}
				oc->oc_desc = sval;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"OBSOLETE") ) {
				if ( seen_obsolete ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_obsolete = 1;
				oc->oc_obsolete = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"SUP") ) {
				if ( seen_sup ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_sup = 1;
				/* Netscape DS is broken or I have not
				   understood the syntax. */
				/* oc->oc_sup_oids = parse_oids(&ss,code); */
				oc->oc_sup_oids = parse_qdescrs(&ss,code);
				if ( !oc->oc_sup_oids ) {
					*errp = ss;
					free_oc(oc);
					return NULL;
				}
			} else if ( !strcmp(sval,"ABSTRACT") ) {
				if ( seen_kind ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_kind = 1;
				oc->oc_kind = 0;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"STRUCTURAL") ) {
				if ( seen_kind ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_kind = 1;
				oc->oc_kind = 1;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"AUXILIARY") ) {
				if ( seen_kind ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_kind = 1;
				oc->oc_kind = 2;
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"MUST") ) {
				if ( seen_must ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_must = 1;
				oc->oc_at_oids_must = parse_oids(&ss,code);
				if ( !oc->oc_at_oids_must ) {
					*errp = ss;
					free_oc(oc);
					return NULL;
				}
				parse_whsp(&ss);
			} else if ( !strcmp(sval,"MAY") ) {
				if ( seen_may ) {
					*code = LDAP_SCHERR_DUPOPT;
					*errp = ss;
					free_oc(oc);
					return(NULL);
				}
				seen_may = 1;
				oc->oc_at_oids_may = parse_oids(&ss,code);
				if ( !oc->oc_at_oids_may ) {
					*errp = ss;
					free_oc(oc);
					return NULL;
				}
				parse_whsp(&ss);
			} else {
				*code = LDAP_SCHERR_UNEXPTOKEN;
				*errp = ss;
				free_oc(oc);
				return NULL;
			}
			break;
		default:
			*code = LDAP_SCHERR_UNEXPTOKEN;
			*errp = ss;
			free_oc(oc);
			return NULL;
		}
	}
}

static char *err2text[] = {
	"",
	"Out of memory",
	"Unexpected token",
	"Missing opening parenthesis",
	"Missing closing parenthesis",
	"Expecting digit",
	"Expecting a name",
	"Bad description",
	"Bad superiors",
	"Duplicate option"
};

char *
ldap_scherr2str(int code)
{
	if ( code < 1 || code >= (sizeof(err2text)/sizeof(char *)) ) {
		return "Unknown error";
	} else {
		return err2text[code];
	}
}
