/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>
#include "ac/string.h"
#include "ac/ctype.h"
#include "ac/stdarg.h"
#include "slap.h"
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "back-sql.h"
#include "schema-map.h"
#include "util.h"

#define BACKSQL_MAX(a,b) ((a)>(b)?(a):(b))
#define BACKSQL_MIN(a,b) ((a)<(b)?(a):(b))

#define BACKSQL_STR_GROW 256

char backsql_def_oc_query[] = 
	"SELECT id,name,keytbl,keycol,create_proc,delete_proc,expect_return "
	"FROM ldap_oc_mappings";
char backsql_def_needs_select_oc_query[] = 
	"SELECT id,name,keytbl,keycol,create_proc,create_keyval,delete_proc,"
	"expect_return FROM ldap_oc_mappings";
char backsql_def_at_query[] = 
	"SELECT name,sel_expr,from_tbls,join_where,add_proc,delete_proc,"
	"param_order,expect_return,sel_expr_u FROM ldap_attr_mappings "
	"WHERE oc_map_id=?";
char backsql_def_delentry_query[] = "DELETE FROM ldap_entries WHERE id=?";
char backsql_def_insentry_query[] = 
	"INSERT INTO ldap_entries (dn,oc_map_id,parent,keyval) "
	"VALUES (?,?,?,?)";
char backsql_def_subtree_cond[] = "ldap_entries.dn LIKE CONCAT('%',?)";
char backsql_def_upper_subtree_cond[] = "(ldap_entries.dn) LIKE CONCAT('%',?)";
char backsql_id_query[] = "SELECT id,keyval,oc_map_id FROM ldap_entries WHERE ";
/* better ?||? or cast(?||? as varchar) */ 
char backsql_def_concat_func[] = "CONCAT(?,?)";

/* TimesTen */
char backsql_check_dn_ru_query[] = "SELECT dn_ru from ldap_entries";

struct berval *
backsql_strcat( struct berval *dest, ber_len_t *buflen, ... )
{
	va_list		strs;
	ber_len_t	cdlen, cslen, grow;
	char		*cstr;

	assert( dest );
	assert( dest->bv_val == NULL 
			|| dest->bv_len == strlen( dest->bv_val ) );
 
#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "==>backsql_strcat()\n" );
#endif /* BACKSQL_TRACE */

	va_start( strs, buflen );
	if ( dest->bv_val == NULL || *buflen == 0 ) {
		dest->bv_val = (char *)ch_calloc( BACKSQL_STR_GROW, 
				sizeof( char ) );
		dest->bv_len = 0;
		*buflen = BACKSQL_STR_GROW;
	}
	cdlen = dest->bv_len;
	while ( ( cstr = va_arg( strs, char * ) ) != NULL ) {
		cslen = strlen( cstr );
		grow = BACKSQL_MAX( BACKSQL_STR_GROW, cslen );
		if ( *buflen - cdlen <= cslen ) {
			char	*tmp_dest;

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, "backsql_strcat(): "
				"buflen=%d, cdlen=%d, cslen=%d "
				"-- reallocating dest\n",
				*buflen, cdlen + 1, cslen );
#endif /* BACKSQL_TRACE */

			tmp_dest = (char *)ch_realloc( dest->bv_val,
					( *buflen ) + grow * sizeof( char ) );
			if ( tmp_dest == NULL ) {
				Debug( LDAP_DEBUG_ANY, "backsql_strcat(): "
					"could not reallocate string buffer.\n",
					0, 0, 0 );
				return NULL;
			}
			dest->bv_val = tmp_dest;
			*buflen += grow;

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, "backsql_strcat(): "
				"new buflen=%d, dest=%p\n", *buflen, dest, 0 );
#endif /* BACKSQL_TRACE */
		}
		AC_MEMCPY( dest->bv_val + cdlen, cstr, cslen + 1 );
		cdlen += cslen;
	}
	va_end( strs );

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<==backsql_strcat() (dest='%s')\n", 
			dest, 0, 0 );
#endif /* BACKSQL_TRACE */

	dest->bv_len = cdlen;

	return dest;
} 

struct berval *
backsql_strfcat( struct berval *dest, ber_len_t *buflen, const char *fmt, ... )
{
	va_list		strs;
	ber_len_t	cdlen;

	assert( dest );
	assert( buflen );
	assert( fmt );
	assert( *buflen == 0 || *buflen > dest->bv_len );
	assert( dest->bv_val == NULL 
			|| dest->bv_len == strlen( dest->bv_val ) );
 
#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "==>backsql_strfcat()\n" );
#endif /* BACKSQL_TRACE */

	va_start( strs, fmt );
	if ( dest->bv_val == NULL || *buflen == 0 ) {
		dest->bv_val = (char *)ch_calloc( BACKSQL_STR_GROW, 
				sizeof( char ) );
		dest->bv_len = 0;
		*buflen = BACKSQL_STR_GROW;
	}

	cdlen = dest->bv_len;
	for ( ; fmt[0]; fmt++ ) {
		ber_len_t	cslen, grow;
		char		*cstr, cc[ 2 ] = { '\0', '\0' };
		struct berval	*cbv;

		switch ( fmt[ 0 ] ) {

		/* berval */
		case 'b':
			cbv = va_arg( strs, struct berval * );
			cstr = cbv->bv_val;
			cslen = cbv->bv_len;
			break;

		/* length + string */
		case 'l':
			cslen = va_arg( strs, ber_len_t );
			cstr = va_arg( strs, char * );
			break;
			
		/* string */
		case 's':
			cstr = va_arg( strs, char * );
			cslen = strlen( cstr );
			break;

		/* char */
		case 'c':
			/* 
			 * `char' is promoted to `int' when passed through `...'
			 */
			cc[0] = va_arg( strs, int );
			cstr = cc;
			cslen = 1;
			break;

		default:
			assert( 0 );
		}

		grow = BACKSQL_MAX( BACKSQL_STR_GROW, cslen );
		if ( *buflen - cdlen <= cslen ) {
			char	*tmp_dest;

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, "backsql_strfcat(): "
				"buflen=%d, cdlen=%d, cslen=%d "
				"-- reallocating dest\n",
				*buflen, cdlen + 1, cslen );
#endif /* BACKSQL_TRACE */

			tmp_dest = (char *)ch_realloc( dest->bv_val,
					( *buflen ) + grow * sizeof( char ) );
			if ( tmp_dest == NULL ) {
				Debug( LDAP_DEBUG_ANY, "backsql_strfcat(): "
					"could not reallocate string buffer.\n",
					0, 0, 0 );
				return NULL;
			}
			dest->bv_val = tmp_dest;
			*buflen += grow * sizeof( char );

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, "backsql_strfcat(): "
				"new buflen=%d, dest=%p\n", *buflen, dest, 0 );
#endif /* BACKSQL_TRACE */
		}

		assert( cstr );
		
		AC_MEMCPY( dest->bv_val + cdlen, cstr, cslen + 1 );
		cdlen += cslen;
	}

	va_end( strs );

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<==backsql_strfcat() (dest='%s')\n", 
			dest, 0, 0 );
#endif /* BACKSQL_TRACE */

	dest->bv_len = cdlen;

	return dest;
} 

int
backsql_entry_addattr(
	Entry		*e,
	struct berval	*at_name,
	struct berval	*at_val )
{
	AttributeDescription	*ad;
	int			rc;
	const char		*text;

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "backsql_entry_addattr(): "
		"at_name='%s', at_val='%s'\n", 
		at_name->bv_val, at_val->bv_val, 0 );
#endif /* BACKSQL_TRACE */

	ad = NULL;
	rc = slap_bv2ad( at_name, &ad, &text );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_entry_addattr(): "
			"failed to find AttributeDescription for '%s'\n",
			at_name->bv_val, 0, 0 );
		return 0;
	}

	rc = attr_merge_one( e, ad, at_val );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_entry_addattr(): "
			"failed to merge value '%s' for attribute '%s'\n",
			at_val->bv_val, at_name->bv_val, 0 );
		return 0;
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<==backsql_query_addattr()\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */

	return 1;
}

char *
backsql_get_table_spec( char **p )
{
	char		*s, *q;
	struct berval	res = BER_BVNULL;
	ber_len_t	res_len = 0;

	assert( p );
	assert( *p );

	s = *p;
	while ( **p && **p != ',' ) {
		(*p)++;
	}

	if ( **p ) {
		*(*p)++ = '\0';
	}
	
#define BACKSQL_NEXT_WORD { \
		while ( *s && isspace( (unsigned char)*s ) ) s++; \
		if ( !*s ) return res.bv_val; \
		q = s; \
		while ( *q && !isspace( (unsigned char)*q ) ) q++; \
		if ( *q ) *q++='\0'; \
	}

	BACKSQL_NEXT_WORD;
	/* table name */
	backsql_strcat( &res, &res_len, s, NULL );
	s = q;

	BACKSQL_NEXT_WORD;
	if ( !strcasecmp( s, "as" ) ) {
		s = q;
		BACKSQL_NEXT_WORD;
	}

#if 0
	backsql_strcat( &res, &res_len, " AS ", s, NULL );
	/* oracle doesn't understand AS :( */
#endif

	/* table alias */
	backsql_strfcat( &res, &res_len, "cs", ' ', s );

	return res.bv_val;
}

int
backsql_merge_from_clause( 
	struct berval	*dest_from,
	ber_len_t	*dest_len, 
	struct berval	*src_from )
{
	char		*s, *p, *srcc, *pos, e;
	struct berval	res = { 0 , NULL };

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "==>backsql_merge_from_clause(): "
		"dest_from='%s',src_from='%s'\n",
 		dest_from ? dest_from->bv_val : "<NULL>", src_from, 0 );
#endif /* BACKSQL_TRACE */

	srcc = ch_strdup( src_from->bv_val );
	p = srcc;

	if ( dest_from != NULL ) {
		res = *dest_from;
	}
	
	while ( *p ) {
		s = backsql_get_table_spec( &p );

#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, "backsql_merge_from_clause(): "
			"p='%s' s='%s'\n", p, s, 0 );
#endif /* BACKSQL_TRACE */

		if ( res.bv_val == NULL ) {
			backsql_strcat( &res, dest_len, s, NULL );

		} else {
			pos = strstr( res.bv_val, s );
			if ( pos == NULL ) {
				backsql_strfcat( &res, dest_len, "cs", ',', s );
			} else if ( ( e = pos[ strlen( s ) ] ) != '\0' && e != ',' ) {
				backsql_strfcat( &res, dest_len, "cs", ',', s );
			}
		}
		
		if ( s ) {
			ch_free( s );
		}
	}

#ifdef BACKSQL_TRACE
	Debug( LDAP_DEBUG_TRACE, "<==backsql_merge_from_clause()\n", 0, 0, 0 );
#endif /* BACKSQL_TRACE */

	free( srcc );
	*dest_from = res;

	return 1;
}

/*
 * splits a pattern in components separated by '?'
 * (double ?? are turned into single ? and left in the string)
 * expected contains the number of expected occurrences of '?'
 * (a negative value means parse as many as possible)
 */

int
backsql_split_pattern(
	const char	*_pattern,
	BerVarray	*split_pattern,
	int		expected )
{
	char		*pattern, *start, *end;
	struct berval	bv;
	int		rc = 0;

#define SPLIT_CHAR	'?'
	
	assert( _pattern );
	assert( split_pattern );

	pattern = ch_strdup( _pattern );

	start = pattern;
	end = strchr( start, SPLIT_CHAR );
	for ( ; start; expected-- ) {
		char		*real_end = end;
		ber_len_t	real_len;
		
		if ( real_end == NULL ) {
			real_end = start + strlen( start );

		} else if ( real_end[ 1 ] == SPLIT_CHAR ) {
			expected++;
			AC_MEMCPY( real_end, real_end + 1, strlen( real_end ) );
			end = strchr( real_end + 1, SPLIT_CHAR );
			continue;
		}

		real_len = real_end - start;
		if ( real_len == 0 ) {
			ber_str2bv( "", 0, 1, &bv );
		} else {
			ber_str2bv( start, real_len, 1, &bv );
		}

		ber_bvarray_add( split_pattern, &bv );

		if ( expected == 0 ) {
			if ( end != NULL ) {
				rc = -1;
				goto done;
			}
			break;
		}

		if ( end != NULL ) {
			start = end + 1;
			end = strchr( start, SPLIT_CHAR );
		}
	}

done:;

     	ch_free( pattern );

	return rc;
}

int
backsql_prepare_pattern(
	BerVarray	split_pattern,
	BerVarray	values,
	struct berval	*res )
{
	ber_len_t	len = 0;
	int		i;

	res->bv_val = NULL;
	res->bv_len = 0;

	for ( i = 0; values[i].bv_val; i++ ) {
		if ( split_pattern[i].bv_val == NULL ) {
			return -1;
		}
		backsql_strfcat( res, &len, "b", &split_pattern[ i ] );
		backsql_strfcat( res, &len, "b", &values[ i ] );
	}

	if ( split_pattern[ i ].bv_val == NULL ) {
		return -1;
	}

	backsql_strfcat( res, &len, "b", &split_pattern[ i ] );

	return 0;
}

#endif /* SLAPD_SQL */

