/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>		/* get SAFEMEMCPY */

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/modify.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>
extern IFP	merge_acl;

#include "lber.h"
#include "ldap.h"
#include "common.h"

static CommonArgs	common = default_common_args;

static int replace_mod( struct entrymod *, Attr_Sequence, Attr_Sequence );

#ifdef LDAP_COMPAT20
#define MODTAG	(ldap_compat == 20 ? OLD_LDAP_RES_MODIFY : LDAP_RES_MODIFY)
#else
#define MODTAG	LDAP_RES_MODIFY
#endif

int
do_modify(
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	char			*dn;
	char			*last;
	int			rc;
	unsigned long		tag, len;
	LDAPModList		*mods, *modtail;
	struct ds_read_arg	ra;

	Debug( LDAP_DEBUG_TRACE, "do_modify\n", 0, 0, 0 );

	/*
	 * Parse the modify request.  It looks like this:
	 *	ModifyRequest := [APPLICATION 6] SEQUENCE {
	 *		name	DistinguishedName,
	 *		mods	SEQUENCE OF SEQUENCE {
	 *			operation	ENUMERATED {
	 *				add	(0),
	 *				delete	(1),
	 *				replace	(2)
	 *			},
	 *			modification	SEQUENCE {
	 *				type	AttributeType,
	 *				values	SET OF AttributeValue
	 *			}
	 *		}
	 *	}
	 * We then have to initiate a read of the entry to be modified.
	 * The actual modification is done by do_modify2(), after the
	 * read completes.
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_ReadArgument_INIT( &ra );
#endif
#endif

	if ( ber_scanf( ber, "{a", &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, MODTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn, 0, 0 );

	ra.rda_object = ldap_str2dn( dn );
	free( dn );
	if ( ra.rda_object == NULLDN ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, MODTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}
	ra.rda_eis.eis_allattributes = TRUE;
	ra.rda_eis.eis_infotypes = EIS_ATTRIBUTESANDVALUES;
	ra.rda_eis.eis_select = NULLATTR;

	/* collect modifications & save for later */
	mods = modtail = NULL;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) ) {
		LDAPModList	*tmp;

		if ( (tmp = (LDAPModList *) calloc( 1, sizeof(LDAPModList) ))
		    == NULL ) {
			send_ldap_msgresult( clientsb, MODTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "Malloc error" );
			return( 0 );
		}
			
		if ( ber_scanf( ber, "{i{a[V]}}", &tmp->m.mod_op,
		    &tmp->m.mod_type, &tmp->m.mod_bvalues ) == LBER_ERROR ) {
			send_ldap_msgresult( clientsb, MODTAG, m,
			    LDAP_PROTOCOL_ERROR, NULL, "" );
			return( 0 );
		}

		if ( mods == NULL ) {
			mods = tmp;
		} else {
			modtail->mod_next = tmp;
		}
		modtail = tmp;
	}
	m->m_mods = mods;

	ra.rda_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_READ, m, &ra );

	dn_free( ra.rda_object );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, MODTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

int
do_modify2(
    Sockbuf			*clientsb,
    struct msg			*m,
    struct ds_read_result	*rr
)
{
	struct ds_modifyentry_arg	ma;
	struct entrymod			*changetail = NULLMOD;
	int				rc;
	LDAPModList			*mods;

	Debug( LDAP_DEBUG_TRACE, "do_modify2\n", 0, 0, 0 );

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_ModifyEntryArgument_INIT( &ma );
#endif
#endif

	ma.mea_changes = NULLMOD;
	for ( mods = m->m_mods; mods != NULL; mods = mods->mod_next ) {
		struct entrymod	*em;
		Attr_Sequence	as, new;

		if ( (em = (struct entrymod *) calloc( 1,
		    sizeof(struct entrymod) )) == NULLMOD ) {
			send_ldap_msgresult( clientsb, MODTAG, m,
			    LDAP_OPERATIONS_ERROR, NULL, "Malloc error" );
			return( 0 );
		}
		em->em_next = NULLMOD;

		if ( (new = get_as( clientsb, MODTAG, m,
		    mods->m.mod_type, mods->m.mod_bvalues )) == NULLATTR )
			return( 0 );
		em->em_what = new;

		for ( as = rr->rdr_entry.ent_attr; as != NULLATTR;
		    as = as->attr_link ) {
			if ( AttrT_cmp( new->attr_type, as->attr_type ) == 0 )
				break;
		}

		if ( new->attr_value == NULLAV &&
		    mods->m.mod_op != LDAP_MOD_DELETE ) {
			send_ldap_msgresult( clientsb, MODTAG, m,
			    LDAP_INVALID_SYNTAX, NULL, "No values specified" );
			return( 0 );
		}

		switch ( mods->m.mod_op ) {
		case LDAP_MOD_ADD:
			Debug( LDAP_DEBUG_ARGS, "ADD:\n", 0, 0, 0 );

			if ( as == NULLATTR ) {
				Debug( LDAP_DEBUG_ARGS, "\tattribute\n", 0, 0,
				    0 );
				em->em_type = EM_ADDATTRIBUTE;
			} else {
				Debug( LDAP_DEBUG_ARGS, "\tvalues\n", 0, 0, 0 );
				em->em_type = EM_ADDVALUES;
			}
			break;

		case LDAP_MOD_DELETE:
			Debug( LDAP_DEBUG_ARGS, "DELETE:\n", 0, 0, 0 );

			if ( as == NULLATTR ) {
				Debug( LDAP_DEBUG_ARGS,
				    "\tno existing attribute\n", 0, 0, 0 );
				send_ldap_msgresult( clientsb, MODTAG,
				    m, LDAP_NO_SUCH_ATTRIBUTE, NULL, "" );
				ems_free( em );
				return( 0 );
			} else {
				if ( new->attr_value == NULLAV ) {
					Debug( LDAP_DEBUG_ARGS, "\tattribute\n",
					    0, 0, 0 );
					em->em_type = EM_REMOVEATTRIBUTE;
				} else {
					if ( avs_cmp( new->attr_value,
					    as->attr_value ) == 0 ) {
						Debug( LDAP_DEBUG_ARGS,
						    "\tattribute\n", 0, 0, 0 );
						em->em_type =
						    EM_REMOVEATTRIBUTE;
					} else {
						Debug( LDAP_DEBUG_ARGS,
						    "\tvalues\n", 0, 0, 0 );
						em->em_type = EM_REMOVEVALUES;
					}
				}
			}
			break;

		case LDAP_MOD_REPLACE:
			Debug( LDAP_DEBUG_ARGS, "REPLACE:\n", 0, 0, 0 );

			if ( as == NULLATTR ) {
				Debug( LDAP_DEBUG_ARGS, "\tattribute\n", 0, 0,
				    0 );
				em->em_type = EM_ADDATTRIBUTE;
			} else {
				if ( replace_mod( em, as, new ) < 0 ) {
					return( 0 );
				}
			}
			break;

		default:
			Debug( LDAP_DEBUG_ARGS, "UNKNOWN MOD:\n", 0, 0, 0 );

			send_ldap_msgresult( clientsb, MODTAG, m,
			    LDAP_PROTOCOL_ERROR, NULL, "" );
			return( 0 );
			break;
		}

		if ( em->em_what == NULL ) {	/* ignore this mod */
			free( em );
		} else {
			if ( ma.mea_changes == NULLMOD ) {
				ma.mea_changes = em;
			} else {
				changetail->em_next = em;
			}
			changetail = em->em_next == NULLMOD ? em : em->em_next;
		}
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_ARGS ) {
                struct entrymod *e;
                Attr_Sequence   as;
                AV_Sequence     val;
		PS		ps;

		ps = ps_alloc( std_open );
		std_setup( ps, stderr );

                fprintf( stderr, "Modify changes are:\n");
                for (e = ma.mea_changes; e; e = e->em_next) {
                        switch (e->em_type) {
                        case EM_ADDATTRIBUTE:
                                fprintf( stderr, "\tADD ATTRIBUTE\n");
                                break;
                        case EM_REMOVEATTRIBUTE:
                                fprintf( stderr, "\tREMOVE ATTRIBUTE\n");
                                break;
                        case EM_ADDVALUES:
                                fprintf( stderr, "\tADD VALUES\n");
                                break;
                        case EM_REMOVEVALUES:
                                fprintf( stderr, "\tREMOVE VALUES\n");
                                break;
                        default:
                                fprintf( stderr, "\tUNKNOWN\n");
                                break;
                        }

                        as = e->em_what;
                        fprintf( stderr, "\t\ttype (" );
			AttrT_print( ps, as->attr_type, EDBOUT );
			fprintf( stderr, ")" );
                        if ( e->em_type == EM_REMOVEATTRIBUTE ) {
                                fprintf( stderr, "\n" );
                                continue;
                        }
                        fprintf( stderr, " values" );
                        for (val = as->attr_value; val; val = val->avseq_next) {
                                ps_print( ps, " (" );
				AttrV_print( ps, &val->avseq_av, EDBOUT );
				ps_print( ps, ")" );
			}
                        fprintf( stderr, "\n" );
                }
		ps_free( ps );
	}
#endif

	if ( ma.mea_changes == NULLMOD ) {	/* nothing to do */
		send_ldap_msgresult( clientsb, MODTAG, m,
		    LDAP_SUCCESS, NULL, "" );
		return( 0 );
	}

	ma.mea_object = rr->rdr_entry.ent_dn;
	ma.mea_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_MODIFYENTRY, m, &ma );

	ems_free( ma.mea_changes );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, MODTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

Attr_Sequence
get_as(
    Sockbuf		*clientsb,
    unsigned long	op,
    struct msg		*m,
    char		*type,
    struct berval	**bvals
)
{
	Attr_Sequence	as;
	int		i;
	short		syntax;

	Debug( LDAP_DEBUG_TRACE, "get_as\n", 0, 0, 0 );

	if ( (as = as_comp_new( NULLAttrT, NULLAV, NULLACL_INFO ))
	    == NULLATTR ) {
		send_ldap_msgresult( clientsb, op, m,
		    LDAP_OPERATIONS_ERROR, NULL, "Malloc error" );
		return( NULLATTR );
	}
	as->attr_link = NULLATTR;
	as->attr_value = NULLAV;
	as->attr_acl = NULLACL_INFO;

	if ( (as->attr_type = str2AttrT( type )) == NULLAttrT ) {
              send_ldap_msgresult( clientsb, op, m, LDAP_UNDEFINED_TYPE,
                  NULL, type );
		return( NULLATTR );
	}

	if ( bvals == NULL )
		return( as );

	syntax = as->attr_type->oa_syntax;
	for ( i = 0; bvals[i] != NULL; i++ ) {
		AttributeValue	av;
		int		t61str, ncomp;
		char		*sval, *s, *news, *n;

		if ( syntax == ldap_jpeg_syntax ||
		    syntax == ldap_jpeg_nonfile_syntax ||
		    syntax == ldap_octetstring_syntax ||
		    syntax == ldap_audio_syntax ) {
			if (( av = bv_octet2AttrV( bvals[i] )) == NULLAttrV ) {
				send_ldap_msgresult( clientsb, op, m,
				    LDAP_INVALID_SYNTAX, NULL, type );
				as_free( as );
				return( NULLATTR );
			}
		} else if ( syntax == ldap_photo_syntax ) {
			if (( av = bv_asn2AttrV( bvals[i] )) == NULLAttrV ) {
				send_ldap_msgresult( clientsb, op, m,
				    LDAP_INVALID_SYNTAX, NULL, type );
				as_free( as );
				return( NULLATTR );
			}
		} else {

			if (( sval = malloc( bvals[i]->bv_len + 1 )) == NULL ) {
				send_ldap_msgresult( clientsb, op, m,
				    LDAP_OPERATIONS_ERROR, NULL,
                                  "Malloc error" );
				return( NULLATTR );
			}
			SAFEMEMCPY( sval, bvals[i]->bv_val, bvals[i]->bv_len );
			sval[ bvals[i]->bv_len ] = '\0';

			/* dang quipu - there's no need for this! */
			if ( syntax == ldap_postaladdress_syntax ) {
				t61str = 0;
				ncomp = 1;
				for ( s = sval; *s; s++ ) {
					if ( *s == '$' ) {
						ncomp++;
						continue;
					}
#define ist61(c)  (!isascii(c) || !isalnum(c) \
			  && c != 047 && c != '(' && c != ')' \
			  && c != '+' && c != '-' && c != '.' && c != ',' \
			  && c != '/' && c != ':' && c != '=' && c != '?' \
			  && c != ' ')
					if ( ist61( *s ) )
						t61str = 1;
				}
#define T61MARK		"{T.61}"
#define T61MARKLEN	6
				if ( t61str ) {
					news = malloc( strlen(sval) +
					    ncomp * T61MARKLEN + 1 );
					strcpy( news, T61MARK );
					for ( n = news + T61MARKLEN, s = sval;
					    *s; n++, s++ ) {
						*n = *s;
						if ( *s == '$' ) {
							strcpy( ++n, T61MARK );
							n += T61MARKLEN - 1;
						}
					}
					*n = '\0';
					free( sval );
					sval = news;
				}

				av = str_at2AttrV( sval, as->attr_type );
			} else if ( syntax == ldap_dn_syntax ) {
				av = ldap_strdn2AttrV( sval );
			} else if ( i != 0 && syntax == ldap_acl_syntax ) {
				(void) (*merge_acl)( as->attr_value, sval );
				free( sval );
				continue;
			} else {
				av = ldap_str_at2AttrV( sval, as->attr_type );
			}

			if ( av == NULLAttrV ) {
				send_ldap_msgresult( clientsb, op, m,
				    LDAP_INVALID_SYNTAX, NULL, sval );
				free( sval );
				as_free( as );
				return( NULLATTR );
			}

			free( sval );
		}
		as->attr_value = avs_merge( as->attr_value,
		    avs_comp_new( av ) );
	}

	return( as );
}

void
modify_result( Sockbuf *sb, struct msg *m )
{
	send_ldap_msgresult( sb, MODTAG, m, LDAP_SUCCESS, NULL, "" );

	return;
}

void
modlist_free( LDAPModList *mods )
{
	LDAPModList	*next;

	for ( ; mods != NULL; mods = next ) {
		free( mods->m.mod_type );
		if ( mods->m.mod_bvalues != NULL )
			ber_bvecfree( mods->m.mod_bvalues );
		next = mods->mod_next;
		free( mods );
	}
}

/*
 * called when mod is replace to optimize by only deleting old values
 * that are not in the new set and by only adding what isn't in old set
 */

static int
replace_mod(
    struct entrymod	*rem,
    Attr_Sequence	oas,
    Attr_Sequence	nas
)
{
	AV_Sequence	oavs, navs, davs, prev_navs, tmp;
#ifdef LDAP_DEBUG
	PS		ps;

	ps = ps_alloc( std_open );
	std_setup( ps, stderr );

	if ( ldap_debug & LDAP_DEBUG_ARGS ) {
		ps_print( ps, "replace_mod(" );
		AttrT_print( ps, oas->attr_type, EDBOUT );
		ps_print( ps, ")\n" );
	}
#endif

	davs = NULL;
	for ( oavs = oas->attr_value; oavs != NULL; oavs = oavs->avseq_next ) {
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_ARGS ) {
			ps_print( ps, "old value " );
			AttrV_print( ps, &oavs->avseq_av, EDBOUT );
			ps_print( ps, "\n" );
		}
#endif

		prev_navs = NULL;
		for ( navs = nas->attr_value; navs != NULL;
		    prev_navs = navs, navs = navs->avseq_next ) {
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				ps_print( ps, "\tnew value " );
				AttrV_print( ps, &navs->avseq_av, EDBOUT );
				ps_print( ps, "\n" );
			}
#endif
			if ( AttrV_cmp( &oavs->avseq_av, &navs->avseq_av)
			    == 0) {
				break;
			}
		}

		if ( navs == NULL ) {	/* value to delete */
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				ps_print( ps, "value to delete " );
				AttrV_print( ps, &oavs->avseq_av, EDBOUT );
				ps_print( ps, "\n" );
			}
#endif
			if ( davs == NULL ) {
			    davs = avs_comp_cpy( oavs );
			} else {
			    tmp = avs_comp_cpy( oavs );
			    tmp->avseq_next = davs;
			    davs = tmp;
			}
		} else {		/* value to keep */
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				ps_print( ps, "value to leave alone " );
				AttrV_print( ps, &oavs->avseq_av, EDBOUT );
				ps_print( ps, "\n" );
			}
#endif
			if ( prev_navs == NULL ) {
			    nas->attr_value = navs->avseq_next;
			} else {
			    prev_navs->avseq_next = navs->avseq_next;
			}
			avs_comp_free( navs );
		}
	}

	if ( davs == NULL && nas->attr_value == NULL ) {
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_ARGS ) {
			ps_print( ps, "  nothing to do" );
		}
#endif
		rem->em_what = NULL;
	} else {
            /*  Must add new values before removing old values.
             *  Otherwise, removing all existing values causes the
             *  attribute to be removed such that subsequent add values
             *  fail.
             */
		if ( nas->attr_value != NULL ) {	/* add new values */
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				AttrT_print( ps, nas->attr_type, EDBOUT );
				ps_print( ps, ": some to add\n" );
			}
#endif
			rem->em_type = EM_ADDVALUES;
			rem->em_what = nas;
			rem->em_next = NULLMOD;
		}

		if ( davs != NULL ) {	/* delete old values */
#ifdef LDAP_DEBUG
			if ( ldap_debug & LDAP_DEBUG_ARGS ) {
				AttrT_print( ps, nas->attr_type, EDBOUT );
				ps_print( ps, ": some to delete\n" );
			}
#endif
			if ( nas->attr_value != NULL ) {
				rem->em_next = (struct entrymod *) calloc( 1,
				    sizeof(struct entrymod) );
				rem = rem->em_next;
			}
			rem->em_type = EM_REMOVEVALUES;
			rem->em_what = as_comp_new( NULLAttrT, NULLAV,
			    NULLACL_INFO );
			rem->em_what->attr_type = AttrT_cpy( nas->attr_type );
			rem->em_what->attr_value = davs;
		}
	}

	return( 0 );
}
