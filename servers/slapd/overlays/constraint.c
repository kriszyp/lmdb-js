/* constraint.c - Overlay to constrain attributes to certain values */
/* 
 *
 * Copyright 2003-2004 Hewlett-Packard Company
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/*
 * Author: Neil Dunbar <neil.dunbar@hp.com>
 */
#include "portable.h"

#ifdef SLAPD_OVER_CONSTRAINT

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/regex.h>

#include "slap.h"

/*
 * This overlay limits the values which can be placed into an
 * attribute, over and above the limits placed by the schema.
 *
 * It traps only LDAP adds and modify commands (and only seeks to
 * control the add and modify value mods of a modify)
 */

/*
 * Linked list of attribute constraints which we should enforce.
 * This is probably a sub optimal structure - some form of sorted
 * array would be better if the number of attributes contrained is
 * likely to be much bigger than 4 or 5. We stick with a list for
 * the moment.
 */
typedef struct constraint {
    struct constraint *ap_next;
    AttributeDescription *ap;
    regex_t *re;
} constraint;

static int
constraint_violation( constraint *c, struct berval *bv )
{
    if ((!c) || (!bv)) return 0;
    
    if ((c->re) &&
        (regexec(c->re, bv->bv_val, 0, NULL, 0) == REG_NOMATCH))
        
        return 1; /* regular expression violation */
    
    return 0;
}

static char *
print_message( const char *fmt, AttributeDescription *a )
{
    char *ret;
    int sz;
    
    sz = strlen(fmt) + a->ad_cname.bv_len + 1;
    ret = ch_malloc(sz);
    snprintf( ret, sz, fmt, a->ad_cname.bv_val );
    return ret;
}

static int
constraint_add( Operation *op, SlapReply *rs )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    Attribute *a;
    constraint *c = on->on_bi.bi_private, *cp;
    BerVarray b = NULL;
    int i;
    const char *rsv = "add breaks regular expression constraint on %s";
    char *msg;
    
    if ((a = op->ora_e->e_attrs) == NULL) {
        op->o_bd->bd_info = (BackendInfo *)(on->on_info);
        send_ldap_error(op, rs, LDAP_INVALID_SYNTAX,
                        "constraint_add() got null op.ora_e.e_attrs");
        return(rs->sr_err);
    }

    for(; a; a = a->a_next ) {
            /* we don't constrain operational attributes */
    
        if (is_at_operational(a->a_desc->ad_type)) continue;
        
        for(cp = c; cp; cp = cp->ap_next) {
            if (cp->ap != a->a_desc) continue;
            if ((b = a->a_vals) == NULL) continue;
                
            for(i=0; b[i].bv_val; i++) {
                int cv = constraint_violation( cp, &b[i]);
                    
                if (cv) {
                        /* regex violation */
                    op->o_bd->bd_info = (BackendInfo *)(on->on_info);
                    msg = print_message( rsv, a->a_desc );
                    send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION, msg );
                    ch_free(msg);
                    return (rs->sr_err);
                }
            }
        }
    }
	/* Default is to just fall through to the normal processing */
    return SLAP_CB_CONTINUE;
}

static int
constraint_modify( Operation *op, SlapReply *rs )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    constraint *c = on->on_bi.bi_private, *cp;
    Modifications *m;
    BerVarray b = NULL;
    int i;
    const char *rsv = "modify breaks regular expression constraint on %s";
    char *msg;
    
    if ((m = op->orm_modlist) == NULL) {
        op->o_bd->bd_info = (BackendInfo *)(on->on_info);
        send_ldap_error(op, rs, LDAP_INVALID_SYNTAX,
                        "constraint_modify() got null orm_modlist");
        return(rs->sr_err);
    }

    for(;m; m = m->sml_next) {
        if (is_at_operational( m->sml_desc->ad_type )) continue;
        if ((( m->sml_op & LDAP_MOD_OP ) != LDAP_MOD_ADD) &&
            (( m->sml_op & LDAP_MOD_OP ) != LDAP_MOD_REPLACE))
            continue;
            /* we only care about ADD and REPLACE modifications */
        if ((( b = m->sml_values ) == NULL ) || (b[0].bv_val == NULL))
            continue;

        for(cp = c; cp; cp = cp->ap_next) {
            if (cp->ap != m->sml_desc) continue;
            
            for(i=0; b[i].bv_val; i++) {
                int cv = constraint_violation( cp, &b[i]);
                
                if (cv) {
                        /* regex violation */
                    op->o_bd->bd_info = (BackendInfo *)(on->on_info);
                    msg = print_message( rsv, m->sml_desc );
                    send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION, msg );
                    ch_free(msg);
                    return (rs->sr_err);
                }
            }
        }
    }
    
    return SLAP_CB_CONTINUE;
}

static int constraint_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
    )
{
    slap_overinst *on = (slap_overinst *) be->bd_info;
    constraint ap = { NULL, NULL, NULL  }, *a2 = NULL;
    regmatch_t rm[2];
    
    if ( strcasecmp( argv[0], "constraint_attribute" ) == 0 ) {
        const char *text;
                
        if ( argc != 4 ) {
            Debug( LDAP_DEBUG_ANY, "%s: line %d: "
                   "wrong number of parameters in"
                   "\"constraint_attribute <attribute> <constraint> <constraint_value>\" line.\n",
                   fname, lineno, 0 );
            return( 1 );
        }
        if ( slap_str2ad( argv[1], &ap.ap, &text ) ) {
            Debug( LDAP_DEBUG_ANY, "%s: line %d: "
                   "attribute description unknown \"constraint_attribute\" line: %s.\n",
                   fname, lineno, text );
            return( 1 );
        }

        if ( strcasecmp( argv[2], "regex" ) == 0) {
            int err;
            
            ap.re = ch_malloc( sizeof(regex_t) );
            if ((err = regcomp( ap.re, argv[3], REG_EXTENDED )) != 0) {
                const char *fmt = "%s: line %d: Illegal regular expression \"%s\": Error %s\n";
                char errmsg[1024], *msg;
                int i, l, msgsize;
                
                msgsize = regerror( err, ap.re, errmsg, sizeof(errmsg) );
                msgsize += strlen(fmt) + strlen(argv[3]) + strlen(fname);
                for(l=lineno; l>0; l/=10, msgsize++);
                msgsize++;

                msg = ch_malloc( msgsize + 1 );
                snprintf( msg, msgsize, fmt, fname, lineno, argv[3], errmsg );
                ch_free(ap.re);
                Debug( LDAP_DEBUG_ANY, msg, 0, 0, 0);
                ch_free(msg);
                ap.re = NULL;
                return(1);
            }
        } else
            Debug( LDAP_DEBUG_ANY, "%s: line %d: "
                   "Unknown constraint type: %s",
                   fname, lineno, argv[2] );
        

        a2 = ch_malloc( sizeof(constraint) );
        a2->ap_next = on->on_bi.bi_private;
        a2->ap = ap.ap;
        a2->re = ap.re;
        on->on_bi.bi_private = a2;
    } else {
        return SLAP_CONF_UNKNOWN;
    }
    
    return 0;
}

static int
constraint_close(
    BackendDB *be
    )
{
    slap_overinst *on = (slap_overinst *) be->bd_info;
    constraint *ap, *a2;

    for ( ap = on->on_bi.bi_private; ap; ap = a2 ) {
        a2 = ap->ap_next;
        if (ap->re) {
            regfree( ap->re );
            ch_free( ap->re );
        }
        
        ch_free( ap );
    }

    return 0;
}

static slap_overinst constraint_ovl;

/* This overlay is set up for dynamic loading via moduleload. For static
 * configuration, you'll need to arrange for the slap_overinst to be
 * initialized and registered by some other function inside slapd.
 */

int constraint_init() {
    constraint_ovl.on_bi.bi_type = "constraint";
    constraint_ovl.on_bi.bi_db_config = constraint_config;
    constraint_ovl.on_bi.bi_db_close = constraint_close;
    constraint_ovl.on_bi.bi_op_add = constraint_add;
    constraint_ovl.on_bi.bi_op_modify = constraint_modify;

    return overlay_register( &constraint_ovl );
}

#if SLAPD_OVER_CONSTRAINT == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
    return constraint_init();
}
#endif

#endif /* defined(SLAPD_OVER_CONSTRAINT) */

