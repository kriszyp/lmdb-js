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
#include "config.h"

/*
 * This overlay limits the values which can be placed into an
 * attribute, over and above the limits placed by the schema.
 *
 * It traps only LDAP adds and modify commands (and only seeks to
 * control the add and modify value mods of a modify)
 */

#define REGEX_STR "regex"

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
    char *re_str; /* string representation of regex */
} constraint;

enum {
    CONSTRAINT_ATTRIBUTE = 1
};

static ConfigDriver constraint_cf_gen;

static ConfigTable constraintcfg[] = {
    { "constraint_attribute", "attribute regex <regular expression>",
      4, 4, 0, ARG_MAGIC | CONSTRAINT_ATTRIBUTE, constraint_cf_gen,
      "( OLcfgOvAt:13.1 NAME 'olcConstraintAttribute' "
      "DESC 'regular expression constraint for attribute' "
	  "EQUALITY caseIgnoreMatch "
      "SYNTAX OMsDirectoryString )", NULL, NULL },
    { NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs constraintocs[] = {
    { "( OLcfgOvOc:13.1 "
      "NAME 'olcConstraintConfig' "
      "DESC 'Constraint overlay configuration' "
      "SUP olcOverlayConfig "
      "MAY ( olcConstraintAttribute ) )",
      Cft_Overlay, constraintcfg },
    { NULL, 0, NULL }
};

static int
constraint_cf_gen( ConfigArgs *c )
{
    slap_overinst *on = (slap_overinst *)(c->bi);
    constraint *cn = on->on_bi.bi_private, *cp;
    struct berval bv;
    int i, rc = 0;
    constraint ap = { NULL, NULL, NULL  }, *a2 = NULL;
    const char *text = NULL;
    
    switch ( c->op ) {
        case SLAP_CONFIG_EMIT:
            switch (c->type) {
                case CONSTRAINT_ATTRIBUTE:
                    for (cp=cn; cp; cp=cp->ap_next) {
                        int len;
                        char *s;
                        
                        len = cp->ap->ad_cname.bv_len +
                            strlen( REGEX_STR ) + strlen( cp->re_str) + 3;
                        s = ch_malloc(len);
                        if (!s) continue;
                        snprintf(s, len, "%s %s %s", cp->ap->ad_cname.bv_val,
                                 REGEX_STR, cp->re_str);
                        bv.bv_val = s;
                        bv.bv_len = strlen(s);
                        rc = value_add_one( &c->rvalue_vals, &bv );
                        if (rc) return rc;
                        rc = value_add_one( &c->rvalue_nvals, &bv );
                        if (rc) return rc;
                        ch_free(s);
                    }
                    break;
                default:
                    abort();
                    break;
            }
            break;
        case LDAP_MOD_DELETE:
            switch (c->type) {
                case CONSTRAINT_ATTRIBUTE:
                    if (!cn) break; /* nothing to do */
                    
                    if (c->valx < 0) {
                            /* zap all constraints */
                        while (cn) {
                            cp = cn->ap_next;
                            if (cn->re) {
                                regfree(cn->re);
                                ch_free(cn->re);
                            }
                            if (cn->re_str) ch_free(cn->re_str);
                            ch_free(cn);
                            cn = cp;
                        }
                        
                        on->on_bi.bi_private = NULL;
                    } else {
                        constraint **cpp;
                        
                            /* zap constraint numbered 'valx' */
                        for(i=0, cp = cn, cpp = &cn;
                            (cp) && (i<c->valx);
                            i++, cpp = &cp->ap_next, cp = *cpp);

                        if (cp) {
                                /* zap cp, and join cpp to cp->ap_next */
                            *cpp = cp->ap_next;
                            if (cp->re) {
                                regfree(cp->re);
                                ch_free(cp->re);
                            }
                            if (cp->re_str) ch_free(cp->re_str);
                            ch_free(cp);
                        }
                        on->on_bi.bi_private = cn;
                    }
                    
                    break;
                default:
                    abort();
                    break;
            }
            break;
        case SLAP_CONFIG_ADD:
        case LDAP_MOD_ADD:
            switch (c->type) {
                case CONSTRAINT_ATTRIBUTE:
                    if ( slap_str2ad( c->argv[1], &ap.ap, &text ) ) {
						snprintf( c->msg, sizeof( c->msg ),
							"%s <%s>: %s\n", c->argv[0], c->argv[1], text );
                        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE,
                               "%s: %s\n", c->log, c->msg, 0 );
                        return( ARG_BAD_CONF );
                    }

                    if ( strcasecmp( c->argv[2], "regex" ) == 0) {
                        int err;
            
                        ap.re = ch_malloc( sizeof(regex_t) );
                        if ((err = regcomp( ap.re,
                                            c->argv[3], REG_EXTENDED )) != 0) {
                            char errmsg[1024];
                            
                            regerror( err, ap.re, errmsg, sizeof(errmsg) );
                            ch_free(ap.re);
							snprintf( c->msg, sizeof( c->msg ),
                                   "%s %s: Illegal regular expression \"%s\": Error %s",
                                   c->argv[0], c->argv[1], c->argv[3], errmsg);
                            Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE,
									"%s: %s\n", c->log, c->msg, 0 );
                            ap.re = NULL;
                            return( ARG_BAD_CONF );
                        }
                        ap.re_str = ch_strdup( c->argv[3] );
                    } else {
						snprintf( c->msg, sizeof( c->msg ),
                               "%s %s: Unknown constraint type: %s",
                               c->argv[0], c->argv[1], c->argv[2] );
                        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE,
                               "%s: %s\n", c->log, c->msg, 0 );
                        return ( ARG_BAD_CONF );
                    }
                    

                    a2 = ch_malloc( sizeof(constraint) );
                    a2->ap_next = on->on_bi.bi_private;
                    a2->ap = ap.ap;
                    a2->re = ap.re;
                    a2->re_str = ap.re_str;
                    on->on_bi.bi_private = a2;
                    break;
                default:
                    abort();
                    break;
            }
            break;
        default:
            abort();
    }

    return rc;
}

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

static int
constraint_close(
    BackendDB *be
    )
{
    slap_overinst *on = (slap_overinst *) be->bd_info;
    constraint *ap, *a2;

    for ( ap = on->on_bi.bi_private; ap; ap = a2 ) {
        a2 = ap->ap_next;
        if (ap->re_str) ch_free(ap->re_str);
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

#if SLAPD_OVER_CONSTRAINT == SLAPD_MOD_DYNAMIC
static
#endif
int
constraint_initialize( void ) {
    int rc;

    constraint_ovl.on_bi.bi_type = "constraint";
    constraint_ovl.on_bi.bi_db_close = constraint_close;
    constraint_ovl.on_bi.bi_op_add = constraint_add;
    constraint_ovl.on_bi.bi_op_modify = constraint_modify;

    constraint_ovl.on_bi.bi_private = NULL;
    
    constraint_ovl.on_bi.bi_cf_ocs = constraintocs;
    rc = config_register_schema( constraintcfg, constraintocs );
    if (rc) return rc;
    
    return overlay_register( &constraint_ovl );
}

#if SLAPD_OVER_CONSTRAINT == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
    return constraint_initialize();
}
#endif

#endif /* defined(SLAPD_OVER_CONSTRAINT) */

