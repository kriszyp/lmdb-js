/* $OpenLDAP$ */
/*
 * certificate.c - ldap version of quipu certificate syntax handler
 *		   donated by Eric Rosenquist and BNR
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/ds_search.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>
extern sntx_table *get_syntax_table( short int sntx );
extern PE asn2pe( char * );

#include "lber.h"
#include "ldap.h"
#include "common.h"

int
ldap_certif_print( PS ps, struct certificate *parm, int format )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_certif_print()\n", 0, 0, 0 );

/*
 *	An ldap certificate looks like this:
 *
 *	<certificate> ::= <version> '#' <serial> '#' <signature-algorithm-id>
 *		     '#' <issuer> '#' <validity> '#' <subject>
 *		     '#' <public-key-info> '#' <encrypted-sign-value>
 *	<version> ::= <integervalue>
 *	<serial> ::= <integervalue>
 *	<signature-algorithm-id> ::= <algorithm-id>
 *	<issuer> ::= an encoded Distinguished Name
 *	<validity> ::= <not-before-time> '#' <not-after-time>
 *	<not-before-time> ::= <utc-time>
 *	<not-after-time> ::= <utc-time>
 *	<algorithm-parameters> ::=  <null> | <integervalue> |
 *				 '{ASN}' <hex-string>
 *	<subject> ::= an encoded Distinguished Name
 *	<public-key-info> ::= <algorithm-id> '#' <encrypted-sign-value>
 *	<encrypted-sign-value> ::= <hex-string> | <hex-string> '-' <d>
 *	<algorithm-id> ::= <oid> '#' <algorithm-parameters>
 *	<utc-time> ::= an encoded UTCTime value
 *	<hex-string> ::= <hex-digit> | <hex-digit> <hex-string>
 */

        ps_printf(ps, "%d#%d#", parm->version, parm->serial);

        ldap_print_algid(ps, &(parm->sig.alg), format);

        dn_print_real(ps, parm->issuer, format);
        ps_printf(ps, "#");

        utcprint(ps, parm->valid.not_before, format);
        ps_printf(ps, "#");
        utcprint(ps, parm->valid.not_after, format);
        ps_printf(ps, "#");

        dn_print_real(ps, parm->subject, format);
        ps_printf(ps, "#");

        ldap_print_algid(ps, &(parm->key.alg), format);
        print_encrypted(ps, parm->key.value, parm->key.n_bits, format);

        print_encrypted(ps, parm->sig.encrypted, parm->sig.n_bits, format);
}

void
ldap_print_algid( PS ps, struct alg_id *parm, int format )
{
  ps_printf(ps, "%s#", oid2name (parm->algorithm, OIDPART));

  switch(parm->p_type) {
     case ALG_PARM_ABSENT:
       if(parm->asn != NULLPE)
             pe_print(ps, parm->asn, format);
       ps_printf(ps, "#");
       break;
     case ALG_PARM_NUMERIC:
       if (format == READOUT)
         ps_printf(ps, "%d#", parm->un.numeric);
       else
         ps_printf(ps, "%d#", parm->un.numeric);
       break;
      default:
       if (format == READOUT)
       {
         if ((parm->asn->pe_class == PE_CLASS_UNIV)
           &&(parm->asn->pe_form  == PE_FORM_PRIM)
           &&(parm->asn->pe_id    == PE_PRIM_INT))
           ps_printf(ps, "%d", prim2num(parm->asn));
         else if ((parm->asn->pe_class == PE_CLASS_UNIV)
           &&(parm->asn->pe_form  == PE_FORM_PRIM)
           &&(parm->asn->pe_id    == PE_PRIM_NULL))
           ps_printf(ps, "NULL");
         else
         {
           vpushquipu (ps);
           vunknown(parm->asn);
           vpopquipu ();
         }
       }
       else
       {
        /* This routine will print a {ASN} prefix */
         pe_print(ps, parm->asn, format);
       }
       ps_printf(ps, "#");
   }
}

struct certificate *
ldap_str2cert( char *str )
{
struct certificate *result;
char *ptr;
OID oid;

  Debug( LDAP_DEBUG_TRACE, "ldap_str2cert(%s)\n", str, 0, 0 );

  result = (struct certificate *) calloc(1, sizeof(*result));

  /* version */
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("version not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->version = atoi(str);

  /* serial number */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("serial number not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->serial = atoi(str);

  /* signature algorithm id - oid */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("signature algorithm id not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  oid = name2oid(SkipSpace(str));
  if (oid == NULLOID)
  {
    parse_error("Bad algorithm identifier (SIGNED Value)",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  result->sig.alg.algorithm = oid;
  result->alg.algorithm     = oid_cpy(oid);

  /* signature algorithm id - parameters */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("algorithm id parameters not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  ldap_str2alg(str, &(result->sig.alg));
  ldap_str2alg(str, &(result->alg));

  /* issuer */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("Issuer not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->issuer = ldap_str2dn(str);

  /* validity - not before */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("Start time not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->valid.not_before = strdup(str);

  /* validity - not after */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("End time not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->valid.not_after = strdup(str);

  /* subject */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("Subject not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  result->subject = ldap_str2dn(str);

  /* public key info - algorithm id - oid */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("public key info algid oid not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  oid = name2oid(SkipSpace(str));
  if (oid == NULLOID)
  {
    free((char*)result);
    return (struct certificate *) 0;
  }
  result->key.alg.algorithm = oid;

  /* public key info - algorithm id - parameters */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("Parameters not present (SIGNED Value)",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  ldap_str2alg(str, &(result->key.alg));

  /* public key info - encrypted sign value */
  str = ptr;
  ptr = strchr(str, '#');
  if (ptr == NULLCP)
  {
    parse_error("Signature not present",NULLCP);
    cert_free(result);
    return (struct certificate *) 0;
  }
  *ptr++ = '\0';
  str2encrypted(str, &(result->key.value), &(result->key.n_bits));

  /* encrypted sign value */
  str = ptr;
  str2encrypted(str, &(result->sig.encrypted), &(result->sig.n_bits));

  return (result);
}

void
ldap_str2alg( char *str, struct alg_id *alg )
{
  if ((str == NULLCP) || (*str == '\0'))
   {
     alg->asn = NULLPE;
     alg->p_type = ALG_PARM_ABSENT;
   }
  else if (strncmp(str,"{ASN}", 5) == 0)
    {
      alg->asn = asn2pe((char*)str+5);
      alg->p_type = ALG_PARM_UNKNOWN;
    }
  else if (strncmp(str, "NULL", 4) == 0)
    {
      alg->asn = asn2pe((char*)"0500");
      alg->p_type = ALG_PARM_UNKNOWN;
    }
  else
    {
      alg->asn=NULLPE;
      alg->p_type = ALG_PARM_NUMERIC;
      alg->un.numeric = atoi(str);
    }
}

void
certif_init( void )
{
	sntx_table	*syntax_table;

	if ((syntax_table = get_syntax_table(ldap_certif_syntax)) != NULL) {
		syntax_table->s_print = (void *) ldap_certif_print;
		syntax_table->s_parse = (void *) ldap_str2cert;
	} else
		fprintf(stderr, "error getting sntx table in certif_init()\n");
}
