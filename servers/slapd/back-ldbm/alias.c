/*
 * Copyright (c) 1998 Will Ballantyne, ITSD, Government of BC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to ITSD, Government of BC. The name of ITSD
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <string.h>
#include <ac/socket.h>		/* Get struct sockaddr for slap.h */
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

/*
 * given an alias object, dereference it to its end point.
 * entry returned has reader lock 
 */
Entry *derefAlias_r ( Backend     *be,
		    Connection	*conn,
		    Operation	*op,
		    Entry       *e)
{
  Attribute *a;
  int       depth;
  char      **pastAliases;
  char      *matched;

  Debug( LDAP_DEBUG_TRACE, "<= checking for alias for dn %s\n", e->e_dn, 0, 0 );

  /*
   * try to deref fully, up to a maximum depth.  If the max depth exceeded
   * then send an error
   */
  for ( depth = 0;
	( ( a = attr_find( e->e_attrs, "aliasedobjectname" ) ) != NULL) &&
	  ( depth < be->be_maxDerefDepth );
	++depth) 
  {

    /* 
     * make sure there is a defined aliasedobjectname.  
     * can only have one value so just use first value (0) in the attr list. 
     */	    
    if (a->a_vals[0] && a->a_vals[0]->bv_val) {
      char *newDN, *oldDN;

      Debug( LDAP_DEBUG_TRACE, "<= %s is an alias for %s\n", 
	     e->e_dn, a->a_vals[0]->bv_val, 0 );
      newDN = ch_strdup (a->a_vals[0]->bv_val);
      oldDN = ch_strdup (e->e_dn);

      /*
       * ok, so what happens if there is an alias in the DN of a dereferenced
       * alias object?  
       */
      if ( (e = dn2entry_r( be, newDN, &matched )) == NULL ) {

	/* could not deref return error  */
	Debug( LDAP_DEBUG_TRACE, 
	       "<= %s is a dangling alias to %s\n", 
	       oldDN, newDN, 0 );
	send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM, "",
			  "Dangling Alias" );

			if(matched != NULL) free(matched);
      }
      free (newDN);
      free (oldDN);
    }
    else {
      /*
       * there was an aliasedobjectname defined but no data.
       * this can't happen, right?
       */
	Debug( LDAP_DEBUG_TRACE, 
	       "<= %s has no data in aliasedobjectname attribute\n", 
	       e->e_dn, 0, 0 );
	send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM, "",
			  "Alias missing aliasedobjectname" );
    }
  }

  /*
   * warn if we pulled out due to exceeding the maximum deref depth
   */
  if ( depth >= be->be_maxDerefDepth ) {
    Debug( LDAP_DEBUG_TRACE, 
	   "<= %s exceeded maximum deref depth %d\n", 
	   e->e_dn, be->be_maxDerefDepth, 0 );
    send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM, "",
			"Maximum alias dereference depth exceeded" );
  }

  return e;
}

/*
 * given a DN fully deref it and return the real DN or original DN if it fails
 */
char *derefDN ( Backend     *be,
                Connection  *conn,
                Operation   *op,
                char        *dn
)
{
  struct ldbminfo *li = (struct ldbminfo *) be->be_private;
  char 	*matched;
  char 	*newDN = NULL;
  int	depth;
  Entry 	*eMatched;
  Entry 	*eDeref;
  Entry         *eNew;
  

  Debug( LDAP_DEBUG_TRACE, 
	 "<= dereferencing dn %s\n", 
	 dn, 0, 0 );
  
  newDN = ch_strdup ( dn );

  /* while we don't have a matched dn, deref the DN */
  for ( depth = 0;
	( (eMatched = dn2entry_r( be, newDN, &matched )) == NULL) &&
	  (depth < be->be_maxDerefDepth);
	++depth ) {
    
    /* free reader lock */
    cache_return_entry_r(&li->li_cache, eMatched);

    if ((matched != NULL) && *matched) {	
      char *submatch;
      
      /* 
       * make sure there actually is an entry for the matched part 
       */
      if ( (eMatched = dn2entry_r( be, matched, &submatch )) != NULL) {
	char  *remainder; /* part before the aliased part */
	int  rlen = strlen(newDN) - strlen(matched);
	
	Debug( LDAP_DEBUG_TRACE, "<= matched %s\n", matched, 0, 0 );
	
	remainder = ch_malloc (rlen + 1);
	strncpy ( remainder, newDN, rlen );
	remainder[rlen]	= '\0';
	
	Debug( LDAP_DEBUG_TRACE, "<= remainder %s\n", remainder, 0, 0 );
	
	if ((eNew = derefAlias_r( be, conn, op, eMatched )) == NULL) {
	  free (matched);
	  matched = NULL;
	  free (newDN);
	  newDN = NULL;
	  free (remainder);
	  break; /*  no associated entry, dont deref */
	}
	else {

	  Debug( LDAP_DEBUG_TRACE, "<= l&g we have %s vs %s \n", matched, eNew->e_dn, 0 );

	  if (!strcasecmp (matched, eNew->e_dn)) {
	    /* newDN same as old so not an alias, no need to go further */
	    free (newDN);
	    newDN = NULL;
	    free (matched);
	    matched = NULL;
	    free (remainder);
	    break;
	  }

	  /* 
	   * we have dereferenced the aliased part so put
	   * the new dn together
	   */
	  free (newDN);
	  newDN = ch_malloc (strlen(eMatched->e_dn) + rlen + 1);
	  strcpy (newDN, remainder);
	  strcat (newDN, eMatched->e_dn);
	  Debug( LDAP_DEBUG_TRACE, "<= expanded to %s\n", newDN, 0, 0 );

	  free (matched);
	  matched = NULL;
	  free (remainder);

          /* free reader lock */
          cache_return_entry_r(&li->li_cache, eNew);
	}
        /* free reader lock */
        cache_return_entry_r(&li->li_cache, eMatched);
      }
      else {
	if(submatch != NULL) free(submatch);
	break; /* there was no entry for the matched part */
      }
    }
    else {
      break; /* there was no matched part */
    }
  }
  
  /*
   * the final part of the DN might be an alias 
   * so try to dereference it.
   */
  if ( (eNew = dn2entry_r( be, newDN, &matched )) != NULL) {
    if ((eDeref = derefAlias_r( be, conn, op, eNew )) != NULL) {
      free (newDN);
      newDN = ch_strdup (eDeref->e_dn);
      /* free reader lock */
      cache_return_entry_r(&li->li_cache, eDeref);
    }
    /* free reader lock */
    cache_return_entry_r(&li->li_cache, eNew);
  }
  
  /*
   * warn if we exceeded the max depth as the resulting DN may not be dereferenced
   */
  if (depth >= be->be_maxDerefDepth) {
    Debug( LDAP_DEBUG_TRACE, 
	   "<= max deref depth exceeded in derefDN for %s, result %s\n", 
	   dn, newDN, 0 );
    send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM, "",
		      "Maximum alias dereference depth exceeded for base" );
  }

  if (newDN == NULL) {
    newDN = ch_strdup ( dn );
  }
  
  Debug( LDAP_DEBUG_TRACE, "<= returning deref DN of  %s\n", newDN, 0, 0 ); 
  if (matched != NULL) free(matched);

  return newDN;
}
