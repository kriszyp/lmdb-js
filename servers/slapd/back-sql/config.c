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
#include <string.h>
#include <sys/types.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"

int backsql_db_config(BackendDB *be,const char *fname,int lineno,int argc,char **argv)
{
 backsql_info *si=(backsql_info*) be->be_private;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_db_config()\n",0,0,0);
 if (!si)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_db_config: be_private is NULL!!!\n",0,0,0);
   exit(1);
  }
  
 if (!strcasecmp(argv[0],"dbhost"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing hostname in dbhost directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->dbhost=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): hostname=%s\n",si->dbhost,0,0);
    }
   return(0);
  }
  
 if (!strcasecmp(argv[0],"dbuser"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing username in dbuser directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->dbuser=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): dbuser=%s\n",argv[1],0,0);
    }
   return(0);
  }
 
 if (!strcasecmp(argv[0],"dbpasswd"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing password in dbpasswd directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->dbpasswd=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): dbpasswd=%s\n",si->dbpasswd,0,0);
    }
   return(0);
  }
  
 if (!strcasecmp(argv[0],"dbname"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing database name in dbname directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->dbname=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): dbname=%s\n",si->dbname,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"subtree_cond"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing SQL condition in subtree_cond directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->subtree_cond=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): subtree_cond=%s\n",si->subtree_cond,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"oc_query"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing SQL statement in oc_query directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->oc_query=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): oc_query=%s\n",si->oc_query,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"at_query"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing SQL statement in at_query directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->at_query=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): at_query=%s\n",si->at_query,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"insentry_query"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing SQL statement in insentry_query directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->insentry_query=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): insentry_query=%s\n",si->insentry_query,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"upper_func"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing function name in upper_func directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->upper_func=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): upper_func=%s\n",si->upper_func,0,0);
    }
   return(0);
  }

 if (!strcasecmp(argv[0],"delentry_query"))
  {
   if (argc<2)
    {
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): missing SQL statement in delentry_query directive\n",
                     fname,lineno,0);
    }
   else
    {
     si->delentry_query=ch_strdup(argv[1]);
     Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config(): delentry_query=%s\n",si->delentry_query,0,0);
    }
   return(0);
  }
 
 Debug(LDAP_DEBUG_TRACE,"<==backsql_db_config (%s line %d): unknown directive '%s' (ignored)\n",
                     fname,lineno,argv[0]);
 return 0;
}

#endif /* SLAPD_SQL */
