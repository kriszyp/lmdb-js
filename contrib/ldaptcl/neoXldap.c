/*
 * NeoSoft Tcl client extensions to Lightweight Directory Access Protocol.
 * 
 * Copyright (c) 1998-1999 NeoSoft, Inc.  
 * All Rights Reserved.
 * 
 * This software may be used, modified, copied, distributed, and sold,
 * in both source and binary form provided that these copyrights are
 * retained and their terms are followed.
 * 
 * Under no circumstances are the authors or NeoSoft Inc. responsible
 * for the proper functioning of this software, nor do the authors
 * assume any liability for damages incurred with its use.
 * 
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to NeoSoft, Inc.
 * 
 * NeoSoft, Inc. may not be used to endorse or promote products derived
 * from this software without specific prior written permission. This
 * software is provided ``as is'' without express or implied warranty.
 * 
 * Requests for permission may be sent to NeoSoft Inc, 1770 St. James Place,
 * Suite 500, Houston, TX, 77056.
 *
 * $Id: neoXldap.c,v 1.1 1999/02/10 22:56:49 kunkee Exp $
 *
 */

/*
 * This code was originally developed by Karl Lehenbauer to work with
 * Umich-3.3 LDAP.  It was debugged against the Netscape LDAP server
 * and their much more reliable SDK, and again backported to the
 * Umich-3.3 client code.  The UMICH_LDAP define is used to include
 * code that will work with the Umich-3.3 LDAP, but not with Netscape's
 * SDK.  OpenLDAP may support some of these, but they have not been tested.
 * Current support is by Randy Kunkee.
 */

#include "tclExtend.h"

#include <lber.h>
#include <ldap.h>
#include <string.h>

/*
 * Macros to do string compares.  They pre-check the first character before
 * checking of the strings are equal.
 */

#define STREQU(str1, str2) \
	(((str1) [0] == (str2) [0]) && (strcmp (str1, str2) == 0))

/*
 * The following section defines some common macros used by the rest
 * of the code.  It's ugly, and can use some work.  This code was
 * originally developed to work with Umich-3.3 LDAP.  It was debugged
 * against the Netscape LDAP server and the much more reliable SDK,
 * and then again backported to the Umich-3.3 client code.
 */

#if defined(LDAP_API_VERSION)
       /* LDAP_API_VERSION must be defined per the current draft spec
       ** it's value will be assigned RFC number.  However, as
       ** no RFC is defined, it's value is currently implementation
       ** specific (though I would hope it's value is greater than 1823).
       ** In OpenLDAP 2.x-devel, its 2000 + the draft number, ie 2002.
       ** This section is for OPENLDAP.
       */
#define ldap_attributefree(p) ldap_memfree(p)
#define LDAP_ERR_STRING(ld)  \
	ldap_err2string(ldap_get_lderrno(ldap))
#elif defined( LDAP_OPT_SIZELIMIT )
       /*
       ** Netscape SDK w/ ldap_set_option, ldap_get_option
       */
#define ldap_attributefree(p) ldap_memfree(p)
#define LDAP_ERR_STRING(ld)  \
	ldap_err2string(ldap_get_lderrno(ldap, (char**)NULL, (char**)NULL))
#else
       /* U-Mich/OpenLDAP 1.x API */
       /* RFC-1823 w/ changes */
#define UMICH_LDAP
#define ldap_memfree(p) free(p)
#define ldap_ber_free(p, n) ber_free(p, n)
#define ldap_get_lderrno(ld, dummy1, dummy2) (ld->ld_errno)
#define ldap_value_free_len(bvals) ber_bvecfree(bvals)
#define ldap_attributefree(p) 
#define LDAP_ERR_STRING(ld)  \
	ldap_err2string(ldap_get_lderrno(ldap))
#endif

#if defined(LDAP_API_VERSION)
#ifdef LDAP_OPT_ERROR_NUMBER
static int ldap_get_lderrno(LDAP *ld)
{
    int ld_errno = 0;
    ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, (void*)&ld_errno);
    return ld_errno;
}
#endif
#endif



/*-----------------------------------------------------------------------------
 * LDAP_ProcessOneSearchResult --
 * 
 *   Process one result return from an LDAP search.
 *
 * Paramaters:
 *   o interp -            Tcl interpreter; Errors are returned in result.
 *   o ldap -              LDAP structure pointer.
 *   o entry -             LDAP message pointer.
 *   o destArrayNameObj -  Name of Tcl array in which to store attributes.
 *   o evalCodeObj -       Tcl_Obj pointer to code to eval against this result.
 * Returns:
 *   o TCL_OK if processing succeeded..
 *   o TCL_ERROR if an error occured, with error message in interp.
 *-----------------------------------------------------------------------------
 */
static int
LDAP_ProcessOneSearchResult (interp, ldap, entry, destArrayNameObj, evalCodeObj)
    Tcl_Interp     *interp;
    LDAP           *ldap;
    LDAPMessage    *entry;
    Tcl_Obj        *destArrayNameObj;
    Tcl_Obj        *evalCodeObj;
{
    char           *attributeName;
    Tcl_Obj        *attributeNameObj;
    Tcl_Obj        *attributeDataObj;
    int             i; 
    BerElement     *ber; 
    struct berval **bvals;
    char	   *dn;

    Tcl_UnsetVar (interp, Tcl_GetStringFromObj (destArrayNameObj, NULL), 0);

    dn = ldap_get_dn(ldap, entry);
    if (dn != NULL) {
	if (Tcl_SetVar2(interp,		/* set dn */
		       Tcl_GetStringFromObj(destArrayNameObj, NULL),
		       "dn",
		       dn,
		       TCL_LEAVE_ERR_MSG) == NULL)
	    return TCL_ERROR;
	ldap_memfree(dn);
    }
    for (attributeName = ldap_first_attribute (ldap, entry, &ber); 
      attributeName != NULL;
      attributeName = ldap_next_attribute(ldap, entry, ber)) {

	bvals = ldap_get_values_len(ldap, entry, attributeName);

	if (bvals != NULL) {
	    /* Note here that the U.of.M. ldap will return a null bvals
	       when the last attribute value has been deleted, but still
	       retains the attributeName.  Even though this is documented
	       as an error, we ignore it to present a consistent interface
	       with Netscape's server
	    */
	    attributeNameObj = Tcl_NewStringObj (attributeName, -1);
	    Tcl_IncrRefCount (attributeNameObj);
	    attributeDataObj = Tcl_NewObj();
	    for (i = 0; bvals[i] != NULL; i++) {
		Tcl_Obj *singleAttributeValueObj;

		singleAttributeValueObj = Tcl_NewStringObj (bvals[i]->bv_val, -1);
		if (Tcl_ListObjAppendElement (interp, 
					      attributeDataObj, 
					      singleAttributeValueObj) 
		  == TCL_ERROR) {
		    return TCL_ERROR;
		}
	    }

	    ldap_value_free_len(bvals);

	    if (Tcl_ObjSetVar2 (interp, 
				destArrayNameObj,
				attributeNameObj,
				attributeDataObj,
				TCL_LEAVE_ERR_MSG) == NULL) {
		return TCL_ERROR;
	    }
	    Tcl_DecrRefCount (attributeNameObj);
	}
	ldap_attributefree(attributeName);
    }
    return Tcl_EvalObj (interp, evalCodeObj);
}

/*-----------------------------------------------------------------------------
 * LDAP_PerformSearch --
 * 
 *   Perform an LDAP search.
 *
 * Paramaters:
 *   o interp -            Tcl interpreter; Errors are returned in result.
 *   o ldap -              LDAP structure pointer.
 *   o base -              Base DN from which to perform search.
 *   o scope -             LDAP search scope, must be one of LDAP_SCOPE_BASE,
 *                         LDAP_SCOPE_ONELEVEL, or LDAP_SCOPE_SUBTREE.
 *   o attrs -             Pointer to array of char * pointers of desired
 *                         attribute names, or NULL for all attributes.
 *   o filtpatt            LDAP filter pattern.
 *   o value               Value to get sprintf'ed into filter pattern.
 *   o destArrayNameObj -  Name of Tcl array in which to store attributes.
 *   o evalCodeObj -       Tcl_Obj pointer to code to eval against this result.
 * Returns:
 *   o TCL_OK if processing succeeded..
 *   o TCL_ERROR if an error occured, with error message in interp.
 *-----------------------------------------------------------------------------
 */
static int 
LDAP_PerformSearch (interp, ldap, base, scope, attrs, filtpatt, value, destArrayNameObj, evalCodeObj)
    Tcl_Interp     *interp;
    LDAP           *ldap;
    char           *base;
    int             scope;
    char          **attrs;
    char           *filtpatt;
    char           *value;
    Tcl_Obj        *destArrayNameObj;
    Tcl_Obj        *evalCodeObj;
{
    char          filter[BUFSIZ];
    int           resultCode;
    int           errorCode;
    int		  abandon;
    int		  tclResult = TCL_OK;
    int		  msgid;
    LDAPMessage  *resultMessage;
    LDAPMessage  *entryMessage;

    Tcl_Obj      *resultObj;
    int		  lderr;

    resultObj = Tcl_GetObjResult (interp);

    sprintf(filter, filtpatt, value);

    if ((msgid = ldap_search (ldap, base, scope, filter, attrs, 0)) == -1) {
	Tcl_AppendStringsToObj (resultObj,
			        "LDAP start search error: ",
					LDAP_ERR_STRING(ldap),
			        (char *)NULL);
	return TCL_ERROR;
    }

    abandon = 0;
    while ((resultCode = ldap_result (ldap, 
			      msgid, 
			      0,
			      NULL,
			      &resultMessage)) == LDAP_RES_SEARCH_ENTRY) {

	entryMessage = ldap_first_entry(ldap, resultMessage);

	tclResult = LDAP_ProcessOneSearchResult  (interp, 
				ldap, 
				entryMessage,
				destArrayNameObj,
				evalCodeObj);
	ldap_msgfree(resultMessage);
	if (tclResult != TCL_OK) {
	    if (tclResult == TCL_CONTINUE) {
		tclResult = TCL_OK;
	    } else if (tclResult == TCL_BREAK) {
		tclResult = TCL_OK;
		abandon = 1;
		break;
	    } else if (tclResult == TCL_ERROR) {
		char msg[100];
		sprintf(msg, "\n    (\"search\" body line %d)",
			interp->errorLine);
		Tcl_AddObjErrorInfo(interp, msg, -1);
		abandon = 1;
		break;
	    } else {
		abandon = 1;
		break;
	    }
	}
    }

    if (abandon) {
	ldap_abandon(ldap, msgid);
    } else {
	if (resultCode == LDAP_RES_SEARCH_RESULT) {
	    if ((errorCode = ldap_result2error (ldap, resultMessage, 0))
	      != LDAP_SUCCESS) {
	      Tcl_AppendStringsToObj (resultObj,
				      "LDAP search error: ",
				      ldap_err2string(errorCode),
				      (char *)NULL);
	      ldap_msgfree(resultMessage);
	      return TCL_ERROR;
	    }
	}


	if (resultCode == -1) {
	    Tcl_AppendStringsToObj (resultObj,
				    "LDAP result search error: ",
				    LDAP_ERR_STRING(ldap),
				    (char *)NULL);
	    return TCL_ERROR;
	} else
	    ldap_msgfree(resultMessage);
    }

    return tclResult;
}

/*-----------------------------------------------------------------------------
 * NeoX_LdapTargetObjCmd --
 *  
 * Implements the body of commands created by Neo_LdapObjCmd.
 *  
 * Results:
 *      A standard Tcl result.
 *      
 * Side effects:
 *      See the user documentation.
 *-----------------------------------------------------------------------------
 */     
static int
NeoX_LdapTargetObjCmd (clientData, interp, objc, objv)
    ClientData    clientData;
    Tcl_Interp   *interp;
    int           objc;
    Tcl_Obj      *CONST objv[];
{
    char         *command;
    char         *subCommand;
    LDAP         *ldap = (LDAP *)clientData;
    char         *dn;
    int           is_add = 0;
    int           is_add_or_modify = 0;
    int           mod_op = 0;
    char	 *m, *s, *errmsg;
    int		 errcode;

    Tcl_Obj      *resultObj = Tcl_GetObjResult (interp);

    if (objc < 2)
       return TclX_WrongArgs (interp,
			      objv [0],
			      "subcommand [args...]");

    command = Tcl_GetStringFromObj (objv[0], NULL);
    subCommand = Tcl_GetStringFromObj (objv[1], NULL);

    /* object bind authtype name password */
    if (STREQU (subCommand, "bind")) {
	char     *binddn;
	char     *passwd;
	int       stringLength;
	char     *ldap_authString;
	int       ldap_authInt;

	if (objc != 5)
	    return TclX_WrongArgs (interp, objv [0], "bind authtype dn passwd");

	ldap_authString = Tcl_GetStringFromObj (objv[2], NULL);

	if (STREQU (ldap_authString, "simple")) {
	    ldap_authInt = LDAP_AUTH_SIMPLE;
	}
#ifdef UMICH_LDAP
	else if (STREQU (ldap_authString, "kerberos_ldap")) {
	    ldap_authInt = LDAP_AUTH_KRBV41;
	} else if (STREQU (ldap_authString, "kerberos_dsa")) {
	    ldap_authInt = LDAP_AUTH_KRBV42;
	} else if (STREQU (ldap_authString, "kerberos_both")) {
	    ldap_authInt = LDAP_AUTH_KRBV4;
	}
#endif
	else {
	    Tcl_AppendStringsToObj (resultObj,
				    "\"",
				    command,
				    " ",
				    subCommand, 
#ifdef UMICH_LDAP
				    "\" authtype must be one of \"simple\", ",
				    "\"kerberos_ldap\", \"kerberos_dsa\" ",
				    "or \"kerberos_both\"",
#else
				    "\" authtype must be \"simple\", ",
#endif
				    (char *)NULL);
	    return TCL_ERROR;
	}

	binddn = Tcl_GetStringFromObj (objv[3], &stringLength);
	if (stringLength == 0)
	    binddn = NULL;

	passwd = Tcl_GetStringFromObj (objv[4], &stringLength);
	if (stringLength == 0)
	    passwd = NULL;

/*  ldap_bind_s(ldap, dn, pw, method) */

#ifdef UMICH_LDAP
#define LDAP_BIND(ldap, dn, pw, method) \
  ldap_bind_s(ldap, dn, pw, method)
#else
#define LDAP_BIND(ldap, dn, pw, method) \
  ldap_simple_bind_s(ldap, dn, pw)
#endif
	if ((errcode = LDAP_BIND (ldap, 
			 binddn, 
			 passwd, 
			 ldap_authInt)) != LDAP_SUCCESS) {

	    Tcl_AppendStringsToObj (resultObj,
			            "LDAP bind error: ",
				    ldap_err2string(errcode),
				    (char *)NULL);
	    return TCL_ERROR;
	}
	return TCL_OK;
    }

    if (STREQU (subCommand, "unbind")) {
	if (objc != 2)
	    return TclX_WrongArgs (interp, objv [0], "unbind");

       return Tcl_DeleteCommand(interp, Tcl_GetStringFromObj(objv[0], NULL));
    }

    /* object delete dn */
    if (STREQU (subCommand, "delete")) {
	if (objc != 3)
	    return TclX_WrongArgs (interp, objv [0], "delete dn");

       dn = Tcl_GetStringFromObj (objv [2], NULL);
       if ((errcode = ldap_delete_s(ldap, dn)) != LDAP_SUCCESS) {
	   Tcl_AppendStringsToObj (resultObj,
			           "LDAP delete error: ",
				   ldap_err2string(errcode),
				   (char *)NULL);
	   return TCL_ERROR;
       }
       return TCL_OK;
    }

    /* object rename_rdn dn rdn */
    /* object modify_rdn dn rdn */
    if (STREQU (subCommand, "rename_rdn") || STREQU (subCommand, "modify_rdn")) {
	char    *rdn;
	int      deleteOldRdn;

	if (objc != 4)
	    return TclX_WrongArgs (interp, 
				   objv [0], 
				   "delete_rdn|modify_rdn dn rdn");

	dn = Tcl_GetStringFromObj (objv [2], NULL);
	rdn = Tcl_GetStringFromObj (objv [3], NULL);

	deleteOldRdn = (*subCommand == 'r');

	if ((errcode = ldap_modrdn2_s (ldap, dn, rdn, deleteOldRdn)) != LDAP_SUCCESS) {
	    Tcl_AppendStringsToObj (resultObj,
				    "LDAP ",
				    subCommand,
				    " error: ",
				    ldap_err2string(errcode),
				    (char *)NULL);
	    return TCL_ERROR;
	}
	return TCL_OK;
    }

    /* object add dn attributePairList */
    /* object add_attributes dn attributePairList */
    /* object replace_attributes dn attributePairList */
    /* object delete_attributes dn attributePairList */

    if (STREQU (subCommand, "add")) {
	is_add = 1;
	is_add_or_modify = 1;
    } else {
	is_add = 0;
	if (STREQU (subCommand, "add_attributes")) {
	    is_add_or_modify = 1;
	    mod_op = LDAP_MOD_ADD;
	} else if (STREQU (subCommand, "replace_attributes")) {
	    is_add_or_modify = 1;
	    mod_op = LDAP_MOD_REPLACE;
	} else if (STREQU (subCommand, "delete_attributes")) {
	    is_add_or_modify = 1;
	    mod_op = LDAP_MOD_DELETE;
	}
    }

    if (is_add_or_modify) {
	int          result;
	LDAPMod    **modArray;
	LDAPMod     *mod;
	char       **valPtrs = NULL;
	int          attribObjc;
	Tcl_Obj    **attribObjv;
	int          valuesObjc;
	Tcl_Obj    **valuesObjv;
	int          nPairs;
	int          i;
	int          j;

	Tcl_Obj      *resultObj = Tcl_GetObjResult (interp);

	if (objc != 4) {
	    Tcl_AppendStringsToObj (resultObj,
				    "wrong # args: ",
				    Tcl_GetStringFromObj (objv [0], NULL),
				    " ",
				    subCommand,
				    " dn attributePairList",
				    (char *)NULL);
	    return TCL_ERROR;
	}

	dn = Tcl_GetStringFromObj (objv [2], NULL);

	if (Tcl_ListObjGetElements (interp, objv [3], &attribObjc, &attribObjv)
	  == TCL_ERROR) {
	   return TCL_ERROR;
	}

        if (attribObjc & 1) {
	    Tcl_AppendStringsToObj (resultObj,
				    "attribute list does not contain an ",
				    "even number of key-value elements",
				    (char *)NULL);
	    return TCL_ERROR;
	}

	nPairs = attribObjc / 2;

	modArray = (LDAPMod **)ckalloc (sizeof(LDAPMod *) * (nPairs + 1));
	modArray[nPairs] = (LDAPMod *) NULL;

	for (i = 0; i < nPairs; i++) {
	    mod = modArray[i] = (LDAPMod *) ckalloc (sizeof(LDAPMod));
	    mod->mod_op = mod_op;
	    mod->mod_type = Tcl_GetStringFromObj (attribObjv [i * 2], NULL);

	    if (Tcl_ListObjGetElements (interp, attribObjv [i * 2 + 1], &valuesObjc, &valuesObjv) == TCL_ERROR) {
		/* FIX: cleanup memory here */
		return TCL_ERROR;
	    }

	    valPtrs = mod->mod_vals.modv_strvals = \
	        (char **)ckalloc (sizeof (char *) * (valuesObjc + 1));
	    valPtrs[valuesObjc] = (char *)NULL;

	    for (j = 0; j < valuesObjc; j++) {
		valPtrs [j] = Tcl_GetStringFromObj (valuesObjv[j], NULL);

		/* If it's "delete" and value is an empty string, make
		 * value be NULL to indicate entire attribute is to be 
		 * deleted */
		if ((*valPtrs [j] == '\0') 
		    && (mod->mod_op == LDAP_MOD_DELETE)) {
			valPtrs [j] = NULL;
		}
	    }
	}

        if (is_add) {
	    result = ldap_add_s (ldap, dn, modArray);
	} else {
	    result = ldap_modify_s (ldap, dn, modArray);
	}

        /* free the modArray elements, then the modArray itself. */
	for (i = 0; i < nPairs; i++) {
	    ckfree ((char *) modArray[i]->mod_vals.modv_strvals);
	    ckfree ((char *) modArray[i]);
	}
	ckfree ((char *) modArray);

	/* FIX: memory cleanup required all over the place here */
        if (result != LDAP_SUCCESS) {
	    Tcl_AppendStringsToObj (resultObj,
				    "LDAP ",
				    subCommand,
				    " error: ",
				    ldap_err2string(result),
				    (char *)NULL);
	    return TCL_ERROR;
	}
	return TCL_OK;
    }

    /* object search controlArray dn pattern */
    if (STREQU (subCommand, "search")) {
	char        *controlArrayName;
	Tcl_Obj     *controlArrayNameObj;

	char        *scopeString;
	int          scope;

	char        *derefString;
	int          deref;

	char        *baseString;

	char       **attributesArray;
	char        *attributesString;
	int          attributesArgc;

	char        *filterPatternString;

	Tcl_Obj     *destArrayNameObj;
	Tcl_Obj     *evalCodeObj;

	if (objc != 5)
	    return TclX_WrongArgs (interp, 
				   objv [0],
				   "search controlArray destArray code");

        controlArrayNameObj = objv [2];
	controlArrayName = Tcl_GetStringFromObj (controlArrayNameObj, NULL);

	destArrayNameObj = objv [3];

	evalCodeObj = objv [4];

	baseString = Tcl_GetVar2 (interp, 
				  controlArrayName, 
				  "base",
				  0);

	if (baseString == (char *)NULL) {
	    Tcl_AppendStringsToObj (resultObj,
				    "required element \"base\" ",
				    "is missing from ldap control array \"",
				    controlArrayName,
				    "\"",
				    (char *)NULL);
	    return TCL_ERROR;
	}

	filterPatternString = Tcl_GetVar2 (interp,
				           controlArrayName,
				           "filter",
				           0);
	if (filterPatternString == (char *)NULL) {
	    Tcl_AppendStringsToObj (resultObj,
				    "required element \"filter\" ",
				    "is missing from ldap control array \"",
				    controlArrayName,
				    "\"",
				    (char *)NULL);

	    return TCL_ERROR;
	}

	/* Fetch scope setting from control array.
	 * If it doesn't exist, default to subtree scoping.
	 */
	scopeString = Tcl_GetVar2 (interp, controlArrayName, "scope", 0);
	if (scopeString == NULL) {
	    scope = LDAP_SCOPE_SUBTREE;
	} else {
	    if (STREQU(scopeString, "base")) 
		scope = LDAP_SCOPE_BASE;
	    else if (STREQU(scopeString, "onelevel"))
		scope = LDAP_SCOPE_ONELEVEL;
	    else if (STREQU(scopeString, "subtree"))
		scope = LDAP_SCOPE_SUBTREE;
	    else {
		Tcl_AppendStringsToObj (resultObj,
				        "\"scope\" element of \"",
				        controlArrayName,
				        "\" array is not one of ",
				        "\"base\", \"one_level\", ",
					"or \"subtree\"",
				      (char *) NULL);
		return TCL_ERROR;
	    }
	}

	/* Fetch dereference control setting from control array.
	 * If it doesn't exist, default to never dereference. */
	derefString = Tcl_GetVar2 (interp,
				   controlArrayName,
				   "deref",
				   0);
				      
	if (derefString == (char *)NULL) {
	    deref = LDAP_DEREF_NEVER;
	} else {
	    if (STREQU(derefString, "never"))
		deref = LDAP_DEREF_NEVER;
	    else if (STREQU(derefString, "search"))
		deref = LDAP_DEREF_SEARCHING;
	    else if (STREQU(derefString, "find") == 0)
		deref = LDAP_DEREF_FINDING;
	    else if (STREQU(derefString, "always"))
		deref = LDAP_DEREF_ALWAYS;
	    else {
		Tcl_AppendStringsToObj (resultObj,
				        "\"deref\" element of \"",
				        controlArrayName,
				        "\" array is not one of ",
				        "\"never\", \"search\", \"find\", ",
				        "or \"always\"",
				        (char *) NULL);
		return TCL_ERROR;
	    }
	}

	/* Fetch list of attribute names from control array.
	 * If entry doesn't exist, default to NULL (all).
	 */
	attributesString = Tcl_GetVar2 (interp,
				        controlArrayName,
				        "attributes", 
				        0);
	if (attributesString == (char *)NULL) {
	    attributesArray = NULL;
	} else {
	    if ((Tcl_SplitList (interp, 
				attributesString,
				&attributesArgc, 
				&attributesArray)) != TCL_OK) {
		return TCL_ERROR;
	    }
	}

#ifdef UMICH_LDAP
	ldap->ld_deref = deref; 
	ldap->ld_timelimit = 0;
	ldap->ld_sizelimit = 0; 
	ldap->ld_options = 0;
#endif

	 return LDAP_PerformSearch (interp, 
			            ldap, 
			            baseString, 
			            scope, 
			            attributesArray, 
			            filterPatternString, 
			            "",
			            destArrayNameObj,
			            evalCodeObj);
    }

#if UMICH_LDAP
    if (STREQU (subCommand, "cache")) {
	char *cacheCommand;

	if (objc < 3)
	  badargs:
	    return TclX_WrongArgs (interp, 
				   objv [0],
				   "cache command [args...]");

	cacheCommand = Tcl_GetStringFromObj (objv [2], NULL);

	if (STREQU (cacheCommand, "uncache")) {
	    char *dn;

	    if (objc != 4)
		return TclX_WrongArgs (interp, 
				       objv [0],
				       "cache uncache dn");

            dn = Tcl_GetStringFromObj (objv [3], NULL);
	    ldap_uncache_entry (ldap, dn);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "enable")) {
	    long   timeout;
	    long   maxmem;

	    if (objc != 5)
		return TclX_WrongArgs (interp, 
				       objv [0],
				       "cache enable timeout maxmem");

            if (Tcl_GetLongFromObj (interp, objv [3], &timeout) == TCL_ERROR)
		return TCL_ERROR;

            if (Tcl_GetLongFromObj (interp, objv [4], &maxmem) == TCL_ERROR)
		return TCL_ERROR;

	    if (ldap_enable_cache (ldap, timeout, maxmem) == -1) {
		Tcl_AppendStringsToObj (resultObj,
					"LDAP cache enable error: ",
					LDAP_ERR_STRING(ldap),
					(char *)NULL);
		return TCL_ERROR;
	    }
	    return TCL_OK;
	}

	if (objc != 3) goto badargs;

	if (STREQU (cacheCommand, "disable")) {
	    ldap_disable_cache (ldap);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "destroy")) {
	    ldap_destroy_cache (ldap);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "flush")) {
	    ldap_flush_cache (ldap);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "no_errors")) {
	    ldap_set_cache_options (ldap, LDAP_CACHE_OPT_CACHENOERRS);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "all_errors")) {
	    ldap_set_cache_options (ldap, LDAP_CACHE_OPT_CACHEALLERRS);
	    return TCL_OK;
	}

	if (STREQU (cacheCommand, "size_errors")) {
	    ldap_set_cache_options (ldap, 0);
	    return TCL_OK;
	}
	Tcl_AppendStringsToObj (resultObj,
				"\"",
				command,
				" ",
				subCommand, 
				"\" subcommand", 
				" must be one of \"enable\", ",
				"\"disable\", ",
				"\"destroy\", \"flush\", \"uncache\", ",
				"\"no_errors\", \"size_errors\",",
				" or \"all_errors\"",
				(char *)NULL);
	return TCL_ERROR;
    }
#endif
#ifdef LDAP_DEBUG
    if (STREQU (subCommand, "debug")) {
	if (objc != 3) {
	    Tcl_AppendStringsToObj(resultObj, "Wrong # of arguments",
		(char*)NULL);
	    return TCL_ERROR;
	}
	return Tcl_GetIntFromObj(interp, objv[2], &ldap_debug);
    }
#endif

    /* FIX: this needs to enumerate all the possibilities */
    Tcl_AppendStringsToObj (resultObj,
	                    "subcommand \"", 
			    subCommand, 
			    "\" must be one of \"add\", ",
			    "\"add_attributes\", ",
			    "\"bind\", \"cache\", \"delete\", ",
			    "\"delete_attributes\", \"modify\", ",
			    "\"modify_rdn\", \"rename_rdn\", ",
			    "\"replace_attributes\", ",
			    "\"search\" or \"unbind\".",
	                    (char *)NULL);
    return TCL_ERROR;
}

/* 
 * Delete and LDAP command object
 *
 */
static void
NeoX_LdapObjDeleteCmd(clientData)
    ClientData    clientData;
{
    LDAP         *ldap = (LDAP *)clientData;

    ldap_unbind(ldap);
}

/*-----------------------------------------------------------------------------
 * NeoX_LdapObjCmd --
 *  
 * Implements the `ldap' command:
 *    ldap open newObjName host [port]
 *    ldap init newObjName host [port]
 *  
 * Results:
 *      A standard Tcl result.
 *      
 * Side effects:
 *      See the user documentation.
 *-----------------------------------------------------------------------------
 */     
static int
NeoX_LdapObjCmd (clientData, interp, objc, objv)
    ClientData    clientData;
    Tcl_Interp   *interp;
    int           objc;
    Tcl_Obj      *CONST objv[];
{
    extern int    errno;
    char         *subCommand;
    char         *newCommand;
    char         *ldapHost;
    int           ldapPort = 389;
    LDAP         *ldap;

    Tcl_Obj      *resultObj = Tcl_GetObjResult (interp);

    if (objc < 3 || objc > 5)
	return TclX_WrongArgs (interp, objv [0],
			       "(open|init) new_command host [port]|explode dn");

    subCommand = Tcl_GetStringFromObj (objv[1], NULL);

    if (STREQU(subCommand, "explode")) {
	char *param;
	int nonames = 0;
	int list = 0;
	char **exploded, **p;

	param = Tcl_GetStringFromObj (objv[2], NULL);
	if (param[0] == '-') {
	    if (STREQU(param, "-nonames")) {
		nonames = 1;
	    } else if (STREQU(param, "-list")) {
		list = 1;
	    } else {
		return TclX_WrongArgs (interp, objv [0], "explode ?-nonames|-list? dn");
	    }
	}
	if (nonames || list)
	    param = Tcl_GetStringFromObj (objv[3], NULL);
	exploded = ldap_explode_dn(param, nonames);
	for (p = exploded; *p; p++) {
	    if (list) {
		char *q = strchr(*p, '=');
		if (!q) {
		    Tcl_SetObjLength(resultObj, 0);
		    Tcl_AppendStringsToObj(resultObj, "rdn ", *p,
			" missing '='", NULL);
		    ldap_value_free(exploded);
		    return TCL_ERROR;
		}
		*q = '\0';
		if (Tcl_ListObjAppendElement(interp, resultObj,
			Tcl_NewStringObj(*p, -1)) != TCL_OK ||
			Tcl_ListObjAppendElement(interp, resultObj,
			Tcl_NewStringObj(q+1, -1)) != TCL_OK) {
		    ldap_value_free(exploded);
		    return TCL_ERROR;
		}
	    } else {
		if (Tcl_ListObjAppendElement(interp, resultObj,
			Tcl_NewStringObj(*p, -1))) {
		    ldap_value_free(exploded);
		    return TCL_ERROR;
		}
	    }
	}
	ldap_value_free(exploded);
	return TCL_OK;
    }

#ifdef UMICH_LDAP
    if (STREQU(subCommand, "friendly")) {
	char *friendly = ldap_dn2ufn(Tcl_GetStringFromObj(objv[2], NULL));
	Tcl_SetStringObj(resultObj, friendly, -1);
	free(friendly);
	return TCL_OK;
    }
#endif

    newCommand = Tcl_GetStringFromObj (objv[2], NULL);
    ldapHost = Tcl_GetStringFromObj (objv[3], NULL);

    if (objc == 5) {
	if (Tcl_GetIntFromObj (interp, objv [4], &ldapPort) == TCL_ERROR) {
	    Tcl_AppendStringsToObj (resultObj,
				    "LDAP port number is non-numeric",
				    (char *)NULL);
            return TCL_ERROR;
	}
    }

    if (STREQU (subCommand, "open")) {
	ldap = ldap_open (ldapHost, ldapPort);
    } else if (STREQU (subCommand, "init")) {
	ldap = ldap_init (ldapHost, ldapPort);
    } else {
	Tcl_AppendStringsToObj (resultObj, 
				"option was not \"open\" or \"init\"");
	return TCL_ERROR;
    }

    if (ldap == (LDAP *)NULL) {
	Tcl_SetErrno(errno);
	Tcl_AppendStringsToObj (resultObj, 
				Tcl_PosixError (interp), 
				(char *)NULL);
	return TCL_ERROR;
    }

#if UMICH_LDAP
    ldap->ld_deref = LDAP_DEREF_NEVER;  /* Turn off alias dereferencing */
#endif

    Tcl_CreateObjCommand (interp,
			  newCommand,
                          NeoX_LdapTargetObjCmd,
                          (ClientData) ldap,
                          NeoX_LdapObjDeleteCmd);
    return TCL_OK;
}

/*-----------------------------------------------------------------------------
 * Neo_initLDAP --
 *     Initialize the LDAP interface.
 *-----------------------------------------------------------------------------
 */     
int
Ldaptcl_Init (interp)
Tcl_Interp   *interp;
{
    Tcl_CreateObjCommand (interp,
			  "ldap",
                          NeoX_LdapObjCmd,
                          (ClientData) NULL,
                          (Tcl_CmdDeleteProc*) NULL);
    Tcl_PkgProvide(interp, "Ldaptcl", "1.1");
    return TCL_OK;
}
