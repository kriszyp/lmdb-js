/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap-int.h"

static const LDAPAPIFeatureInfo features[] = {
#ifdef LDAP_API_FEATURE_X_OPENLDAP
	{	/* OpenLDAP Extensions API Feature */
		LDAP_FEATURE_INFO_VERSION,
		"X_OPENLDAP",
		LDAP_API_FEATURE_X_OPENLDAP
	},
#endif

#ifdef LDAP_API_FEATURE_THREAD_SAFE
	{	/* Basic Thread Safe */
		LDAP_FEATURE_INFO_VERSION,
		"THREAD_SAFE",
		LDAP_API_FEATURE_THREAD_SAFE
	},
#endif
#ifdef LDAP_API_FEATURE_SESSION_THREAD_SAFE
	{	/* Session Thread Safe */
		LDAP_FEATURE_INFO_VERSION,
		"SESSION_THREAD_SAFE",
		LDAP_API_FEATURE_SESSION_THREAD_SAFE
	},
#endif
#ifdef LDAP_API_FEATURE_OPERATION_THREAD_SAFE
	{	/* Operation Thread Safe */
		LDAP_FEATURE_INFO_VERSION,
		"OPERATION_THREAD_SAFE",
		LDAP_API_FEATURE_OPERATION_THREAD_SAFE
	},
#endif
#ifdef LDAP_API_FEATURE_X_OPENLDAP_REENTRANT
	{	/* OpenLDAP Reentrant */
		LDAP_FEATURE_INFO_VERSION,
		"X_OPENLDAP_REENTRANT",
		LDAP_API_FEATURE_X_OPENLDAP_REENTRANT
	},
#endif
#if defined( LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE ) && \
	defined( LDAP_THREAD_SAFE )
	{	/* OpenLDAP Thread Safe */
		LDAP_FEATURE_INFO_VERSION,
		"X_OPENLDAP_THREAD_SAFE",
		LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE
	},
#endif
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
	{	/* DNS */
		LDAP_FEATURE_INFO_VERSION,
		"X_OPENLDAP_V2_DNS",
		LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
	},
#endif
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	{	/* V2 Referrals */
		LDAP_FEATURE_INFO_VERSION,
		"X_OPENLDAP_V2_REFERRALS",
		LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	},
#endif
	{0, NULL, 0}
};

int
ldap_get_option(
	LDAP	*ld,
	int		option,
	void	*outvalue)
{
	struct ldapoptions *lo;

	if(!openldap_ldap_initialized) {
		openldap_ldap_initialize();
	}

	if(outvalue == NULL) {
		/* no place to get to */
		return -1;
	}

	if(ld == NULL) {
		lo = &openldap_ldap_global_options;
	} else {
		lo = &ld->ld_options;
	}

	switch(option) {
	case LDAP_OPT_API_INFO: {
			struct ldapapiinfo *info = (struct ldapapiinfo *) outvalue;

			if(info == NULL) {
				/* outvalue must point to an apiinfo structure */
				return -1;
			}

			if(info->ldapai_info_version != LDAP_API_INFO_VERSION) {
				/* api info version mismatch */
				info->ldapai_info_version = LDAP_API_INFO_VERSION;
				return -1;
			}

			info->ldapai_api_version = LDAP_API_VERSION;
			info->ldapai_api_version = LDAP_API_VERSION;
			info->ldapai_protocol_version = LDAP_VERSION_MAX;

			if(features[0].ldapaif_name == NULL) {
				info->ldapai_extensions = NULL;
			} else {
				int i;
				info->ldapai_extensions = malloc(sizeof(char *) *
					sizeof(features)/sizeof(LDAPAPIFeatureInfo));

				for(i=0; features[i].ldapaif_name != NULL; i++) {
					info->ldapai_extensions[i] =
						strdup(features[i].ldapaif_name);
				}

				info->ldapai_extensions[i] = NULL;
			}

			info->ldapai_vendor_name = strdup(LDAP_VENDOR_NAME);
			info->ldapai_vendor_version = LDAP_VENDOR_VERSION;

			return 0;
		} break;

	case LDAP_OPT_DESC:
		if(ld == NULL) {
			/* bad param */
			break;
		} 

		* (int *) outvalue = ber_pvt_sb_get_desc( &(ld->ld_sb) );
		return 0;

	case LDAP_OPT_DEREF:
		* (int *) outvalue = lo->ldo_deref;
		return 0;

	case LDAP_OPT_SIZELIMIT:
		* (int *) outvalue = lo->ldo_sizelimit;
		return 0;

	case LDAP_OPT_TIMELIMIT:
		* (int *) outvalue = lo->ldo_timelimit;
		return 0;

	case LDAP_OPT_REFERRALS:
		* (int *) outvalue = (LDAP_BOOL_GET(lo, LDAP_BOOL_REFERRALS) ==
				      LDAP_OPT_ON);
		return 0;
		
	case LDAP_OPT_RESTART:
		* (int *) outvalue = (LDAP_BOOL_GET(lo, LDAP_BOOL_RESTART) ==
				      LDAP_OPT_ON);
		return 0;

	case LDAP_OPT_DNS:	/* LDAPv2 */
		* (int *) outvalue = (LDAP_BOOL_GET(lo, LDAP_BOOL_DNS) ==
				      LDAP_OPT_ON);
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION:
		if ((ld != NULL) && ld->ld_version) {
			* (int *) outvalue = ld->ld_version;
		} else { 
			* (int *) outvalue = lo->ldo_version;
		}
		return 0;

	case LDAP_OPT_SERVER_CONTROLS:
		* (LDAPControl ***) outvalue =
			ldap_controls_dup( lo->ldo_sctrls );

		return 0;

	case LDAP_OPT_CLIENT_CONTROLS:
		* (LDAPControl ***) outvalue =
			ldap_controls_dup( lo->ldo_cctrls );

		return 0;

	case LDAP_OPT_HOST_NAME:
		/*
		 * draft-ietf-ldapext-ldap-c-api-01 doesn't state
		 * whether caller has to free host names or not,
		 * we do.
		 */

		* (char **) outvalue = strdup(lo->ldo_defhost);
		return 0;

	case LDAP_OPT_ERROR_NUMBER:
		if(ld == NULL) {
			/* bad param */
			break;
		} 
		* (int *) outvalue = ld->ld_errno;
		return 0;

	case LDAP_OPT_ERROR_STRING:
		if(ld == NULL) {
			/* bad param */
			break;
		} 

		/*
		 * draft-ietf-ldapext-ldap-c-api-01 doesn't require
		 *	the client to have to free error strings, we do
		 */

		if( ld->ld_error == NULL ) {
			* (char **) outvalue = NULL;
		} else {
			* (char **) outvalue = strdup(ld->ld_error);
		}

		return 0;

	case LDAP_OPT_API_FEATURE_INFO: {
			LDAPAPIFeatureInfo *info = (LDAPAPIFeatureInfo *) outvalue;
			int i;

			if(info == NULL) return -1;

			if(info->ldapaif_info_version != LDAP_FEATURE_INFO_VERSION) {
				/* api info version mismatch */
				info->ldapaif_info_version = LDAP_FEATURE_INFO_VERSION;
				return -1;
			}

			if(info->ldapaif_name == NULL) return -1;

			for(i=0; features[i].ldapaif_name != NULL; i++) {
				if(!strcmp(info->ldapaif_name, features[i].ldapaif_name)) {
					info->ldapaif_version =
						features[i].ldapaif_version;
					return 0;
				}
			}
		}
		break;

	case LDAP_OPT_DEBUG_LEVEL:
		* (int *) outvalue = lo->ldo_debug;
		return 0;

	default:
		/* bad param */
		break;
	}

	return -1;
}

int
ldap_set_option(
	LDAP	*ld,
	int		option,
	void	*invalue)
{
	struct ldapoptions *lo;

	if(!openldap_ldap_initialized) {
		openldap_ldap_initialize();
	}

	if(ld == NULL) {
		lo = &openldap_ldap_global_options;
	} else {
		lo = &ld->ld_options;
	}

	switch(option) {
	case LDAP_OPT_REFERRALS:
		if(invalue == LDAP_OPT_ON) {
			LDAP_BOOL_SET(lo, LDAP_BOOL_REFERRALS);
		} else {
			LDAP_BOOL_CLR(lo, LDAP_BOOL_REFERRALS);
		}
		return 0;

	case LDAP_OPT_RESTART:
		if(invalue == LDAP_OPT_ON) {
			LDAP_BOOL_SET(lo, LDAP_BOOL_RESTART);
		} else {
			LDAP_BOOL_CLR(lo, LDAP_BOOL_RESTART);
		}
		return 0;
	}

	if(invalue == NULL) {
		/* no place to set from */
		return -1;
	}

	switch(option) {
	case LDAP_OPT_API_INFO:
	case LDAP_OPT_DESC:
		/* READ ONLY */
		break;

	case LDAP_OPT_DEREF:
		lo->ldo_deref = * (int *) invalue;
		return 0;

	case LDAP_OPT_SIZELIMIT:
		lo->ldo_sizelimit = * (int *) invalue;
		return 0;

	case LDAP_OPT_TIMELIMIT:
		lo->ldo_timelimit = * (int *) invalue;
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION: {
			int vers = * (int *) invalue;
			if (vers < LDAP_VERSION_MIN || vers > LDAP_VERSION_MAX) {
				/* not supported */
				break;
			}
			ld->ld_version = vers;
		} return 0;

	case LDAP_OPT_SERVER_CONTROLS: {
			LDAPControl **controls = (LDAPControl **) invalue;

			ldap_controls_free( lo->ldo_sctrls );

			if( controls == NULL || *controls == NULL ) {
				lo->ldo_sctrls = NULL;
				return 0;
			}
				
			lo->ldo_sctrls =
				ldap_controls_dup( (LDAPControl **) invalue );

			if(lo->ldo_sctrls == NULL) {
				/* memory allocation error ? */
				break;
			}
		} return 0;

	case LDAP_OPT_CLIENT_CONTROLS: {
			LDAPControl **controls = (LDAPControl **) invalue;

			ldap_controls_free( lo->ldo_cctrls );

			if( controls == NULL || *controls == NULL ) {
				lo->ldo_cctrls = NULL;
				return 0;
			}
				
			lo->ldo_cctrls =
				ldap_controls_dup( (LDAPControl **) invalue );

			if(lo->ldo_cctrls == NULL) {
				/* memory allocation error ? */
				break;
			}
		} return 0;

	case LDAP_OPT_HOST_NAME: {
			char* host = (char *) invalue;

			if(lo->ldo_defhost != NULL) {
				free(lo->ldo_defhost);
				lo->ldo_defhost = NULL;
			}

			if(host != NULL) {
				lo->ldo_defhost = strdup(host);
				return 0;
			}

			if(ld == NULL) {
				/*
				 * must want global default returned
				 * to initial condition.
				 */
				lo->ldo_defhost = strdup("localhost");

			} else {
				/*
				 * must want the session default
				 *   updated to the current global default
				 */
				lo->ldo_defhost = strdup(
					openldap_ldap_global_options.ldo_defhost);
			}
		} return 0;

	case LDAP_OPT_ERROR_NUMBER: {
			int err = * (int *) invalue;

			if(ld == NULL) {
				/* need a struct ldap */
				break;
			}

			ld->ld_errno = err;
		} return 0;

	case LDAP_OPT_ERROR_STRING: {
			char* err = (char *) invalue;

			if(ld == NULL) {
				/* need a struct ldap */
				break;
			}

			if( ld->ld_error ) {
				free(ld->ld_error);
			}

			ld->ld_error = strdup(err);
		} return 0;

	case LDAP_OPT_API_FEATURE_INFO:
		/* read-only */
		break;

	case LDAP_OPT_DEBUG_LEVEL:
		lo->ldo_debug = * (int *) invalue;
		return 0;

	default:
		/* bad param */
		break;
	}
	return -1;
}
