#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap-int.h"

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
			info->ldapai_extensions = NULL;
			info->ldapai_vendor_name = strdup(LDAP_VENDOR_NAME);
			info->ldapai_vendor_version = LDAP_VENDOR_VERSION;

			return 0;
		} break;

	case LDAP_OPT_DESC:
		if(ld == NULL) {
			/* bad param */
			break;
		} 

		* (int *) outvalue = ld->ld_sb.sb_sd;
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
		* (int *) outvalue = (int) LDAP_BOOL_GET(lo, LDAP_BOOL_REFERRALS);
		return 0;
		
	case LDAP_OPT_RESTART:
		* (int *) outvalue = (int) LDAP_BOOL_GET(lo, LDAP_BOOL_RESTART);
		return 0;

	case LDAP_OPT_DNS:	/* LDAPv2 */
		* (int *) outvalue = (int) LDAP_BOOL_GET(lo, LDAP_BOOL_DNS);
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION:
		if(ld == NULL) {
			/* bad param */
			break;
		} 

		* (int *) outvalue = ld->ld_version;
		return 0;

	case LDAP_OPT_SERVER_CONTROLS:
	case LDAP_OPT_CLIENT_CONTROLS:
		/* not yet supported */
		break;

	case LDAP_OPT_HOST_NAME:
		if(ld == NULL) {
			/* bad param */
			break;
		} 
		* (char **) outvalue = ld->ld_host;
		return 0;

	case LDAP_OPT_ERROR_NUMBER:
		if(ld == NULL) {
			/* bad param */
			break;
		} 
		* (int *) outvalue = ld->ld_errno;
		return 0;

	case LDAP_OPT_ERROR_STRING:
		/* not yet supported */
		if(ld == NULL) {
			/* bad param */
			break;
		} 
		break;

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

	if(invalue == NULL) {
		/* no place to set from */
		return -1;
	}

	if(ld == NULL) {
		lo = &openldap_ldap_global_options;
	} else {
		lo = &ld->ld_options;
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

	case LDAP_OPT_REFERRALS:
		if((int) invalue == (int) LDAP_OPT_ON) {
			LDAP_BOOL_SET(lo, LDAP_BOOL_REFERRALS);
		} else {
			LDAP_BOOL_CLR(lo, LDAP_BOOL_REFERRALS);
		}
		return 0;

	case LDAP_OPT_RESTART:
		if((int) invalue == (int) LDAP_OPT_ON) {
			LDAP_BOOL_SET(lo, LDAP_BOOL_RESTART);
		} else {
			LDAP_BOOL_CLR(lo, LDAP_BOOL_RESTART);
		}
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION: {
			int vers = * (int *) invalue;
			if (vers < LDAP_VERSION_MIN || vers > LDAP_VERSION_MAX) {
				/* not supported */
				break;
			}
			ld->ld_version = vers;
		} return 0;

	case LDAP_OPT_SERVER_CONTROLS:
	case LDAP_OPT_CLIENT_CONTROLS:
	case LDAP_OPT_HOST_NAME:
	case LDAP_OPT_ERROR_NUMBER:
	case LDAP_OPT_ERROR_STRING:
		/* not yet supported */
		break;
	default:
		/* bad param */
		break;
	}
	return -1;
}
