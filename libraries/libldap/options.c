#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap-int.h"

int
ldap_get_option(
	LDAP	*ldp,
	int		option,
	void	*outvalue)
{
	LDAP *ld;

	if(!openldap_ldap_initialized) {
		openldap_ldap_initialize();
	}

	if(outvalue == NULL) {
		/* no place to get to */
		return -1;
	}

	if(ldp == NULL) {
		ld = &openldap_ld_globals;
	} else {
		ld = ldp;
	}

	switch(option) {
	case LDAP_OPT_API_INFO: {
			struct ldapapiinfo *info = (struct ldapapiinfo *) outvalue;

			if(info == NULL) {
				/* outvalue must point to an apiinfo structure */
				return -1;
			}

			if(info->ldapai_info_version != 1) {
				/* version mismatch */
				return -1;
			}

			info->ldapai_api_version = LDAP_API_VERSION;
			info->ldapai_protocol_version = LDAP_VERSION_MAX;
			info->ldapai_extensions = NULL;
			info->ldapai_vendor_name = strdup(LDAP_VENDOR);
			info->ldapai_vendor_version = LDAP_VENDOR_VERSION;

			return 0;
		} break;

	case LDAP_OPT_DESC:
		if(ldp == NULL) {
			/* bad param */
			break;
		} 

		* (int *) outvalue = ld->ld_sb.sb_sd;
		return 0;

	case LDAP_OPT_DEREF:
		* (int *) outvalue = ld->ld_deref;
		return 0;

	case LDAP_OPT_SIZELIMIT:
		* (int *) outvalue = ld->ld_sizelimit;
		return 0;

	case LDAP_OPT_TIMELIMIT:
		* (int *) outvalue = ld->ld_timelimit;
		return 0;

	case LDAP_OPT_REFERRALS:
		* (int *) outvalue = (int) LDAP_BOOL_GET(ld, LDAP_BOOL_REFERRALS);
		return 0;
		
	case LDAP_OPT_RESTART:
		* (int *) outvalue = (int) LDAP_BOOL_GET(ld, LDAP_BOOL_RESTART);
		return 0;

	case LDAP_OPT_DNS:	/* LDAPv2 */
		* (int *) outvalue = (int) LDAP_BOOL_GET(ld, LDAP_BOOL_DNS);
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION:
		* (int *) outvalue = ld->ld_version;
		return 0;

	case LDAP_OPT_SERVER_CONTROLS:
	case LDAP_OPT_CLIENT_CONTROLS:
		/* not yet supported */
		break;

	case LDAP_OPT_HOST_NAME:
		* (char **) outvalue = ld->ld_host;
		return 0;

	case LDAP_OPT_ERROR_NUMBER:
		* (int *) outvalue = ld->ld_errno;
		return 0;

	case LDAP_OPT_ERROR_STRING:
		/* not yet supported */
		break;

	default:
		/* bad param */
		break;
	}

	return -1;
}

int
ldap_set_option(
	LDAP	*ldp,
	int		option,
	void	*invalue)
{
	LDAP *ld;

	if(!openldap_ldap_initialized) {
		openldap_ldap_initialize();
	}

	if(invalue == NULL) {
		/* no place to set from */
		return -1;
	}

	if(ldp == NULL) {
		ld = &openldap_ld_globals;
	} else {
		ld = ldp;
	}

	switch(option) {
	case LDAP_OPT_API_INFO:
	case LDAP_OPT_DESC:
		/* READ ONLY */
		break;

	case LDAP_OPT_DEREF:
		ld->ld_deref = * (int *) invalue;
		return 0;

	case LDAP_OPT_SIZELIMIT:
		ld->ld_sizelimit = * (int *) invalue;
		return 0;

	case LDAP_OPT_TIMELIMIT:
		ld->ld_timelimit = * (int *) invalue;
		return 0;

	case LDAP_OPT_REFERRALS:
		if((int) invalue == (int) LDAP_OPT_ON) {
			LDAP_BOOL_SET(ld, LDAP_BOOL_REFERRALS);
		} else {
			LDAP_BOOL_CLR(ld, LDAP_BOOL_REFERRALS);
		}
		return 0;

	case LDAP_OPT_RESTART:
		if((int) invalue == (int) LDAP_OPT_ON) {
			LDAP_BOOL_SET(ld, LDAP_BOOL_RESTART);
		} else {
			LDAP_BOOL_CLR(ld, LDAP_BOOL_RESTART);
		}
		return 0;

	case LDAP_OPT_PROTOCOL_VERSION: {
			int vers = * (int *) invalue;
			if (vers > LDAP_VERSION_MAX) {
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
