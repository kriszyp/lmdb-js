/*
 * OpenLDAP API Test
 *	Written by: Kurt Zeilenga
 *
 * This program is designed to test libldap API for conformance
 * to draft-api-ldapext-ldap-c-api-01.txt.
 */
#include "portable.h"

#include <stdio.h>
#include <ac/time.h>

#include "lber.h"
#include "ldap.h"

void
main(int argc, char **argv)
{
	LDAPAPIInfo api;
	int ival;
	int sval;

#ifdef LDAP_API_INFO_VERSION
	api.ldapai_info_version = LDAP_API_INFO_VERSION;
#else
	api.ldapai_info_version = 1;
#endif

	printf("Compile time API Information\n");
	printf("  API Info version:  %d\n", api.ldapai_info_version);
	printf("  API version:       %d\n", LDAP_API_VERSION);
#ifdef LDAP_VERSION
	printf("  Protocol Version:  %d\n", LDAP_VERSION);
#else
	printf("  Protocol Version:  unknown\n");
#endif
#ifdef LDAP_VERSION_MIN
	printf("  Protocol Min:      %d\n", LDAP_VERSION_MIN);
#else
	printf("  Protocol Min:      unknown\n");
#endif
#ifdef LDAP_VERSION_MAX
	printf("  Protocol Max:      %d\n", LDAP_VERSION_MAX);
#else
	printf("  Protocol Max:      unknown\n");
#endif
#ifdef LDAP_VENDOR_NAME
	printf("  Vendor Name:       %s\n", LDAP_VENDOR_NAME);
#else
	printf("  Vendor Name:       unknown\n");
#endif
#ifdef LDAP_VENDOR_VERSION
	printf("  Vendor Version:    %d\n", LDAP_VENDOR_VERSION);
#else
	printf("  Vendor Version:    unknown\n");
#endif

	if(ldap_get_option(NULL, LDAP_OPT_API_INFO, &api) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(api) failed", argv[0]);
		exit(-1);
	}

	printf("\nExecution time API Information\n");
	printf("  API Info version:  %d\n", api.ldapai_info_version);

	if (api.ldapai_info_version != LDAP_API_INFO_VERSION) {
		printf(" API INFO version mismatch!");
		exit(-1);
	}

	printf("  API Version:       %d\n", api.ldapai_api_version);
	printf("  Protocol Max:      %d\n", api.ldapai_protocol_version);
	if(api.ldapai_extensions == NULL) {
		printf("  Extensions:        none\n");
	} else {
		int i;
		for(i=0; api.ldapai_extensions[i] != NULL; i++) {
			printf("                     %s\n",
				api.ldapai_extensions[i]);
		}
		printf("  #Extensions:       %d\n", i);
	}
	printf("  Vendor Name:       %s\n", api.ldapai_vendor_name);
	printf("  Vendor Version:    %d\n", api.ldapai_vendor_version);

	printf("\nExecution time Default Options\n");

	if(ldap_get_option(NULL, LDAP_OPT_DEREF, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(api) failed", argv[0]);
		exit(-1);
	}
	printf("  DEREF:             %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_SIZELIMIT, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(sizelimit) failed", argv[0]);
		exit(-1);
	}
	printf("  SIZELIMIT:         %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_TIMELIMIT, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(timelimit) failed", argv[0]);
		exit(-1);
	}
	printf("  TIMELIMIT:         %d\n", ival);
}
