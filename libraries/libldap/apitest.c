/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * OpenLDAP API Test
 *	Written by: Kurt Zeilenga
 *
 * This program is designed to test API features of libldap.
 *
 * The API specification can be found in:
 *
 *	 draft-api-ldapext-ldap-c-api-01.txt 
 *
 * and discussions on ietf-ldapext mailing list.
 *
 */
#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include "lber.h"
#include "ldap.h"

int
main(int argc, char **argv)
{
	LDAPAPIInfo api;
	int ival;
	char *sval;

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
		fprintf(stderr, "%s: ldap_get_option(api) failed\n", argv[0]);
		exit(-1);
	}

	printf("\nExecution time API Information\n");
	printf("  API Info version:  %d\n", api.ldapai_info_version);

	if (api.ldapai_info_version != LDAP_API_INFO_VERSION) {
		printf(" API INFO version mismatch!\n");
		exit(-1);
	}

	printf("  API Version:       %d\n", api.ldapai_api_version);
	printf("  Protocol Max:      %d\n", api.ldapai_protocol_version);

	if(api.ldapai_extensions == NULL) {
		printf("  Extensions:        none\n");

	} else {
		int i;
		for(i=0; api.ldapai_extensions[i] != NULL; i++) /* empty */;
		printf("  Extensions:        %d\n", i);
		for(i=0; api.ldapai_extensions[i] != NULL; i++) {
#ifndef LDAP_API_FEATURE_INFO
			printf("                     %s\n",
				api.ldapai_extensions[i]);
#else
			LDAPAPIFeatureInfo fi;
			fi.ldapaif_name = api.ldapai_extensions[i];
			fi.ldapaif_version = 0;

			ldap_get_option(NULL, LDAP_OPT_API_FEATURE_INFO, &fi);

			printf("                     %s (%d)\n",
				api.ldapai_extensions[i], fi.ldapaif_version);
#endif
		}
	}

	printf("  Vendor Name:       %s\n", api.ldapai_vendor_name);
	printf("  Vendor Version:    %d\n", api.ldapai_vendor_version);

	printf("\nExecution time Default Options\n");

	if(ldap_get_option(NULL, LDAP_OPT_DEREF, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(api) failed\n", argv[0]);
		exit(-1);
	}
	printf("  DEREF:             %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_SIZELIMIT, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(sizelimit) failed\n", argv[0]);
		exit(-1);
	}
	printf("  SIZELIMIT:         %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_TIMELIMIT, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(timelimit) failed\n", argv[0]);
		exit(-1);
	}
	printf("  TIMELIMIT:         %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_REFERRALS, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(referrals) failed\n", argv[0]);
		exit(-1);
	}
	printf("  REFERRALS:         %s\n",
		ival == (int) LDAP_OPT_ON ? "on" : "off");

	if(ldap_get_option(NULL, LDAP_OPT_RESTART, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(restart) failed\n", argv[0]);
		exit(-1);
	}
	printf("  RESTART:           %s\n",
		ival == (int) LDAP_OPT_ON ? "on" : "off");

	if(ldap_get_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &ival) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(protocol version) failed\n", argv[0]);
		exit(-1);
	}
	printf("  PROTOCOL VERSION:  %d\n", ival);

	if(ldap_get_option(NULL, LDAP_OPT_HOST_NAME, &sval) != LDAP_SUCCESS) {
		fprintf(stderr, "%s: ldap_get_option(host name) failed\n", argv[0]);
		exit(-1);
	}
	printf("  HOST NAME:         %s\n", sval);

	exit(0);
	return 0;
}
