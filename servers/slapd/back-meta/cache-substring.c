/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Apurva Kumar for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#include "ldap_pvt.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "ldap_log.h"
#include "../../../libraries/libldap/ldap-int.h"

#include "slap.h"
#include "back-meta.h"

static char* invert_string(char* string);
static struct berval* merge_init_final(struct berval*, struct berval*, struct berval*); 
static int strings_containment(struct berval* stored, struct berval* incoming); 

/* find and remove string2 from string1 
 * from start if position = 1, 
 * from end if position = 3,
 * from anywhere if position = 2
 */

int 
find_and_remove(struct berval* ber1, struct berval* ber2, int position)
{
	char* temp; 
	int len; 
	int ret=0;

	char* arg1, *arg2;  
	char* string1=ber1->bv_val;
	char* string2=ber2->bv_val;
	
	if (string2 == NULL) 
		return 1; 
	if (string1 == NULL) 
		return 0; 

	if (position == 3) {
		arg1 = invert_string(string1); 
		arg2 = invert_string(string2); 
	} else {
		arg1 = string1; 
		arg2 = string2; 
	}
	    
	temp = strstr(arg1, arg2); 
	len = strlen(arg2); 	

	if (!temp) 
		return 0; 
    
	switch (position) {
	case 1: 
		if (temp == arg1) {
			string1 += len; 
			ret = 1; 
		} else {
			ret = 0; 
		}
		break; 
	case 2: 
		string1 = temp+len;  
		ret = 1; 
		break; 
	case 3: 
		temp = strstr(arg1, arg2); 
		len = strlen(arg2); 	
		if (temp == arg1) {
			/*arg1 += len;*/ 
			string1 = invert_string(arg1+len); 
			free(arg1); 		
			free(arg2); 		
			ret = 1; 
		} else {
			free(arg1); 		
			free(arg2); 		
			ret = 0; 
		}
		break; 
	}
	temp = (char*) malloc( strlen( string1 ) + 1 );
	strcpy( temp, string1 );
	free( ber1->bv_val );
	ber1->bv_val = temp;
	return ret;
}

char*
invert_string( char* string )
{
	int len = strlen(string); 
	int i; 

	char* inverted = (char*)(malloc(len+1)); 

	for (i=0; i<len; i++) 
		inverted[i] = string[len-i-1];

	inverted[len] ='\0'; 

	return inverted; 
}	

struct berval*  
merge_init_final(struct berval* init, struct berval* any, struct berval* final)
{
	struct berval* merged, *temp; 
	int i, any_count, count; 

	for (any_count=0; any && any[any_count].bv_val; any_count++)
		;

	count = any_count; 

	if (init->bv_val) 
		count++; 
	if (final->bv_val)
		count++; 

	merged = (struct berval*)(malloc((count+1)*sizeof(struct berval))); 
	temp = merged; 

	if (init->bv_val) {
		ber_dupbv(temp, init); 
		temp++;
	}

	for (i=0; i<any_count; i++) {
		ber_dupbv(temp, any); 
		any++;
		temp++; 
	} 

	if (final->bv_val){ 
		ber_dupbv(temp, final);
		temp++;
	}	 
	temp->bv_val = NULL; 
	temp->bv_len = 0; 
	return merged; 
}

int
strings_containment(struct berval* stored, struct berval* incoming)
{
	struct berval* element;
	int k=0;
	int j, rc = 0; 
	
	for ( element=stored; element->bv_val != NULL; element++ ) {
		for (j = k; incoming[j].bv_val != NULL; j++) {
			if (find_and_remove(&(incoming[j]), element, 2)) {
				k = j; 
				rc = 1; 
				break; 
			}
			rc = 0; 
		}
		if ( rc ) {
			continue; 
		} else {
			return 0;
		}
	}   
	return 1;
}

int
substr_containment_substr(Filter* stored, Filter* incoming) 
{
	int i; 
	int k=0; 
	int rc; 
	int any_count = 0; 

	struct berval* init_incoming = (struct berval*)(malloc(sizeof(struct berval))); 
	struct berval* final_incoming = (struct berval*)(malloc(sizeof(struct berval)));  
	struct berval* any_incoming = NULL; 
	struct berval* remaining_incoming; 
	struct berval* any_element; 

	if ((!(incoming->f_sub_initial.bv_val) && (stored->f_sub_initial.bv_val)) 
	   || (!(incoming->f_sub_final.bv_val) && (stored->f_sub_final.bv_val))) 
		return 0; 
 
	
	ber_dupbv(init_incoming, &(incoming->f_sub_initial)); 
	ber_dupbv(final_incoming, &(incoming->f_sub_final)); 

	if (incoming->f_sub_any) { 
		for ( any_count=0; incoming->f_sub_any[any_count].bv_val != NULL;
				any_count++ )
			;
	    
		any_incoming = (struct berval*)malloc((any_count+1) *
						sizeof(struct berval)); 
	    
		for (i=0; i<any_count; i++) {
			ber_dupbv(&(any_incoming[i]), &(incoming->f_sub_any[i])); 
		}
		any_incoming[any_count].bv_val = NULL; 
		any_incoming[any_count].bv_len = 0; 
	}
  
	if (find_and_remove(init_incoming, 
			&(stored->f_sub_initial), 1) && find_and_remove(final_incoming, 
			&(stored->f_sub_final), 3)) 
	{
		if (stored->f_sub_any == NULL) {
			rc = 1; 
			goto final; 
		}
		remaining_incoming = merge_init_final(init_incoming,
						any_incoming, final_incoming); 
		rc = strings_containment(stored->f_sub_any, remaining_incoming);
		goto final; 
	}	
	rc = 0; 
final:
	/*
	ber_bvfree(init_incoming);
	ber_bvfree(final_incoming); 
	if (any_incoming) {
		for (i=0; i < any_count; i++) 
			free(any_incoming[i].bv_val);
		free(any_incoming); 
	}	
	*/
		
	return rc; 
}

int
substr_containment_equality(Filter* stored, Filter* incoming) 
{
		
	struct berval* incoming_val = (struct berval*)(malloc(2*sizeof(struct berval)));
	int rc;
 
	ber_dupbv(incoming_val, &(incoming->f_av_value));
	incoming_val[1].bv_val = NULL;
	incoming_val[1].bv_len = 0;
 
	if (find_and_remove(incoming_val, 
			&(stored->f_sub_initial), 1) && find_and_remove(incoming_val, 
			&(stored->f_sub_final), 3)) {
		if (stored->f_sub_any == NULL){ 
			rc = 1;
			goto final;
		}	
		rc = strings_containment(stored->f_sub_any, incoming_val);
		goto final;
	}
	rc=0;
final:
	/*
	if(incoming_val[0].bv_val)
		free(incoming_val[0].bv_val);
	free(incoming_val); 
	*/
	return rc;
}		
