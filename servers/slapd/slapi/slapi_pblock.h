/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#ifndef SLAPI_PBLOCK_H
#define SLAPI_PBLOCK_H

#define CMP_EQUAL 0
#define CMP_GREATER 1
#define CMP_LOWER (-1)
#define PBLOCK_ERROR (-1)
#define INVALID_PARAM PBLOCK_ERROR
#define MAX_PARAMS 100

struct slapi_pblock {
	ldap_pvt_thread_mutex_t	pblockMutex;
	int			ckParams;
	int			numParams;
	int			curParams[MAX_PARAMS];
	void			*curVals[MAX_PARAMS];
};

Slapi_PBlock *slapi_pblock_new();
void slapi_pblock_destroy( Slapi_PBlock* );
int slapi_pblock_get( Slapi_PBlock *pb, int arg, void *value );
int slapi_pblock_set( Slapi_PBlock *pb, int arg, void *value );
void slapi_pblock_check_params(Slapi_PBlock *pb, int flag);
int slapi_pblock_delete_param(Slapi_PBlock *p, int param);
void slapi_pblock_clear(Slapi_PBlock *pb); 

/*
 * OpenLDAP extensions
 */
int slapi_x_pblock_get_first( Backend *be, Slapi_PBlock **pb );
int slapi_x_pblock_get_next( Slapi_PBlock **pb );

#endif /* SLAPI_PBLOCK_H */

