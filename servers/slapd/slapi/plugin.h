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

#ifndef _PLUGIN_H_ 
#define _PLUGIN_H_ 

Slapi_PBlock *newPlugin ( int type, const char *path, const char *initfunc,
		int argc, char *argv[] );
int insertPlugin(Backend *be, Slapi_PBlock *pPB);
int doPluginFNs(Backend *be, int funcType, Slapi_PBlock * pPB);
int getAllPluginFuncs(Backend *be, int functype, SLAPI_FUNC **ppFuncPtrs);
int newExtendedOp(Backend *pBE, ExtendedOp **opList, Slapi_PBlock *pPB);
int getPluginFunc(struct berval  *reqoid, SLAPI_FUNC *pFuncAddr );
int netscape_plugin(Backend *be, const char *fname, int lineno,
		int argc, char **argv );
int slapi_init(void);

#endif /* _PLUGIN_H_ */

