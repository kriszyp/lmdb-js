/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Portions Copyright IBM Corp. 1997,2002-2003
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License, version 2.7 or later.
 */

#ifdef LDAP_SLAPI /* SLAPI is OPTIONAL */

#ifndef _SLAPI_H
#define _SLAPI_H

#include <ibm_pblock_params.h> 

LDAP_BEGIN_DECL

/*
 * Quick 'n' dirty to make struct slapi_* in slapi-plugin.h opaque
 */
#define slapi_entry	slap_entry
#define slapi_attr	slap_attr
#define slapi_value	berval
#define slapi_valueset	berval*
#define slapi_filter	slap_filter

LDAP_END_DECL

#include <slapi-plugin.h>

LDAP_BEGIN_DECL

/*
 * Was: slapi_common.h
 */

/* a little naif ... */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#if 0	/* unused (yet?) */
#define dn_normalize_case	dn_normalize
#define SLAPD_NO_MEMORY    	7
#define ANYBODY_STRING 		"CN=ANYBODY"

extern int slap_debug;

extern int dn_check(char *, int *);

typedef struct strlist {
	char *string;
	struct strlist *next;
} StrList;
#endif

extern struct berval *ns_get_supported_extop( int );

/*
 * Was: slapi_utils.h
 */
typedef struct _Audit_record Audit_record;

#define SLAPI_CONTROL_MANAGEDSAIT_OID		LDAP_CONTROL_MANAGEDSAIT
#define SLAPI_CONTROL_SORTEDSEARCH_OID		LDAP_CONTROL_SORTREQUEST
#define SLAPI_CONTROL_PAGED_RESULTS_OID		LDAP_CONTROL_PAGEDRESULTS

typedef int (*SLAPI_FUNC)( Slapi_PBlock *pb );

#if 0	/* unused (yet?) */
#define DOMAIN "Domain"
#define TCPIPPATH "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#endif

typedef struct _slapi_control {
        int			s_ctrl_num;
        char			**s_ctrl_oids;
        unsigned long		*s_ctrl_ops;
} Slapi_Control;

typedef struct _ExtendedOp {
	struct berval		ext_oid;
        SLAPI_FUNC		ext_func;
        Backend			*ext_be;
        struct _ExtendedOp	*ext_next;
} ExtendedOp;

/* Computed attribute support */
struct _computed_attr_context {
	/* slap_send_search_entry() argblock */
	Slapi_PBlock	*cac_pb;
	AttributeName	*cac_attrs;
	int		cac_attrsonly : 1;
	int		cac_userattrs : 1;
	int 		cac_opattrs : 1;
	AccessControlState	cac_acl_state;
	/* private data */
	void *cac_private;
};

/* for slapi_attr_type_cmp() */
#define SLAPI_TYPE_CMP_EXACT	0
#define SLAPI_TYPE_CMP_BASE	1
#define SLAPI_TYPE_CMP_SUBTYPE	2

typedef enum slapi_extension_e {
	SLAPI_X_EXT_CONNECTION = 0,
	SLAPI_X_EXT_OPERATION = 1,
	SLAPI_X_EXT_MAX = 2
} slapi_extension_t;

/*
 * Was: slapi_pblock.h
 */

#ifndef NO_PBLOCK_CLASS		/* where's this test from? */

#if 0	/* unused (yet?) */
#define CMP_EQUAL			0
#define CMP_GREATER			1
#define CMP_LOWER			(-1)
#endif
#define PBLOCK_ERROR			(-1)
#define INVALID_PARAM			PBLOCK_ERROR
#define PBLOCK_MAX_PARAMS		100

struct slapi_pblock {
	ldap_pvt_thread_mutex_t	pblockMutex;
	int			ckParams;
	int			numParams;
	int			curParams[PBLOCK_MAX_PARAMS];
	void			*curVals[PBLOCK_MAX_PARAMS];
};

#endif /* !NO_PBLOCK_CLASS */

/*
 * Was: plugin.h
 */

#define SLAPI_PLUGIN_IS_POST_FN(x) ((x) >= SLAPI_PLUGIN_POST_BIND_FN && (x) <= SLAPI_PLUGIN_POST_RESULT_FN)

/*
 * Was: slapi_cl.h
 */

#if 0
#define TIME_SIZE 20
#define OBJECTCLASS "objectclass"
#define TOP "top"
#define CHANGE_TIME "changetime"
#define CHANGE_TYPE "changetype"
#define CHANGE_TARGETDN "targetdn"
#define CHANGES	"changes"
#define CHANGE_NUMBER "changenumber"
/*
 * FIXME: I get complaints like "ADD" being redefined - first definition
 * being in "/usr/include/arpa/nameser.h:552"
 */
#undef ADD
#define ADD "add: "
#define ADDLEN 5
#define DEL "delete: "
#define DELLEN 8
#define REPLACE "replace: "
#define REPLEN 9
#define MOD "modify"
#define MODRDN "modrdn"
#define CHANGE_LOGENTRY "changelogentry"
#define IBM_CHANGE_LOGENTRY "ibm-changelog"
#define CL_NEWRDN "newrdn"
#define CL_DELRDN "deleteoldrdn"
#define CHANGE_INITIATOR "ibm-changeInitiatorsName" 

extern void slapi_register_changelog_suffix(char *suffix);
extern char **slapi_get_changelog_suffixes();
extern void slapi_update_changelog_counters(long curNum, long numEntries);
extern char *slapi_get_cl_firstNum();
extern char *slapi_get_cl_lastNum();
extern int slapi_add_to_changelog(Slapi_Entry *ent, char *suffix, char *chNum, Operation* op);	
extern int slapi_delete_changelog(char *dn, char *suffix, char *chNum, Operation* op);	
extern int slapi_modify_changelog(char *dn,LDAPMod	*mods,char *suffix, char *chNum, Operation* op); 
extern int slapi_modifyrdn_changelog(char *olddn, char *newRdn, int delRdn, char *suffix, char *chNum, Operation* op);
extern Backend * slapi_cl_get_be(char *dn);
#endif


/*
 * Attribute flags returned by slapi_attr_get_flags()
 */
#define SLAPI_ATTR_FLAG_SINGLE		0x0001
#define SLAPI_ATTR_FLAG_OPATTR		0x0002
#define SLAPI_ATTR_FLAG_READONLY	0x0004
#define SLAPI_ATTR_FLAG_STD_ATTR	SLAPI_ATTR_FLAG_READONLY
#define SLAPI_ATTR_FLAG_OBSOLETE	0x0040
#define SLAPI_ATTR_FLAG_COLLECTIVE	0x0080
#define SLAPI_ATTR_FLAG_NOUSERMOD	0x0100

/*
 * ACL levels
 */
#define SLAPI_ACL_COMPARE	0x01
#define SLAPI_ACL_SEARCH	0x02
#define SLAPI_ACL_READ		0x04
#define SLAPI_ACL_WRITE		0x08
#define SLAPI_ACL_DELETE	0x10
#define SLAPI_ACL_ADD		0x20
#define SLAPI_ACL_SELF		0x40
#define SLAPI_ACL_PROXY		0x80
#define SLAPI_ACL_ALL		0x7f

/*
 * Plugin types universally supported by SLAPI
 * implementations
 */
#define SLAPI_PLUGIN_DATABASE           1
#define SLAPI_PLUGIN_EXTENDEDOP         2
#define SLAPI_PLUGIN_PREOPERATION       3
#define SLAPI_PLUGIN_POSTOPERATION      4
#define SLAPI_PLUGIN_MATCHINGRULE       5
#define SLAPI_PLUGIN_SYNTAX             6
/* XXX this is SLAPI_PLUGIN_ACL in SunDS */
#define SLAPI_PLUGIN_AUDIT              7
/*
 * The following plugin types are reserved for future
 * Sun ONE DS compatability.
 */
#define SLAPI_PLUGIN_BEPREOPERATION             8       
#define SLAPI_PLUGIN_BEPOSTOPERATION            9       
#define SLAPI_PLUGIN_ENTRY                      10      
#define SLAPI_PLUGIN_TYPE_OBJECT                11      
#define SLAPI_PLUGIN_INTERNAL_PREOPERATION      12      
#define SLAPI_PLUGIN_INTERNAL_POSTOPERATION     13
#define SLAPI_PLUGIN_PWD_STORAGE_SCHEME         14
#define SLAPI_PLUGIN_VATTR_SP                   15
#define SLAPI_PLUGIN_REVER_PWD_STORAGE_SCHEME   16

#define SLAPI_PLUGIN_EXTENDED_SENT_RESULT       -1
#define SLAPI_PLUGIN_EXTENDED_NOT_HANDLED       -2

#define SLAPI_BIND_SUCCESS		0
#define SLAPI_BIND_FAIL			2
#define SLAPI_BIND_ANONYMOUS		3

#define SLAPI_BACKEND				130
#define SLAPI_CONNECTION			131
#define SLAPI_OPERATION				132
#define SLAPI_REQUESTOR_ISROOT			133
#define SLAPI_BE_MONITORDN			134
#define SLAPI_BE_TYPE           		135
#define SLAPI_BE_READONLY       		136
#define SLAPI_BE_LASTMOD       			137
#define SLAPI_OPERATION_PARAMETERS		138
#define SLAPI_CONN_ID        			139

#define SLAPI_OPINITIATED_TIME			140
#define SLAPI_REQUESTOR_DN			141
#define SLAPI_REQUESTOR_ISUPDATEDN		142
#define SLAPI_IS_REPLICATED_OPERATION		SLAPI_REQUESTOR_ISUPDATEDN
#define SLAPI_CONN_DN        			143
#define SLAPI_CONN_AUTHTYPE    			144
#define SLAPI_CONN_CLIENTIP			145
#define SLAPI_CONN_SERVERIP			146
#define SLAPI_X_CONN_CLIENTPATH			1300
#define SLAPI_X_CONN_SERVERPATH			1301
#define SLAPI_X_CONN_IS_UDP			1302
#define SLAPI_X_CONN_SSF			1303
#define SLAPI_X_CONN_SASL_CONTEXT		1304

#define SLAPD_AUTH_NONE   "none"
#define SLAPD_AUTH_SIMPLE "simple"
#define SLAPD_AUTH_SSL    "SSL"
#define SLAPD_AUTH_SASL   "SASL "

#define SLAPI_PLUGIN				3
#define SLAPI_PLUGIN_PRIVATE			4
#define SLAPI_PLUGIN_TYPE			5
#define SLAPI_PLUGIN_ARGV			6
#define SLAPI_PLUGIN_ARGC			7
#define SLAPI_PLUGIN_VERSION			8

#define SLAPI_PLUGIN_OPRETURN			9
#define SLAPI_PLUGIN_OBJECT			10
#define SLAPI_PLUGIN_DESTROY_FN			11

#define SLAPI_PLUGIN_DESCRIPTION		12

#define SLAPI_PLUGIN_INTOP_RESULT		15
#define SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES	16
#define SLAPI_PLUGIN_INTOP_SEARCH_REFERRALS	17

#define SLAPI_PLUGIN_DB_BIND_FN			200
#define SLAPI_PLUGIN_DB_UNBIND_FN		201
#define SLAPI_PLUGIN_DB_SEARCH_FN		202
#define SLAPI_PLUGIN_DB_COMPARE_FN		203
#define SLAPI_PLUGIN_DB_MODIFY_FN		204
#define SLAPI_PLUGIN_DB_MODRDN_FN		205
#define SLAPI_PLUGIN_DB_ADD_FN			206
#define SLAPI_PLUGIN_DB_DELETE_FN		207
#define SLAPI_PLUGIN_DB_ABANDON_FN		208
#define SLAPI_PLUGIN_DB_CONFIG_FN		209
#define SLAPI_PLUGIN_CLOSE_FN			210
#define SLAPI_PLUGIN_DB_FLUSH_FN		211
#define SLAPI_PLUGIN_START_FN			212
#define SLAPI_PLUGIN_DB_SEQ_FN			213
#define SLAPI_PLUGIN_DB_ENTRY_FN		214
#define SLAPI_PLUGIN_DB_REFERRAL_FN		215
#define SLAPI_PLUGIN_DB_RESULT_FN		216
#define SLAPI_PLUGIN_DB_LDIF2DB_FN		217
#define SLAPI_PLUGIN_DB_DB2LDIF_FN		218
#define SLAPI_PLUGIN_DB_BEGIN_FN		219
#define SLAPI_PLUGIN_DB_COMMIT_FN		220
#define SLAPI_PLUGIN_DB_ABORT_FN		221
#define SLAPI_PLUGIN_DB_ARCHIVE2DB_FN		222
#define SLAPI_PLUGIN_DB_DB2ARCHIVE_FN		223
#define SLAPI_PLUGIN_DB_NEXT_SEARCH_ENTRY_FN	224
#define SLAPI_PLUGIN_DB_FREE_RESULT_SET_FN	225
#define	SLAPI_PLUGIN_DB_SIZE_FN			226
#define	SLAPI_PLUGIN_DB_TEST_FN			227
#define SLAPI_PLUGIN_DB_NO_ACL        		250

#define SLAPI_PLUGIN_EXT_OP_FN			300
#define SLAPI_PLUGIN_EXT_OP_OIDLIST		301
#define SLAPI_PLUGIN_PRE_BIND_FN		401
#define SLAPI_PLUGIN_PRE_UNBIND_FN		402
#define SLAPI_PLUGIN_PRE_SEARCH_FN		403
#define SLAPI_PLUGIN_PRE_COMPARE_FN		404
#define SLAPI_PLUGIN_PRE_MODIFY_FN		405
#define SLAPI_PLUGIN_PRE_MODRDN_FN		406
#define SLAPI_PLUGIN_PRE_ADD_FN			407
#define SLAPI_PLUGIN_PRE_DELETE_FN		408
#define SLAPI_PLUGIN_PRE_ABANDON_FN		409
#define SLAPI_PLUGIN_PRE_ENTRY_FN		410
#define SLAPI_PLUGIN_PRE_REFERRAL_FN		411
#define SLAPI_PLUGIN_PRE_RESULT_FN		412
#define SLAPI_PLUGIN_POST_BIND_FN		501
#define SLAPI_PLUGIN_POST_UNBIND_FN		502
#define SLAPI_PLUGIN_POST_SEARCH_FN		503
#define SLAPI_PLUGIN_POST_COMPARE_FN		504
#define SLAPI_PLUGIN_POST_MODIFY_FN		505
#define SLAPI_PLUGIN_POST_MODRDN_FN		506
#define SLAPI_PLUGIN_POST_ADD_FN		507
#define SLAPI_PLUGIN_POST_DELETE_FN		508
#define SLAPI_PLUGIN_POST_ABANDON_FN		509
#define SLAPI_PLUGIN_POST_ENTRY_FN		510
#define SLAPI_PLUGIN_POST_REFERRAL_FN		511
#define SLAPI_PLUGIN_POST_RESULT_FN		512

#define SLAPI_OPERATION_TYPE			590

#define SLAPI_PLUGIN_MR_FILTER_CREATE_FN	600
#define SLAPI_PLUGIN_MR_INDEXER_CREATE_FN	601
#define SLAPI_PLUGIN_MR_FILTER_MATCH_FN		602
#define SLAPI_PLUGIN_MR_FILTER_INDEX_FN		603
#define SLAPI_PLUGIN_MR_FILTER_RESET_FN		604
#define SLAPI_PLUGIN_MR_INDEX_FN		605
#define SLAPI_PLUGIN_MR_OID			610
#define SLAPI_PLUGIN_MR_TYPE			611
#define SLAPI_PLUGIN_MR_VALUE			612
#define SLAPI_PLUGIN_MR_VALUES			613
#define SLAPI_PLUGIN_MR_KEYS			614
#define SLAPI_PLUGIN_MR_FILTER_REUSABLE		615
#define SLAPI_PLUGIN_MR_QUERY_OPERATOR		616
#define SLAPI_PLUGIN_MR_USAGE			617

#define SLAPI_OP_LESS					1
#define SLAPI_OP_LESS_OR_EQUAL				2
#define SLAPI_OP_EQUAL					3
#define SLAPI_OP_GREATER_OR_EQUAL			4
#define SLAPI_OP_GREATER				5
#define SLAPI_OP_SUBSTRING				6

#define SLAPI_PLUGIN_MR_USAGE_INDEX		0
#define SLAPI_PLUGIN_MR_USAGE_SORT		1

#define SLAPI_MATCHINGRULE_NAME			1
#define SLAPI_MATCHINGRULE_OID			2
#define SLAPI_MATCHINGRULE_DESC			3
#define SLAPI_MATCHINGRULE_SYNTAX		4
#define SLAPI_MATCHINGRULE_OBSOLETE		5

#define SLAPI_PLUGIN_SYNTAX_FILTER_AVA		700
#define SLAPI_PLUGIN_SYNTAX_FILTER_SUB		701
#define SLAPI_PLUGIN_SYNTAX_VALUES2KEYS		702
#define SLAPI_PLUGIN_SYNTAX_ASSERTION2KEYS_AVA	703
#define SLAPI_PLUGIN_SYNTAX_ASSERTION2KEYS_SUB	704
#define SLAPI_PLUGIN_SYNTAX_NAMES		705
#define SLAPI_PLUGIN_SYNTAX_OID			706
#define SLAPI_PLUGIN_SYNTAX_FLAGS		707
#define SLAPI_PLUGIN_SYNTAX_COMPARE		708

#define SLAPI_PLUGIN_ACL_INIT			730
#define SLAPI_PLUGIN_ACL_SYNTAX_CHECK		731
#define SLAPI_PLUGIN_ACL_ALLOW_ACCESS		732
#define SLAPI_PLUGIN_ACL_MODS_ALLOWED		733
#define SLAPI_PLUGIN_ACL_MODS_UPDATE		734

#define SLAPI_OPERATION_AUTHTYPE		741
#define SLAPI_OPERATION_ID			742
#define SLAPI_CONN_CERT				743
#define SLAPI_CONN_AUTHMETHOD			746

#define SLAPI_RESULT_CODE			881
#define SLAPI_RESULT_TEXT			882
#define SLAPI_RESULT_MATCHED			883

#define SLAPI_PLUGIN_SYNTAX_FLAG_ORKEYS			1
#define SLAPI_PLUGIN_SYNTAX_FLAG_ORDERING		2

#define SLAPI_PLUGIN_AUDIT_DATA                 1100
#define SLAPI_PLUGIN_AUDIT_FN                   1101

/* DS 5.x Computed Attribute Callbacks (not exposed) */
#define SLAPI_PLUGIN_COMPUTE_EVALUATOR_FN	1200
#define SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN	1201

#define SLAPI_MANAGEDSAIT       		1000

#define SLAPI_CONFIG_FILENAME			40
#define SLAPI_CONFIG_LINENO			41
#define SLAPI_CONFIG_ARGC			42
#define SLAPI_CONFIG_ARGV			43

#define SLAPI_TARGET_DN				50
#define SLAPI_REQCONTROLS			51

#define	SLAPI_ENTRY_PRE_OP			52
#define	SLAPI_ENTRY_POST_OP			53

#define SLAPI_RESCONTROLS			55
#define SLAPI_ADD_RESCONTROL			56

#define SLAPI_ADD_TARGET			SLAPI_TARGET_DN
#define SLAPI_ADD_ENTRY				60

#define SLAPI_BIND_TARGET			SLAPI_TARGET_DN
#define SLAPI_BIND_METHOD			70
#define SLAPI_BIND_CREDENTIALS			71
#define SLAPI_BIND_SASLMECHANISM		72
#define SLAPI_BIND_RET_SASLCREDS		73

#define SLAPI_COMPARE_TARGET			SLAPI_TARGET_DN
#define SLAPI_COMPARE_TYPE			80
#define SLAPI_COMPARE_VALUE			81

#define SLAPI_DELETE_TARGET			SLAPI_TARGET_DN

#define SLAPI_MODIFY_TARGET			SLAPI_TARGET_DN
#define SLAPI_MODIFY_MODS			90

#define SLAPI_MODRDN_TARGET			SLAPI_TARGET_DN
#define SLAPI_MODRDN_NEWRDN			100
#define SLAPI_MODRDN_DELOLDRDN			101
#define SLAPI_MODRDN_NEWSUPERIOR		102

#define SLAPI_SEARCH_TARGET			SLAPI_TARGET_DN
#define SLAPI_SEARCH_SCOPE			110
#define SLAPI_SEARCH_DEREF			111
#define SLAPI_SEARCH_SIZELIMIT			112
#define SLAPI_SEARCH_TIMELIMIT			113
#define SLAPI_SEARCH_FILTER			114
#define SLAPI_SEARCH_STRFILTER			115
#define SLAPI_SEARCH_ATTRS			116
#define SLAPI_SEARCH_ATTRSONLY			117

#define SLAPI_ABANDON_MSGID			120

#define SLAPI_SEQ_TYPE				150
#define SLAPI_SEQ_ATTRNAME			151
#define SLAPI_SEQ_VAL				152

#define SLAPI_EXT_OP_REQ_OID			160
#define SLAPI_EXT_OP_REQ_VALUE			161
#define SLAPI_EXT_OP_RET_OID			162
#define SLAPI_EXT_OP_RET_VALUE			163

#define SLAPI_MR_FILTER_ENTRY			170	
#define SLAPI_MR_FILTER_TYPE			171
#define SLAPI_MR_FILTER_VALUE			172
#define SLAPI_MR_FILTER_OID			173
#define SLAPI_MR_FILTER_DNATTRS			174

#define SLAPI_LDIF2DB_FILE			180
#define SLAPI_LDIF2DB_REMOVEDUPVALS		185

#define SLAPI_DB2LDIF_PRINTKEY			183

#define SLAPI_PARENT_TXN			190
#define SLAPI_TXN				191

#define SLAPI_SEARCH_RESULT_SET			193
#define	SLAPI_SEARCH_RESULT_ENTRY		194
#define	SLAPI_NENTRIES				195
#define SLAPI_SEARCH_REFERRALS			196

#define	SLAPI_CHANGENUMBER			197
#define	SLAPI_LOG_OPERATION			198

#define SLAPI_DBSIZE				199

#define SLAPI_LOG_FATAL          		0
#define SLAPI_LOG_TRACE				1
#define SLAPI_LOG_PACKETS			2
#define SLAPI_LOG_ARGS				3
#define SLAPI_LOG_CONNS				4
#define SLAPI_LOG_BER				5
#define SLAPI_LOG_FILTER			6
#define SLAPI_LOG_CONFIG			7
#define SLAPI_LOG_ACL				8
#define SLAPI_LOG_SHELL				9
#define SLAPI_LOG_PARSE				10
#define SLAPI_LOG_HOUSE				11
#define SLAPI_LOG_REPL				12
#define SLAPI_LOG_CACHE				13
#define SLAPI_LOG_PLUGIN			14

#define SLAPI_OPERATION_BIND            	0x00000001L
#define SLAPI_OPERATION_UNBIND          	0x00000002L
#define SLAPI_OPERATION_SEARCH          	0x00000004L
#define SLAPI_OPERATION_MODIFY          	0x00000008L
#define SLAPI_OPERATION_ADD             	0x00000010L
#define SLAPI_OPERATION_DELETE          	0x00000020L
#define SLAPI_OPERATION_MODDN           	0x00000040L
#define SLAPI_OPERATION_MODRDN          	SLAPI_OPERATION_MODDN
#define SLAPI_OPERATION_COMPARE         	0x00000080L
#define SLAPI_OPERATION_ABANDON         	0x00000100L
#define SLAPI_OPERATION_EXTENDED        	0x00000200L
#define SLAPI_OPERATION_ANY             	0xFFFFFFFFL
#define SLAPI_OPERATION_NONE            	0x00000000L

LDAP_END_DECL

#include "proto-slapi.h"

#endif /* _SLAPI_H */
#endif /* LDAP_SLAPI */
