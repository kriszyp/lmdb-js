/* $OpenLDAP$ */
/*
 * Context CSN Management Routines
 */
/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"
#include "lutil_ldap.h"

const struct berval slap_ldapsync_bv = BER_BVC("ldapsync");
const struct berval slap_ldapsync_cn_bv = BER_BVC("cn=ldapsync");

void
slap_get_commit_csn( Operation *op, struct berval *csn )
{
	struct slap_csn_entry *csne = NULL, *committed_csne = NULL;
	int i = 0;

	csn->bv_val = NULL;
	csn->bv_len = 0;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		csne->state = SLAP_CSN_COMMIT;
	}

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->state == SLAP_CSN_COMMIT )
			committed_csne = csne;
		if ( csne->state == SLAP_CSN_PENDING )
			break;
	}

	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );

	if ( committed_csne ) {
		ber_dupbv( csn, committed_csne->csn );
	}
}

void
slap_rewind_commit_csn( Operation *op )
{
	struct slap_csn_entry *csne = NULL;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		csne->state = SLAP_CSN_PENDING;
	}
	
	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );
}

void
slap_graduate_commit_csn( Operation *op )
{
	struct slap_csn_entry *csne = NULL;

	if ( op == NULL )
		return;

	if ( op->o_bd == NULL )
		return;

	ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );

	LDAP_TAILQ_FOREACH( csne, &op->o_bd->be_pending_csn_list, csn_link ) {
		if ( csne->opid == op->o_opid && csne->connid == op->o_connid )
			break;
	}

	if ( csne ) {
		LDAP_TAILQ_REMOVE( &op->o_bd->be_pending_csn_list, csne, csn_link );
		ch_free( csne->csn->bv_val );
		ch_free( csne->csn );
		ch_free( csne );
	}

	ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );

	return;
}

static struct berval ocbva[] = {
	BER_BVC("top"),
	BER_BVC("subentry"),
	BER_BVC("syncProviderSubentry"),
	{0,NULL}
};

Entry *
slap_create_context_csn_entry(
	Backend *be,
	struct berval *context_csn
)
{
	Entry* e;
	int rc;

	struct berval bv;

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry ));

	attr_merge( e, slap_schema.si_ad_objectClass, ocbva, NULL );

	attr_merge_one( e, slap_schema.si_ad_structuralObjectClass, &ocbva[1], NULL );

	attr_merge_one( e, slap_schema.si_ad_cn, (struct berval *)&slap_ldapsync_bv, NULL );

	if ( context_csn ) {
		attr_merge_one( e, slap_schema.si_ad_contextCSN,
			context_csn, NULL );
	}

	bv.bv_val = "{}";
	bv.bv_len = sizeof("{}")-1;
	attr_merge_one( e, slap_schema.si_ad_subtreeSpecification, &bv, NULL );

	build_new_dn( &e->e_name, &be->be_nsuffix[0], (struct berval *)&slap_ldapsync_cn_bv, NULL );
	ber_dupbv( &e->e_nname, &e->e_name );

	return e;
}

static int
slap_contextcsn_callback(
	Operation* op,
	SlapReply* rs
)
{
	if ( rs->sr_type != REP_SEARCH ) {
		*((int*)op->o_callback->sc_private) = 0;
	} else {
		*((int*)op->o_callback->sc_private) = 1;
	}
	return LDAP_SUCCESS;
}

int
slap_get_csn(
	Operation *op,
	char *csnbuf,
	int	len,
	struct berval *csn,
	int manage_ctxcsn
)
{
	struct	slap_csn_entry *pending;

	if ( csn == NULL )
		return LDAP_OTHER;

	if ( manage_ctxcsn ) {
		pending = (struct slap_csn_entry *) ch_calloc( 1, sizeof( struct slap_csn_entry ));
	}

	csn->bv_len = lutil_csnstr( csnbuf, len, 0, 0 );
	csn->bv_val = csnbuf;

	if ( manage_ctxcsn ) {
		ldap_pvt_thread_mutex_lock( &op->o_bd->be_pcl_mutex );
		pending->csn = ber_dupbv( NULL, csn );
		pending->connid = op->o_connid;
		pending->opid = op->o_opid;
		pending->state = SLAP_CSN_PENDING;
		LDAP_TAILQ_INSERT_TAIL( &op->o_bd->be_pending_csn_list, pending, csn_link );
		ldap_pvt_thread_mutex_unlock( &op->o_bd->be_pcl_mutex );
	}

	return LDAP_SUCCESS;
}
