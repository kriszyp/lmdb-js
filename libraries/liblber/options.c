/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdlib.h>

#include "lber-int.h"

int lber_int_debug = 0;

int
lber_get_option(
	void	*item,
	int		option,
	void	*outvalue)
{
	BerElement *ber;
	Sockbuf *sb;

	if(outvalue == NULL) {
		/* no place to get to */
		return LBER_OPT_ERROR;
	}

	if(item == NULL) {
		if(option == LBER_OPT_BER_DEBUG) {
			* (int *) outvalue = lber_int_debug;
			return LBER_OPT_SUCCESS;
		}

		return LBER_OPT_ERROR;
	}

	ber = (BerElement *) item;
	sb = (Sockbuf *) item;

	switch(option) {
	case LBER_OPT_BER_OPTIONS:
		* (int *) outvalue = ber->ber_options;
		return LBER_OPT_SUCCESS;

	case LBER_OPT_BER_DEBUG:
		* (int *) outvalue = ber->ber_debug;
		return LBER_OPT_SUCCESS;

	default:
		/* bad param */
		break;
	}

	return LBER_OPT_ERROR;
}

int
lber_set_option(
	void	*item,
	int		option,
	void	*invalue)
{
	BerElement *ber;
	Sockbuf *sb;

	if(invalue == NULL) {
		/* no place to set from */
		return LBER_OPT_ERROR;
	}

	if(item == NULL) {
		if(option == LBER_OPT_BER_DEBUG) {
			lber_int_debug = * (int *) invalue;
			return LBER_OPT_SUCCESS;
		}

		return LBER_OPT_ERROR;
	}

	ber = (BerElement *) item;
	sb = (Sockbuf *) item;

	switch(option) {
	case LBER_OPT_BER_OPTIONS:
		ber->ber_options = * (int *) invalue;
		return LBER_OPT_SUCCESS;

	case LBER_OPT_BER_DEBUG:
		ber->ber_debug = * (int *) invalue;
		return LBER_OPT_SUCCESS;

	default:
		/* bad param */
		break;
	}

	return LBER_OPT_ERROR;
}
