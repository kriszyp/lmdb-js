/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/* this routine needs to return the bervals instead of
 * plain strings, since syntax is not known.  It should
 * also return the syntax or some "comparison cookie"
 * that is used by set_filter.
 */
typedef char **(*SET_GATHER) (void *cookie, char *name, char *attr);

long set_size (char **set);
void set_dispose (char **set);

int set_filter (SET_GATHER gatherer, void *cookie, char *filter, char *user, char *this, char ***results);

