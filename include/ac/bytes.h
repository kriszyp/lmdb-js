/* Generic bytes.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_BYTES_H
#define _AC_BYTES_H

#if defined( LDAP_INT4_TYPE ) && defined( LDAP_INT2_TYPE )
	/* cross compilers should define LDAP_INT{2,4}_TYPE in CPPFLAS */
	typedef LDAP_INT4_TYPE LDAP_INT4;
	typedef signed LDAP_INT4_TYPE LDAP_SINT4;
	typedef unsigned LDAP_INT4_TYPE LDAP_UINT4;

	typedef LDAP_INT2_TYPE LDAP_INT2;
	typedef signed LDAP_INT2_TYPE LDAP_SINT2;
	typedef unsigned LDAP_INT2_TYPE LDAP_UINT2;

#else
	/* use autoconf defines to provide sized typedefs */
#	if SIZEOF_LONG == 4
		typedef long LDAP_INT4;
		typedef signed long LDAP_SINT4;
		typedef unsigned long LDAP_UINT4;
#	elif SIZEOF_INT == 4
		typedef int LDAP_INT4;
		typedef signed int LDAP_SINT4;
		typedef unsigned int LDAP_UINT4;

#	endif

#	if SIZEOF_SHORT == 2
		typedef short LDAP_INT2;
		typedef signed short LDAP_SINT2;
		typedef unsigned short LDAP_UINT2;
#	elif SIZEOF_INT == 2
		typedef int LDAP_INT2;
		typedef signed int LDAP_SINT2;
		typedef unsigned int LDAP_UINT2;
#	endif
#endif
    
#ifndef BYTE_ORDER
/* cross compilers should define BYTE_ORDER in CPPFLAGS */

/*
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */
#define LITTLE_ENDIAN   1234    /* LSB first: i386, vax */
#define BIG_ENDIAN  4321        /* MSB first: 68000, ibm, net */
#define PDP_ENDIAN  3412        /* LSB first in word, MSW first in long */

/* assume autoconf's AC_C_BIGENDIAN has been ran */
/* if it hasn't, we assume (maybe falsely) the order is LITTLE ENDIAN */
#	ifdef WORDS_BIGENDIAN
#		define BYTE_ORDER  BIG_ENDIAN
#	else
#		define BYTE_ORDER  LITTLE_ENDIAN
#	endif

#endif /* BYTE_ORDER */

#endif /* _AC_BYTES_H */
