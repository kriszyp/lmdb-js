/*
 * Copyright 1997, 1998, 1999 Computing Research Labs,
 * New Mexico State University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COMPUTING RESEARCH LAB OR NEW MEXICO STATE UNIVERSITY BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef lint
static char rcsid[] = "$Id: urestubs.c,v 1.2 1999/09/21 15:47:44 mleisher Exp $";
#endif

#include "ure.h"

/*
 * This file contains stub routines needed by the URE package to test
 * character properties and other Unicode implementation specific details.
 */

/*
 * This routine should return the lower case equivalent for the character or,
 * if there is no lower case quivalent, the character itself.
 */
ucs4_t
#ifdef __STDC__
_ure_tolower(ucs4_t c)
#else
_ure_tolower(c)
ucs4_t c;
#endif
{
    return c;
}

/*
 * This routine takes a set of URE character property flags (see ure.h) along
 * with a character and tests to see if the character has one or more of those
 * properties.
 */
int
#ifdef __STDC__
_ure_matches_properties(unsigned long props, ucs4_t c)
#else
_ure_matches_properties(props, c)
unsigned long props;
ucs4_t c;
#endif
{
    return 1;
}
