/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* strng_exp.h                                                              *
*                                                                          *
* Function:..String Handling Functions                                     *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            February 13 1996             Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            November 3 1998            ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: strng_exp.h,v 1.6 1999/09/10 15:01:19 zrnsk01 Exp $
 *
 */

#ifndef  __STRNG_EXP__
#define  __STRNG_EXP__

#include <ctype.h> 
#include <stdio.h>
#include <string.h>
#include <time.h>
 


/*
 *  Structures for the offered Funktions
 */

typedef struct _str2intDispatch {

		char    *stringVal;
		int      abbr,
		         intVal;

	} STRDISP, *STRDISP_P;


/*
 *  The "offered" Funktions
 */

/*  Conversion to upper/lower case in the whole string */
char  *str_tolower (/* char *string */);
char  *str_toupper (/* char *string */);

/*  Convert string to integer by means of a dispatcherlist  */
/*  if string is not in the dispatcher -> return default  */
int   cnvt_str2int (/* string, dispatcher, default */);

/*  Truncate characters at the beginning and end of a string  */
char  *trimleft (/* char *s, char *what */);
char  *trimright (/* char *s, char *what */);
char  *trim (/* char *s, char *what */);

/*  A special WHAT: whitespaces  */
#define  WSPACE  "\n\r\t "

/*  Substitute a character in a string to another */
char  *tr1 (/* char *source, char from, char to */);

/*  Count the named characters of string2 in string1  */
int chrcnt (/*String1, String2*/);


/*  Compare by string values in qsort()  */
int qSortByString (/* char **StringP1, char **StringP2 */);

#endif

