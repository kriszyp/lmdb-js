/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* strng.c....                                                              *
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
 * $Id: strng.c,v 1.6 1999/09/10 15:01:19 zrnsk01 Exp $
 *
 */

#include "strng_exp.h"
#include "tgeneral.h"

/*
 *  Convert string to integer by means of a dispatcherlist
 *  if string is not in the dispatcher -> return default
 */

PUBLIC int cnvt_str2int (stringVal, dispatcher, defaultVal)
STRDISP_P  dispatcher;
int        defaultVal;
char      *stringVal;
{
	int        retVal = defaultVal;
	STRDISP_P  disp;
	
	for (disp = dispatcher; disp->stringVal; disp++) {
	
		if (!strncmp (stringVal, disp->stringVal, disp->abbr)) {
		
			retVal = disp->intVal;
			break;
			
		}
	}
	
	return (retVal);
	
} /* cnvt_str2int */


/*
 *  Truncate characters at the beginning of a string
 */

PUBLIC char * trimleft (s, what)
char   *s, *what;
{

        return (s + strspn (s, what));

} /* trimleft */


/*
 *  Truncate characters at the end of a string
 */

PUBLIC char * trimright (s, what)
char   *s, *what;
{
	char  *tmp = s + strlen (s) - 1;

	while ((tmp >= s) && strchr (what, *tmp)) *tmp-- = '\0';

	return (s);

} /* trimright */


/*
 *  Truncate characters at the beginning and end of a string
 */

PUBLIC char * trim (s, what)
char   *s, *what;
{
	(void) trimright (s, what);
	return (trimleft (s, what));

} /* trim */


/*
 *  Convert a string to lower-case "in place"
 *  uses tolower()
 */

PUBLIC char *str_tolower (source)
char  *source;
{
        char  *target = source;

        for (; *target; target++) *target = tolower (*target);
        return (source);

} /* str_tolower */


/*
 *  Convert a string to upper-case "in place"
 *  uses toupper()
 */

PUBLIC char *str_toupper (source)
char  *source;
{
        char  *target = source;

        for (; *target; target++){
            *target = toupper (*target);

            /* Patch fuer Umlaute */
            if(*target == 'ä') *target = 'Ä';
            else if(*target == 'ö') *target = 'Ö';
            else if(*target == 'ü') *target = 'Ü';
        }
        return (source);

} /* str_toupper */


/*
 *  Substitute a character in a string by another
 */

PUBLIC char *tr1 (source, from, to)
char  *source;
char   from, to;
{
	char *target = source - 1;

	while ( ( target = strchr( ++target, from )) ) *target = to;

	return (source);

} /* tr1 */


PUBLIC int chrcnt(string, c)
char *string;
char *c;
{
	int count=0;

	string--;
	while( ( string = strpbrk(string+1, c)) )
		count++;
	return(count);
}
/* end of function: chrcnt */


PUBLIC int
qSortByString( a, b )
char **a, **b;
{
	return strcmp( *a, *b );
}
/*  end of function: qSortByString  */


