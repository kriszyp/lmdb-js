/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* tweb.c.....                                                              *
*                                                                          *
* Function:..WorldWideWeb-X.500-Gateway  MAIN-Routine                      *
*            Based on web500gw.c 1.3 written by Frank Richter, TU Chemmniz *
*            which is based on go500gw by Tim Howes, University of         *
*            Michigan  - All rights reserved                               *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            August 16 1995               Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            December 31 1996           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: tweb.c,v 1.6 1999/09/10 15:01:20 zrnsk01 Exp $
 *
 */


/*
 * redesign BW 94/08/16 
 * patched for HPUX 9.x by /KSp, 94/04/28
 * patched for AMBIX-D and use at University of Tuebingen by /KSp,
 * patched for always-assume-nonleaf-behaviour-and-reread-on-demand; /KSp
 * patched for restricted listing of Tuebinger students; /KSp
 * patched for mailto HREF in mail attribute; /KSp
 * patched for automatic referral to Chemnitz in case of ROOT access
 *             (AMBIX version only); /KSp
 * patched for correct response in case of not found error; /MCl
 * neg patched: subtree search below locality removed; /KSp
 * patched for automatic referral to AMBIX in case of l=DFN access
 *             (non-AMBIX version only); /KSp
 * patched for lower case compare during access control; /KSp
 * patched for menu-'seeAlso' in AMBIXGW; /KSp
 * patched for pgpPubKey formatting as MULTILINE; /KSP
 * correction of MULTILINE handling; /KSp
 * objectClass deleted from menu list entry in html-code; /KSp
 * patched for "Selbsteintrag" needed by AMBIX-Project /mc
 *             last update: 95/07/07
 *
 * 95/07/17 changed to ANSI-C, deleted lots of compiletime-options. /mc
 *         
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Tuebingen. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * ----------------------------------------------------------------------
 */

#include "tweb.h"

PUBLIC int main (argc, argv)
int argc;
char **argv;

{
    /* The Glob-structure is NOT a global variable, but is stored here for
       all other functions !!! */
    GLOB_STRUCT glob;
    char lang[BUFSIZ];
    int pid, i;

    /* make glob global available */
    globP = &glob;

    /* first of all the language-parameter is scanned from the command-line
       and is written as first value to the Glob-structure */
    get_lang(argc, argv, lang);
    bzero((char *) &glob, sizeof(GLOB_STRUCT));
    glob.olang = strdup(lang);

    /* Now start a process for each language and terminate the super-process */
    for(i=0; i<strlen(lang); i++){

        /* memorize the sub-process-language */
        *glob.lang = lang[i];

        switch( pid = fork() ) {

        /* the Sub-Process */
        case  0:
            do_child(argc, argv,lang, &glob);
            break;

        /* A Sub-Process could not be created !!! */
        case -1:
            perror( "fork" );
            break;

        /* the Parent-Process */
        default:
            if ( debug )
                fprintf( stderr, "forked child %d\n", pid );
            break;
        }
    }

	return( 0 );
}
/* end of function: main */
    

/**
 **  do_child()
 **
 **    Main-Function for the working-processes; until now only the
 **    language is initialized. The rest of the configuration 
 **    must be scanned now.
 **/

PRIVATE void do_child(argc, argv,lang, glob)
int argc;
char **argv;
char *lang;
GLOB_STRUCT *glob;

{
    FILE *fp = NULL;
    char filename[BUFSIZ];

    /*  read language-independent (.rc) and -dependent (.conf) configuration */
    init(argv, lang, glob);

    /*  read commandline-parameter (they overwrite conf) */
    getopts (argc, argv, glob);

    /*  If debug-Mode: Configuration Output */
    if (debug) {

        sprintf(filename, "%s.debug", glob->myname);
        fp =fopen(filename, "a");
        fprintf(fp, "\n\n\n#####%s.%s-log Date: %s\n\n",
                           glob->myname, glob->lang, format_time(NULL));
        output(fp, glob, FALSE);

    }

    /*  read language-strings (from .lang) and write out if desired */
    langinit(glob);

    if (debug) {

        langoutput(fp, glob, FALSE);
        fclose(fp);

    }

    /*  Final Configuration-Test */
    check(glob);

    /*  If dynamic Gateway-Switching is enabled the language-dependent
        recognition-string for the meta-Syntax must be fixed
        (language-independent recognition-string is given in Macro GWS ) */
    if(glob->gw_switch->dynamic) {
        char strbuf[BUFSIZ];

        sprintf(strbuf, GWS_FORMAT, glob->la[0]);
        glob->gw_switch->lagws = strdup(strbuf);
    }

    /*  and now start the Gateway ... */
    start_server(glob);

}
/* end of function: do_child */


