/* process_form.h */

#ifndef __PROCESS_FORM_H
#define __PROCESS_FORM_H

#define MAX_ENTRIES 10000

typedef struct {
    char *name;
    char *val;
} entry;

char  *makeword(char *line, char stop);
char  *fmakeword(FILE *f, char stop, int *len);
char  x2c(char *what);
void  unescape_url(char *url);
void  plustospace(char *str);

int   strcompare(char* a, char* b);
int   getvalue(entry* list, char* key, char** value);
void  remove_leading_blanks(char* str);
void  remove_trailing_blanks(char* str);
void  pad_with_char(char* buffer, int length, char padchar);
char* lower_case_string(char* inputbuf);
char* upper_case_string(char* inputbuf);
void  strip_CR(char* buffer);
void  show_form_data(entry* entries);
void  display_html_text(char* filename);
long unformat_cost(char* cost);
#endif

/* end file 'process_form.h' */
