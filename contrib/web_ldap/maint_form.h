/* maint_form.h */

#ifndef __MAINT_FORM_H
#define __MAINT_FORM_H

#define max number of passed fields.
#define MAX_ENTRIES 400  /* way bigger than needed. */

/* define the maximum length of a single config line */
#define MAX_LINE_LEN   256

typedef struct {
    char *name;
    char *val;
} entry;

/* prototypes */
char  *makeword(char *line,
                char stop);

char  *fmakeword(FILE *f,
                 char stop,
                 int *len);

char  x2c(char *what);

void  unescape_url(char *url);

void  plustospace(char *str);

int   strcompare(char* a,
                 char* b);

int   getvalue(entry* list,
               char* key,
               char** value);

int append_to_list(entry* list,
                   char* key,
                   char* value);

void  remove_leading_blanks(char* str);

void  remove_trailing_blanks(char* str);

void  pad_with_char(char* buffer,
                    int length,
                    char padchar);

char* lower_case_string(char* inputbuf);

char* upper_case_string(char* inputbuf);

void  strip_CR(char* buffer);

void  show_form_data(entry* entries);

void  display_html_text(char* filename);

long unformat_cost(char* cost);

int get_line(FILE* file,
             char* returned_line);

void print_header(char* title);

void maint_trailer();

void maint_header(char* name);

void maint_update_form(entry* list,
                       char* maint_filename,
                       char* DatabaseName);

/*
int draw_form_fields(char* maint_filename,
                       CGIDB_REC* cgidb_rec);
*/
void maint_remove_form(entry* list,
                       char* DatabaseName);

void maint_add_form(entry* list,
                    char* maint_filename,
                    char* DatabaseName);

/*
char* get_field_data(CGIDB_REC* cgidb_rec,
                     char* data,
                     char* buffer);
*/
void maint_dump_db(entry* list,
                   char* maint_filename,
                   char* DatabaseName);
/*
void display_dump_entry(CGIDB_REC* cgidb_rec,
                        int cols,
                        char* item1,
                        char* item2,
                        char* item3,
                        char* item4);
*/
void maint_upload_photo(char* MFileName);

void maint_remove_photo(entry* list,
                        char* MFileName);
/*
int copy_data_to_db_field(CGIDB_REC* cgidb_rec,
                          char* field,
                          char* fieldmaxlength,
                          char* data);
*/
#endif

/* end file 'maint_form.h' */
