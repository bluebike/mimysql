/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mimysql.h"


int main(int argc, char **argv)
{
    int ch;
    char *socket = "/tmp/mysql.sock";
    char *user = getenv("USER");
    char *pass = NULL;
    char *db = "";
    // const char *st;
    int ret;
    int log_level = 0;
    MYSQL *mysql;
    MYSQL_RES *res;
    MYSQL_ROW row;
    int rowcount = 0;
    int cols;
    int counter = 0;
    int titles = 0;
    char *query = "select user,host from mysql.user";
    char buf[128];
    

    while ((ch = getopt(argc, argv, "tvu:p:S:D:e:c:L:T:")) != -1) {
        switch (ch) {
        case 'h':
            pass = strdup(optarg);
            break;
        case 'u':
            user = strdup(optarg);
            break;
        case 'p':
            pass = strdup(optarg);
            break;
        case 'S':
            socket = strdup(optarg);
            break;
        case 'D':
            db = strdup(optarg);
            break;
        case 'e':
            query = strdup(optarg);
            break;
        case 'c':
            counter = atoi(optarg);
            break;
        case 'v':
            log_level++;
            break;
        case 't':
            titles++;
            break;
        case 'T':
            titles = atoi(optarg);
            break;
        case 'L':
            log_level = atoi(optarg);
            break;
            
        default:
            fprintf(stderr,"what??: %c\n", ch);
            exit(1);
        }
     }
     argc -= optind;
     argv += optind;

     fprintf(stderr,"titles=%d\n", titles);

     

     mysql = mysql_init(NULL);

     if(log_level) {
         fprintf(stderr,"set log level: %d\n", log_level);
         mysql->log_level = log_level;
     }

     if(mysql_real_connect(mysql,
                           /* host */ NULL,
                           /* user */ user,
                           /* pass */ pass,
                           /* db   */ db,
                           /* port */ 0,
                           /* socket */ socket,
                           /* flags */ 0) == NULL) {
         fprintf(stderr, "cannot connect:  %d  : %s\n", mysql_errno(mysql), mysql_error(mysql));
         exit(1);
     }
     fprintf(stderr,"connected\n");

     /*     
     fprintf(stderr,"do ping\n");
     ret = mysql_ping(mysql);
     fprintf(stderr,"ping: %d\n", ret);

     fprintf(stderr,"do stat\n");

     st = mysql_stat(mysql);
     fprintf(stderr,"stat: %s\n", st ? st : "NULL");
     */

     do {
         printf("\n");

         fprintf(stderr,"mysql_query\n");     
         ret = mysql_query(mysql, query);
         if(ret < 0) {
             fprintf(stderr, "ERROR: query : %d : %s\n", mysql_errno(mysql), mysql_error(mysql));
             break;
         }

         cols = mysql_field_count(mysql);
         if(cols == 0) {
             fprintf(stderr,"(query) query no fields\n");
             continue;
         }

         fprintf(stderr,"field-count: %d\n", cols);
         
         
         fprintf(stderr,"mysql_use_result: %d\n", mysql->state);

         
         res = mysql_use_result(mysql);
         if(res == NULL)  {
             fprintf(stderr, "ERROR: mysql user result: %d : %s\n", mysql_errno(mysql), mysql_error(mysql));
             break;
         }

         if(titles) {
             MYSQL_FIELD *fields = mysql_fetch_fields(res);
             printf("NAME: ");
             for(int i=0; i < cols; i++) {
                 MYSQL_FIELD *f = &fields[i];
                 if(i > 0) { printf(", "); }
                 printf("%s", f->name);
             }
             printf("\n");
             if(titles >= 2) {
                 printf("ORG_NAME: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%s", f->org_name);
                 }
                 printf("\n");
                 
                 printf("TABLE: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%s", f->table);
                 }
                 printf("\n");
                 printf("ORG_TABLE: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%s", f->org_table);
                 }
                 printf("\n");
                 printf("DB: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%s", f->db);
                 }
                 printf("\n");
                 printf("TYPE: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%d", f->type);
                 }
                 printf("\n");
                 printf("TYPES: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%s", mysql_get_type_name(f->type));
                 }
                 printf("\n");
                 printf("DEC: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%d", f->decimals);
                 }
                 printf("\n");
                 printf("CHARSET: ");
                 for(int i=0; i < cols; i++) {
                     MYSQL_FIELD *f = &fields[i];
                     if(i > 0) { printf(", "); }
                     printf("%d", f->charsetnr);
                 }
                 printf("\n");
                 if(titles >= 3) { 
                     printf("FLAGS: ");
                     for(int i=0; i < cols; i++) {
                         MYSQL_FIELD *f = &fields[i];
                         if(i > 0) { printf(", "); }
                         mysql_get_field_flags(buf, 128,  f->flags);
                         printf("%04x=%s", f->flags, buf);
                     }
                     printf("\n");
                 }
             }
             printf("\n");             
         }
         
         
         fprintf(stderr,"fetch rows: %d\n", mysql->state);
         rowcount = 0;
         while((row = mysql_fetch_row(res)) != NULL) {
             printf("ROW: ");
             for(int i=0; i < cols; i++) {
                 if(i > 0) { printf(", "); }
                 printf("%s", row[i] ? row[i] : "NULL");
             }
             printf("\n");
             rowcount++;
         }
         printf("\n");                      
         printf("got rows: %d\n", rowcount);
         
         if(mysql_errno(mysql)) {
             fprintf(stderr, "ERROR: mysql fetch row error: %d : %s\n", mysql_errno(mysql), mysql_error(mysql));
         }
            
         mysql_free_result(res);
         
         counter--;
         
     } while(counter > 0);

     mysql_close(mysql);

     return 0;

}
