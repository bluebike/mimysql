/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "mimysql.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>


extern MIMYSQL_ENV *mimysql_default_env;


#define BUF_OVERFLOW   -2
#define BUF_OUT_OF_MEM -3
#define MINBUF 32


#define ER(xx) client_errors[(xx)-CR_MIN_ERROR]

#define SET_MYSQL_ERROR(m,e,s,fmt,...) \
    {                                                                   \
        if(s) { strcpy((m)->sqlstate,s); }                              \
        (m)->errno = (e);                                               \
        snprintf((m)->error_text, MYSQL_ERRMSG_SIZE-1, fmt ? fmt : ER(e), ##__VA_ARGS__); \
    } while(0)

#define CLEAR_MYSQL_ERROR(m)             \
    {                                    \
        strcpy((m)->sqlstate,"00000");   \
        (m)->errno = 0;                  \
        m->error_text[0] = 0;            \
    } while(0);


#define CHECK_ENV_NULL(e) assert(e != NULL);
#define CHECK_ENV_MAGIC(e) assert((e)->magic == MIMYSQL_ENV_MAGIC_V0);

/* --------------------------------------------------------- */

const char *sqlstate_unknown = "HY000";
const char *sqlstate_none = "HY000";

const char *mi_state_str[32] = {
     "NULL",             // 0
     "READY",            // 1
     "ERROR",            // 2
     "EOF",              // 3
     "COM_SENT",         // 4
     "QUERY_SENT",       // 5
     "QUERY_OK",         // 6
     "QUERY_FIELDS",     // 7
     "QUERY_FIELDS_EOF", // 8
     "QUERY_RESULT",     // 9
     "QUERY_ROWS",       // 11
     "QUERY_ROWS_EOF",   // 12
     "END",              // 13
     "STATE14",          // 14
     "STATE15",          // 
     "STATE16",          // 
     "STATE17",          // 
     "STATE18",          // 
     "STATE19",          // 
     "STATE20",          // 
     "STATE21"           // 
};

const char *client_errors[] =
{
/* 2000 */  "Unknown MySQL error",
/* 2001 */  "Can't create UNIX socket (%d)",
/* 2002 */  "Can't connect to local MySQL server through socket '%-.64s' (%d)",
/* 2003 */  "Can't connect to MySQL server on '%-.64s' (%d)",
/* 2004 */  "Can't create TCP/IP socket (%d)",
/* 2005 */  "Unknown MySQL server host '%-.100s' (%d)",
/* 2006 */  "MySQL server has gone away",
/* 2007 */  "Protocol mismatch. Server Version = %d Client Version = %d",
/* 2008 */  "MySQL client run out of memory",
/* 2009 */  "Wrong host info",
/* 2010 */  "Localhost via UNIX socket",
/* 2011 */  "%-.64s via TCP/IP",
/* 2012 */  "Error in server handshake",
/* 2013 */  "Lost connection to MySQL server during query",
/* 2014 */  "Commands out of sync; you can't run this command now",
/* 2015 */  "%-.64s via named pipe",
/* 2016 */  "Can't wait for named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2017 */  "Can't open named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2018 */  "Can't set state of named pipe to host: %-.64s  pipe: %-.32s (%lu)",
/* 2019 */  "Can't initialize character set %-.64s (path: %-.64s)",
/* 2020 */  "Got packet bigger than 'max_allowed_packet'",
/* 2021 */  "",
/* 2022 */  "",
/* 2023 */  "",
/* 2024 */  "",
/* 2025 */  "",
/* 2026 */  "SSL connection error: %-.100s",
/* 2027 */  "received malformed packet",
/* 2028 */  "",
/* 2029 */  "",
/* 2030 */  "Statement is not prepared",
/* 2031 */  "No data supplied for parameters in prepared statement",
/* 2032 */  "Data truncated",
/* 2033 */  "",
/* 2034 */  "Invalid parameter number",
/* 2035 */  "Invalid buffer type: %d (parameter: %d)",
/* 2036 */  "Buffer type is not supported",
/* 2037 */  "Shared memory: %-.64s",
/* 2038 */  "Shared memory connection failed during %s. (%lu)",
/* 2039 */  "",
/* 2040 */  "",
/* 2041 */  "",
/* 2042 */  "",
/* 2043 */  "",
/* 2044 */  "",
/* 2045 */  "",
/* 2046 */  "",
/* 2047 */  "Wrong or unknown protocol",
/* 2048 */  "",
/* 2049 */  "Connection with old authentication protocol refused.",
/* 2050 */  "",
/* 2051 */  "",
/* 2052 */  "Prepared statement contains no metadata",
/* 2053 */  "",
/* 2054 */  "This feature is not implemented or disabled",
/* 2055 */  "Lost connection to MySQL server at '%s', system error: %d",
/* 2056 */  "Server closed statement due to a prior %s function call",
/* 2057 */  "The number of parameters in bound buffers differs from number of columns in resultset",
/* 2059 */  "Can't connect twice. Already connected",
/* 2058 */  "Plugin %s could not be loaded: %s",
/* 2059 */  "An attribute with same name already exists",
/* 2060 */  "Plugin doesn't support this function",
            ""
};


char *mysql_field_flags[16] = {
		"NOT_NULL"   	     ,  //  1             // field cannot be null
		"PRIMARY_KEY"        ,  //  2             // field is a primary key
		"UNIQUE_KEY"	     ,  //  4             // field is unique
		"MULTIPLE_KEY"	     ,  //  8             // field is in a multiple key
		"BLOB"	             ,  //  16            // is this field a Blob
		"UNSIGNED"           ,  //  32            // is this field unsigned
		"ZEROFILL"           ,  //  64            // is this field a zerofill
		"BINARY_COLLATION"   ,  //  128           // whether this field has a binary collation
		"ENUM"	             ,  //  256           // Field is an enumeration
		"AUTO_INCREMENT"     ,  //  512           // field auto-increment
		"TIMESTAMP"	         ,  //  1024          // field is a timestamp value
		"SET"	             ,  //  2048          // field is a SET
		"NO_DEFAULT_VALUE"   ,  //  4096          // field doesn't have default value
		"ON_UPDATE_NOW"	     ,  //  8192          // field is set to NOW on UPDATE
        "UNKNOWN"	         ,  //  8192          // field is set to NOW on UPDATE
		"NUM"	                //  32768         // field is num
};



char *mysql_cap_flags[64] =   {
     "CLIENT_MYSQL",           /*  0 1ULL    * mysql/old mariadb server/client */
     "CLIENT_FOUND_ROWS",      /*  1 2ULL     Found instead of affected rows */
     "CLIENT_LONG_FLAG",       /*  2 4ULL     Get all column flags */
     "CLIENT_CONNECT_WITH_DB", /*  3 8ULL     One can specify db on connect */
     "CLIENT_NO_SCHEMA",       /*  4 16ULL    Don't allow database.table.column */
     "CLIENT_COMPRESS",        /*  5 32ULL    Can use compression protocol */
     "CLIENT_ODBC",            /*  6 64ULL    Odbc client */
     "CLIENT_LOCAL_FILES",     /*  7 128ULL   Can use LOAD DATA LOCAL */
     "CLIENT_IGNORE_SPACE"     /*  8 256ULL   Ignore spaces before '(' */
     "CLIENT_PROTOCOL_41",     /*  9 512ULL   New 4.1 protocol */
     "CLIENT_INTERACTIVE",     /* 10 1024ULL  This is an interactive client */
     "CLIENT_SSL",             /* 11 2048ULL  Switch to SSL after handshake */
     "CLIENT_IGNORE_SIGPIPE",  /* 12 4096ULL  IGNORE sigpipes */
     "CLIENT_TRANSACTIONS",    /* 13 8192ULL  Client knows about transactions */
     "CLIENT_RESERVED",        /* 14 16384ULL  Old flag for 4.1 protocol  */
     "CLIENT_SECURE_CONNECTION", /* 15 32768ULL  New 4.1 authentication */
     "CLIENT_MULTI_STATEMENTS",  /* 16  (1ULL << 16) Enable/disable multi-stmt support */
     "CLIENT_MULTI_RESULTS",     /* 17  (1ULL << 17) Enable/disable multi-results */
     "CLIENT_PS_MULTI_RESULTS",  /* 18  (1ULL << 18) Multi-results in PS-protocol */
     "CLIENT_PLUGIN_AUTH",       /* 19  (1ULL << 19) Client supports plugin authentication */
     "CLIENT_CONNECT_ATTRS",     /* 20  (1ULL << 20) Client supports connection attributes */
     "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA", /* 21 (1ULL << 21)  Enable authentication response packet to be larger than 255 bytes. */
     "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",   /* 22 (1ULL << 22)  Don't close the connection for a connection with expired password. */
     "CLIENT_SESSION_TRACK",                  /* 23 (1ULL << 23) */
     "CLIENT_DEPRECATE_EOF",                  /* 24 (1ULL << 24) */
     "CLIENT_CAP25",                          /* 25 (1ULL << 25) */
     "CLIENT_CAP26",                          /* 26 (1ULL << 26) */
     "CLIENT_CAP27",                          /* 27 (1ULL << 27) */
     "CLIENT_CAP28",                          /* 28 (1ULL << 28) */
     "CLIENT_PROGRESS_OBSOLETE",              /* 29 (1ULL << 29) */
     "CLIENT_SSL_VERIFY_SERVER_CERT",         /* 30 ((1ULL << 30) */
     "CLIENT_REMEMBER_OPTIONS",               /* 31  (1ULL << 31) */
     // MARIADB
     "MARIADB_CLIENT_PROGRESS",               /* 32 */
     "MARIADB_CLIENT_COM_MULTI",              /* 33 */
     "MARIADB_CLIENT_STMT_BULK_OPERATIONS",   /* 34 */
     "MARIADB_CLIENT_EXTENDED_TYPE_INFO",     /* 35 */
     "CLIENT_CAP36",
     "CLIENT_CAP37",
     "CLIENT_CAP38",
     "CLIENT_CAP39",
     "CLIENT_CAP40",
     "CLIENT_CAP41",
     "CLIENT_CAP42",
     NULL,
     NULL,
};


int mi_send_com(MYSQL *m, int cmd, const char *data, size_t data_len);


static const char *notnull(const char *str) {
    return str ? str : "NULL";
}


void mi_log(MYSQL *m, uint32_t level, const char *fmt, ...) {
    va_list ap;
    if(level <= m->log_level) {
        va_start(ap, fmt);
        fprintf(stderr, "MI LOG: %d : ", level);
        vfprintf(stderr,fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
}


char *mysql_get_field_flags(char *to, int length, uint16_t flags) {
    int i;
    int slen;
    int count = 0;
    char *p  = to;
    char *ep = to + length - 1;
    char *str;
    if(length < 2) {
        return NULL;
    }
    for(i=0; i < 16; i++) {
        if(flags & (1 << i)) {
            str = mysql_field_flags[i];
            slen = strlen(str);
            if((p + slen + 1) >= ep) {
                if(p + 4 <=  ep) {
                    *p++ = '.'; *p++ = '.'; *p++ = '.'; *p = 0;
                    return to;
                } else {
                    *p = 0;
                    return to;
                }
            }
            if(count++ > 0)
                *p++ = ';';
            memcpy(p,str,slen);
            p += slen;
        }
    }
    *p = 0;
    return to;
}


char *hex_string(MIMYSQL_ENV *env, uint8_t *data, size_t len) {
    size_t size = len * 3 + 2;
    char *p;
    char *str = env->alloc(size);
    if(str == NULL) {
        return NULL;
    }
    p = str;
    for(int i=0; i < len; i++) {
        if(i > 0) {
            *p++ = ' ';
        }
        sprintf(p,"%02x", data[i]);
        p += 2;
    }
    *p = 0;
    return str;
}

char *hex_string_buf(MIMYSQL_ENV *env, MI_BUF *bu) {
    return hex_string(env, bu->buf, bu->ptr - bu->buf);
}


void mi_display_caps(MYSQL *m, uint64_t caps, char *where) {
    int count = 0;
    int len;
    char *p;
    char *f;
    
    if(m->bufa == NULL) {
        m->bufa = m->env->alloc(1024);
        if(m->bufa == NULL) {
            return;
        }
    }
    
    p = m->bufa;
    for(int i=0; i < 64; i++) {
        f = mysql_cap_flags[i];
        if((caps & ((uint64_t) 1 << i)) != 0 && f) {
            len = strlen(f);            
            if(count > 0)  {
                *p++ = ',';
                *p++ = ' ';
            }
            memcpy(p,f,len);
            p += len;
            count++;
        }
    }
    *p = 0;    
    mi_log(m,MI_LOG_DEBUG,"(%s) CAPS: : %s", where, m->bufa);
}

int mi_display_packet(MYSQL *m, const char *where,  uint8_t *s, uint8_t *e) {
    
    size_t size = e - s;
    int chunk;
    char *h;
    uint8_t *p = s;
    int c;
    int off = 0;
    int i;
    char buf[120];

    if(m->log_level <  MI_LOG_TRACE) {
        return 0;
    }

    mi_log(m,MI_LOG_TRACE,
           "(%s) PACKET packet-size(%d) size(%d) seq(%d)",
           where,
           size, mdata_uint24(p), p[3]);
    while(p < e) {
        chunk = e - p;
        if(chunk > 16) chunk = 16;
        h = buf;
        *h = 0;
        for( i=0; i < chunk; i++) {
            if(i == 8) {
                *h++ = ' ';
                *h++ = '-';
            }
            sprintf(h," %02x", p[i]); h+= 3;
        }
        for(; i < 16; i++) {
            if(i == 8) {
                *h++ = ' ';
                *h++ = '-';
            }
            strcat(h,"   "); h+= 3;
        }

        *h++ = ' ';
        *h++ = '|';
        *h++ = ' ';
        for(int i=0; i < chunk; i++) {
            if(i == 8) {
                *h++ = ' ';
                *h++ = '-';
                *h++ = ' ';                
            }
            c = p[i] & 0xff;
            if(c < 32 || c >= 127) c = '.';
            *h++ = c;
        }
        *h++ = 0;
        mi_log(m,MI_LOG_TRACE,"H: %04d %s", off, buf);
        p   += chunk;
        off += chunk;
    }
    return 0;
}



int mimysql_max_packet = (32 * 1024) - 4;

MI_BUF *mi_buf_init(MIMYSQL_ENV *env, MI_BUF *o, size_t size) {
    assert(o != NULL);
    assert(env != NULL);
    if(size <= 0) {
        size = 2048;
    }
    memset(o, 0, sizeof(MI_BUF));
    if((o->buf = env->alloc(size)) == NULL) {
        return NULL;
    }
    assert(o->buf);
    o->ptr  = o->buf;
    o->endp = o->buf + size;
    o->env  = env;
    return o;
}


size_t mi_buf_size(MI_BUF *o) {
    return o->ptr - o->buf;
}

void mi_buf_close(MI_BUF *o) {
    assert(o != NULL);
    if(o->buf) {
        o->env->free(o->buf);
    }
    memset(o, 0, sizeof(MI_BUF));
}


void mi_buf_reset(MI_BUF *o) {
    o->ptr = o->buf;
}


int mi_buf_reserve(MI_BUF *o, size_t needed) {
    size_t left = o->endp - o->ptr;
    
    if(needed >= left) {
        
        size_t size = o->endp - o->buf;
        size_t newsize = size + needed + 1;

        uint8_t *newbuf;
        if(newsize < 64) {
            newsize = 64;
        } else if(newsize <= 2048) {
            uint32_t mod = newsize % 256;            
            newsize -= mod;
            newsize += 64;
        } else {
            uint32_t mod = newsize % 2048;
            newsize -= mod;
            newsize += 2048;
        }
        
        assert(newsize > size);
        
        newbuf = o->env->realloc(o->buf, newsize);
        if(newbuf == NULL) {
            return -1;
        }
        
        o->ptr  = newbuf + (o->ptr - o->buf);
        o->endp = newbuf + (o->endp- o->buf);
        o->buf  = newbuf;
        return 1;
    } else {
        return 0;
    }
}





int mi_buf_add_lenc(MI_BUF *o, uint64_t val) {
    if(mi_buf_reserve(o,9) < 0) return -1;
    if(val < 0xFB) {
        *(o->ptr++) = (uint8_t) val;
        return 1;
    } else if(val <= 0xffff) {
        o->ptr[0] = 0xFB;
        o->ptr++;
        mput_uint16(o->ptr + 1,val);
        o->ptr += 2;
        return 3;
    } else if(val <= 0xffffff) {
        o->ptr[0] = 0xFC;
        o->ptr++;
        mput_uint24(o->ptr, val);
        o->ptr += 3;
        return 4;
    } else {
        o->ptr[0]= 0xFD;
        o->ptr++;
        mput_uint64(o->ptr+1,val);
        o->ptr += 8;
        return 9;
    }
}

int mi_buf_reset_header(MI_BUF *o, int seq) {
    o->ptr = o->buf;
    if(mi_buf_reserve(o,10) <0) return -1;
    o->buf[0] = 0x00;
    o->buf[1] = 0x00;
    o->buf[2] = 0x00;
    o->buf[3] = seq;
    o->ptr += 4;
    return 4;
}

void mi_buf_set_length(MI_BUF *o) {
    size_t size = o->ptr - o->buf - 4;
    o->buf[0] = size & 0xff;
    o->buf[1] = (size >> 8) & 0xff;
    o->buf[2] = (size >> 16) & 0xff;
}


int mi_buf_add_data(MI_BUF *o, uint8_t *data, size_t len) {
    if(mi_buf_reserve(o,len) <0) return -1;
    memcpy(o->ptr, data,len);
    o->ptr += len;
    return len;
}

int mi_buf_add_data_lenc(MI_BUF *o, uint8_t *data, size_t len) {
    if(mi_buf_reserve(o,len+9) <0) return -1;
    if(mi_buf_add_lenc(o,len) < 0) return -1;
    memcpy(o->ptr, data,len);
    o->ptr += len;    
    return len;
}


int mi_buf_add_uint8(MI_BUF *o, uint8_t val) {
    if(mi_buf_reserve(o,1) <0) return -1;
    o->ptr[0] = val;
    o->ptr += 1;
    return 1;
}

int mi_buf_add_uint16(MI_BUF *o, uint16_t val) {
    if(mi_buf_reserve(o,2) <0) return -1;
    mput_uint16(o->ptr,val);
    o->ptr += 2;
    return 2;
}

int mi_buf_add_uint24(MI_BUF *o, uint32_t val) {
    if(mi_buf_reserve(o,3) <0) return -1;
    mput_uint24(o->ptr,val);
    o->ptr += 3;
    return 3;
}

int mi_buf_add_uint32(MI_BUF *o, uint32_t val) {
    if(mi_buf_reserve(o,4) <0) return -1;
    mput_uint32(o->ptr,val);
    o->ptr += 4;
    return 4;
}

int mi_buf_add_uint40(MI_BUF *o, uint64_t val) {
    if(mi_buf_reserve(o,5) <0) return -1;
    mput_uint40(o->ptr,val);
    o->ptr += 5;
    return 5;
}


int mi_buf_add_uint48(MI_BUF *o, uint64_t val) {
    if(mi_buf_reserve(o,6) <0) return -1;
    mput_uint48(o->ptr,val);
    o->ptr += 6;
    return 6;
}

int mi_buf_add_uint64(MI_BUF *o, uint64_t val) {
    if(mi_buf_reserve(o,8) <0) return -1;
    mput_uint64(o->ptr,val);
    o->ptr += 8;
    return 8;
}


int mi_buf_add_zero(MI_BUF *o, int count) {
    if(mi_buf_reserve(o,count) <0) return -1;
    memset(o->ptr, 0, count);
    o->ptr += count;
    return count;
}


/**
 *   mi_buf_add_str, mi_buf_add_str_nul, alreays return string offset to start of buffer 
 *  
 */

size_t mi_buf_add_str(MI_BUF *o, const char *str, int len) {
    size_t off;
    if(str == NULL) str = "";    
    if(len < 0) len = strlen(str);
    len = strlen(str);
    if(mi_buf_reserve(o,len) <0) return -1;
    off = o->ptr - o->buf;
    memcpy(o->ptr, 0, len);;
    o->ptr += len;
    return off;
}

size_t mi_buf_add_str_nul(MI_BUF *o, const char *str, int len) {
    size_t off;
    if(str == NULL) { str = ""; };    
    if(len <0) { len = strlen(str); }
    if(mi_buf_reserve(o,len+1) < 0) return -1;
    off = o->ptr - o->buf;    
    memcpy(o->ptr, str, len);
    o->ptr += len;
    o->ptr[0] = 0;
    o->ptr++;
    return off;
}

// ------------------------------------------------------------


int mi_buf_add_str_lenc(MI_BUF *o, const char *str, int len) {
    int l;
    if(str == NULL) {
        str = "";
        len = 0;
    } else if(len < 0) {
        len = strlen(str);
    }
    if(mi_buf_reserve(o,len + 9) <0) return -1;
    if((l = mi_buf_add_lenc(o, len)) < 0) {
        return l;
    }
    if(len > 0) {
        memcpy(o->ptr,str,len);
        o->ptr += len;
    }
    return l + len;
}

// add string with lenc prefix if NULL then add 0xFE (NULL marker)

int mi_buf_add_str_lenc_null(MI_BUF *o, const char *str, int len) {
    int l;
    if(str == NULL) {
        if(mi_buf_reserve(o,1) <0) return -1;
        *(o->ptr++) = MI_LENC_NULL;
        return 1;
    } else if(len < 0) {
        len = strlen(str);
    }
    if(mi_buf_reserve(o,len + 9) <0) return -1;
    if((l = mi_buf_add_lenc(o, len)) < 0) {
        return l;
    }
    if(len > 0) {
        memcpy(o->ptr, str, len);
        o->ptr += len;
    }
    return l;
}


// string with one byte length prefix

size_t mi_buf_add_str_len1(MI_BUF *o, const char *str, int len) {
    size_t off;
    if(str == NULL) {
        str = "";
        len = 0;
    } else if(len < 0) {
        len = strlen(str);
    }
    if(mi_buf_reserve(o,len + 1) <0) return -1;
    off = MI_BUF_PTR_OFFSET(o);    
    *(o->ptr) = len;
    memcpy(o->ptr + 1, str, len);
    o->ptr += len + 1;
    return off;
}

//  add fixed string padded by NUL:s.

size_t mi_buf_add_str_fixed(MI_BUF *o, const char *str, int len) {
    int slen;
    int off;
    if(str == NULL) {
        str = "";
        slen = 0;
    } else {
        slen = strlen(str);
    }
    off = MI_BUF_PTR_OFFSET(o);        
    if(mi_buf_reserve(o,len) <0) return -1;
    if(slen >= len) {
        memcpy(o->ptr,str,len);
    } else {
        memcpy(o->ptr,str,slen);
        memset(o->ptr + slen, 0, len - slen);
    }
    return off;
}


#if 0 

char * mi_int2str10(char *buf, int64_t d) {
    char *p;
    int neg = 0;
    if(d < 0) {
        if(d == −9223372036854775808L) {
            strcpy(buf,"−9223372036854775808");
            return buf;
        }
        neg = 1;
        d = -d;
    }
    p = buf + 28;
    *p = 0;
    while(d > 0) {
        p--;
        *p = '0' + (d % 10);
        d /= 10;
    }
    if(neg) {
        p--;
        *p = '-';
    }
    return p;
}

const char *hexes = "0123456789ABCEDEF";

char * mi_uint2strBase(char *buf, int64_t d, int base) {
    char *p;
    int neg = 0;
    if(d < 0) {
        if(d == −9223372036854775808L) {
            if(base == 10) {
                strcpy(buf,"−9223372036854775808");
            } else if(base == 16) {
                strcpy(buf,"0x");

            }
            
            return buf;
        }
        neg = 1;
        d = -d;
    }
    p = buf + 28;
    *p = 0;
    while(d > 0) {
        p--;
        *p = '0' + (d % 10);
        d /= 10;
    }
    if(neg) {
        p--;
        *p = '-';
    }
    return p;
}




int mi_buf_sprintf(MI_BUF *o, const char *fmt, ...) {
    int ch;
    char *p;
    int  num, done, eot , zero, neg, op, space, l;
    char *mark;
    char apu[30];
    va_arg ap;
    
    va_start(ap,fmt);
    p = (char *) fmt;
    mark = p;
    eot = 0;

    while((ch = *p) && !eot)  {
        if(ch != '%') {
            p++;
            next;
        }
        if(p > mark) {
            mi_buf_add_data(b,mark,p-mark);
        }
        num = done = op = zero = neg = space = l = 0;
        ch = p++;

        switch(ch) {
        case '-':
            neg = 1;
            p++;
            break;
            
        case '-':
            neg = 1;
            p++;
            break;

        case '0':
            zero = 1;
            p++;
            break;
        defaut:
            break;
        }
        
        do {
            switch(ch) {
            case 0:
                mi_buf_add_uint8(b,'%');
                eot = 1;
                done = 1;
                break;
            case '%':
                mi_buf_add_uint8(b,'%');
                done = 1;
                beak;
            case '0':
            case '1':
            case '2':                
            case '3':
            case '4':
            case '5':                
            case '6':
            case '7':
            case '8':
            case '9':
                num *= 10;
                num +=  ch - '0';
                mi_buf_add_uint8(b,'%');
                break;
            case ' ':
                space = 1;
                break;
                
            case 'l':
                l++;
                break;
            case 'j':
            case 't':
            case 'z':
            case 'q':
                // modifiers (not supported)
                break;
            case 'd':
                d = va_arg(arg, int);
                ip = mi_int2str(apu,d);
                break;
            }
        } while(!done && !eot);
    }
    
}

#endif

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------


uint64_t get_lenc64(uint8_t **ptr, uint8_t *ep) {
    uint8_t *p = *ptr;
    uint8_t ch;
    size_t room = ep - p;
    if(room <= 0) {
        return BAD_LENC64;
    }
    ch = *p++;
    if(ch < 0xfb) {
        *ptr += 1;
        return ch;
    }
    if(ch == 0xFb) {   // NULL
        *ptr += 1;
        return BAD_LENC64;
    }
        
    if(ch == 0xFc) {   // 1 + 2
        if(room < 3) {
            *ptr = ep;
            return BAD_LENC64;
        }
        *ptr += 3;
        return mdata_uint16(p);
    }
    if(ch == 0xFd) {   // 1 + 3
        if(room < 4) {
            *ptr = ep;
            return BAD_LENC64;
        }
        *ptr += 4;
        return mdata_uint24(p);
    }
    if(ch == 0xFe) {   // 1 + 8
        if(room < 9) {
            *ptr = ep;
            return BAD_LENC64;
        }
        *ptr += 9;
        return mdata_uint64(p);
    }
    *ptr += 1;
    return BAD_LENC64;
}


uint32_t get_lenc32(uint8_t **ptr, uint8_t *ep) {
    uint8_t *p = *ptr;
    uint8_t ch;
    size_t room = ep - p;
    uint64_t val;
    if(room <= 0) {
        *ptr = ep;
        return BAD_LENC32;
    }
    ch = *p++;
    if(ch < 0xfb) {
        *ptr += 1;
        return ch;
    }
    if(ch == 0xFb) {   // NULL
        *ptr += 1;
        return BAD_LENC32;
    }
        
    if(ch == 0xFc) {   // 1 + 2
        if(room < 3) {
            *ptr = ep;
            return BAD_LENC32;
        }
        *ptr += 3;
        return mdata_uint16(p);
    }
    if(ch == 0xFd) {   // 1 + 3
        if(room < 4) {
            *ptr = ep;
            return BAD_LENC32;
        }
        *ptr += 4;
        return mdata_uint24(p);
    }
    if(ch == 0xFe) {   // 1 + 8
        if(room < 9) {
            *ptr = ep;
            return BAD_LENC32;
        }
        *ptr += 9;
        val = mdata_uint64(p);
        if(val > 0xffffffff) {
            return BAD_LENC32;
        }
        return (uint32_t) val;
    }
    return BAD_LENC32;
}



int mdata_lenc32(uint8_t **ptr, uint8_t *ep, uint32_t * result) {
    uint8_t *p = *ptr;
    int size = ep - p;
    uint8_t ch;
    uint64_t val;

    if(size <= 0) {
        *result = 0;
        return LENC_NO_DATA;
    }

    ch = *p++;    
    
    if(ch < 0xFB) {
        *result = ch;
        *ptr += 1;
        return LENC_OK;
    }
    if(ch == 0xFB) {  /* NULL */
        *result = 0;
        *ptr += 1;
        return LENC_NULL;
    }
    
    if(ch == 0xFC) {   /* 2 bytes */
        if(size >= 3) {
            *result = mdata_uint16(p);
            *ptr += 3;
            return LENC_OK;
        } else {
            *ptr = ep;
            *result = 0;
            return LENC_NO_DATA;
        }
    }

    if(ch == 0xFD) {  /* 1 + 3 bytes */
        if(size >= 4) {
            *result = mdata_uint24(p);
            *ptr += 4;
            return LENC_OK;
        } else {
            *ptr = ep;            
            *result = 0;
            return LENC_NO_DATA;
        }
    }

    if(ch == 0xFE) { /* 1 + 8 bytes */
        if(size >= 9) {
            val = mdata_uint64(p);
            *ptr += 9;
            *result = val;            
            if(val > 0xffffffff) {
                return LENC_OVERFLOW;
            }
            return LENC_OK;
        } else {
            *result = 0;
            *ptr = ep;
            return LENC_NO_DATA;
        }
    }
    
    *result = 0;
    *ptr += 1;
    return LENC_EOF;
}



int mdata_lenc64(uint8_t **ptr, uint8_t *ep, uint64_t * result) {
    uint8_t *p = *ptr;
    int size = ep - p;
    uint8_t ch;

    if(p >= ep) {
        *result = 0;
        return LENC_NO_DATA;
    }

    ch = *p++;    
    
    if(ch < 0xFB) {
        *result = ch;
        *ptr += 1;
        return LENC_OK;
    }
    if(ch == 0xFB) {  /* NULL */
        *result = 0;
        *ptr += 1;
        return LENC_NULL;
    }
    if(ch == 0xFC) {   /* 2 bytes */
        if(size >= 3) {
            *result = mdata_uint16(p);
            *ptr += 3;
            return LENC_OK;
        } else {
            *ptr = ep;            
            *result = 0;
            return LENC_NO_DATA;
        }
    }

    if(ch == 0xFD) {  /* 1 + 3 bytes */
        
        if(size >= 4) {
            *ptr += 4;        
            *result = mdata_uint24(p);
            return LENC_OK;
        } else {
            *ptr = ep;
            *result = 0;
            return LENC_NO_DATA;
        }
    }

    if(ch == 0xFE) { /* 1 + 8 bytes */
        if(size >= 9) {
            *result = mdata_uint64(p);
            *ptr += 9;
            return LENC_OK;
        } else {
            *ptr = ep;            
            *result = 0;
            return LENC_NO_DATA;
        }
    }

    // 0xff == EOF 
    
    *result = 0;
    *ptr += 1;    
    return LENC_EOF;
}


// --------------------------------------------------------------------------------


size_t mimysql_inbuffer_size = 4096;



MI_INBUF *mi_inbuf_init(MIMYSQL_ENV *env, MI_INBUF *b, size_t size) {
    CHECK_ENV_MAGIC(env);
    assert(b);
        if(size <= 0) {
        size = mimysql_inbuffer_size;
    }
    if(size < 3) {
        size = 3;
    }

    if(b) {
        memset(b,0,sizeof(MI_INBUF));
    } else {
        b = env->alloc(size);
        if(b == NULL) {
            return NULL;
        }
        memset(b,0,sizeof(MI_INBUF));
        b->allocated = 1;
    }

    b->buffer    = env->alloc(size);
    if(b->buffer == NULL) {
        return NULL;
    }

    b->buffer_length  = size;
    b->readptr        = b->buffer;
    b->packet_start   = b->buffer;
    b->packet_end     = NULL;
    b->packet_data    = NULL;    
    b->endbuf         = b->buffer + size - 1;   // left room for zero
    b->env            = env;
    return b;
}


void mi_inbuf_close(MI_INBUF *b) {
    MIMYSQL_ENV *env = b->env;
    int allocated = b->allocated;
    if(b->buffer) {
        env->free(b->buffer);
        b->buffer = NULL;
    }
    memset(b,0,sizeof(MI_INBUF));
    if(allocated) {
        env->free(b);
    }
}




void mi_inbuf_free(MI_INBUF *b) {
    MIMYSQL_ENV *env = b->env;
    int allocated = b->allocated;
    env->free(b->buffer);
    memset(b,0,sizeof(MI_INBUF));
    if(allocated) {
        env->free(b);
    }
}


//  move current packet to start of buffer
//  leave data from "pakcet_start" to "readptr"

void mi_inbuf_compact(MI_INBUF *b) {
    size_t used;
    size_t offset;
    if(b->packet_start == b->buffer) {
        return;
    }

    used   = b->readptr - b->packet_start;
    offset = b->packet_start - b->buffer;

    if(used > 0) {
        memmove(b->buffer, b->packet_start, used);
    }
    b->packet_start = b->buffer;
    b->readptr     -= offset;
    b->packet_data -= offset;
    if(b->packet_end) {
        b->packet_end  -= offset;
    }
    b->compacts++;

}

int mi_inbuf_realloc(MI_INBUF *b, size_t needed) {
    MIMYSQL_ENV *env = b->env;
    uint8_t *newbuf;
    uint8_t *oldbuf;
    int x;
    assert(b);
    assert(b->buffer);
    CHECK_ENV_NULL(env);
    CHECK_ENV_MAGIC(env);

    needed += 2;   // make room or hdr + \0
    if(b->buffer_length >= needed) {
        return 0;
    }
    // always have full pages (4096)
    x = needed % 4096;
    if(x != 0) {
        needed -= x + 4096;
    }

    oldbuf = b->buffer;
    newbuf = env->realloc(b->buffer, needed);
    if(newbuf == NULL) {
        return -1;
    }
    if(newbuf != b->buffer) {
        b->readptr       = newbuf + (b->readptr - oldbuf);
        b->endbuf        = newbuf + (b->endbuf  - oldbuf);
        b->packet_start  = newbuf + (b->packet_start - oldbuf);
        
        b->packet_end  = NULL;
        b->packet_data = NULL;
        
        b->buffer = newbuf;
    }
    b->buffer_length = needed;    
    b->reallocs++;

    return 1;
}


// --------------------------------------------------------------------------------

void mi_set_error_text(MYSQL *m,  const char *error, int len) {
    if(len < 0) {
        len = strlen(error);
    }
    if(len >= MYSQL_ERRMSG_SIZE) {
        len = MYSQL_ERRMSG_SIZE - 1;
    }
    memcpy(m->error_text,error,len);
    m->error_text[len] = 0;
}

int mi_connection_has_failed(MYSQL *m,  int error) {
    SET_MYSQL_ERROR(m,CR_TCP_CONNECTION,sqlstate_unknown,"connection failed");
    m->env->close(m->mio);
    m->connected = 0;
    m->mio = NULL;
    return -1;
}


int mi_close_connection(MYSQL *m) {
    mi_log(m,MI_LOG_INFO,"connection closed");
    if(m->mio) {
        m->env->close(m->mio);    
        m->connected = 0;
        m->mio = NULL;
    }
    m->connected = 0;
    m->state = MI_ST_NULL;
    return -1;
}

int mi_read_next_packet(MYSQL *m) {
    MIMYSQL_IO *mio = m->mio;
    MI_INBUF *b = &m->inbuf;
    MIMYSQL_ENV *env = b->env;
    int ret;
    int err;
    size_t full_packet;

    if(b->packet_end) {
        *(b->packet_end) = b->save;
        b->packet_start = b->packet_end;        
    } else {
        b->packet_start = b->buffer;
    }
    
    b->packet_end = NULL;    
    b->packet_data = NULL;

    if(b->packet_start > 0 && b->packet_start == b->readptr) {
        b->readptr =  b->packet_start = b->buffer;
    }

    if((b->readptr - b->packet_start) <  4) {
        if((b->endbuf - b->packet_start) < MINBUF) {
            mi_inbuf_compact(b);
        }
        do {
            b->reads++;
            ret = env->read(mio, b->readptr, b->endbuf - b->readptr, &err);
            if(ret < 0) {
                goto erro;
            }
            if(ret == 0) {
                goto eof;
            }
            b->readptr += ret;
        } while((b->readptr - b->packet_start) <  4);
    }

    b->packet_size = mdata_uint24(b->packet_start);    b->seq   = b->packet_start[3];

    full_packet = b->packet_size + 4;
    if(full_packet > (b->endbuf - b->packet_start)) {
        mi_inbuf_compact(b);
    }

    if(full_packet >= (b->endbuf - b->buffer)) {
        if(mi_inbuf_realloc(b, full_packet) < 0) {
            goto out_of_memory;
        }
    }

    while((b->readptr - b->packet_start) < full_packet) {

        b->reads++;

        ret = env->read(mio, b->readptr, b->endbuf - b->readptr, &err);
        if(ret < 0) {
            goto erro;
            return -1;
        }
        if(ret == 0) {
            goto eof;            
        }
        b->readptr += ret;
    }

    b->packet_end = b->packet_start + full_packet;

    // we save first byte of next packet 
    
    b->save = *(b->packet_end);
    *(b->packet_end) = 0;

    b->packet_data = b->packet_start + 4;
    b->packets++;

    mi_display_packet(m, "READ", b->packet_start, b->packet_end);

    return b->packet_size;


 erro:
    mi_log(m,MI_LOG_ERROR,"read failed: %d", err);
    SET_MYSQL_ERROR(m, CR_TCP_CONNECTION, sqlstate_unknown,"error in writing: %d", err);
    mi_close_connection(m);    
    return -1;

 eof:
    mi_log(m,MI_LOG_ERROR,"read eof %d", err);
    SET_MYSQL_ERROR(m, CR_SERVER_LOST, sqlstate_unknown,"connection to serve lost");
    mi_close_connection(m);    
    return -1;

 out_of_memory:
    mi_log(m,MI_LOG_ERROR,"out of memory");
    SET_MYSQL_ERROR(m,CR_OUT_OF_MEMORY,sqlstate_unknown,"out of memory");
    mi_close_connection(m);        
    return -1;
}



void mysql_system_init(MIMYSQL_ENV *env) {
    mimysql_default_env = env;
}


MYSQL *mysql_init_env(MYSQL *m, MIMYSQL_ENV *env) {
    if(!env) {
        env = mimysql_default_env;
    }
    assert(env != NULL);
    assert(env->magic == MIMYSQL_ENV_MAGIC_V0);
    if(m == NULL) {
        m = env->alloc(sizeof(MYSQL));
        m->allocated = 1;
    } else {
        memset(m ,0,sizeof(MYSQL));
        m->allocated = 0;
    }
    m->magic = MIMYSQL_MAGIC;
    m->env  = env;
    mi_buf_init(env,&m->outbuf,0);
    mi_buf_init(env,&m->field_data_buffer,0);
    mi_buf_init(env,&m->seed,0);
    mi_buf_init(env,&m->auth_data,0);
    m->bufa = NULL;

    mi_inbuf_init(env,&m->inbuf,0);

    return m;
}

MYSQL *mysql_init(MYSQL *m) {
    return mysql_init_env(m, NULL);

}


void mysql_close(MYSQL *m) {
    MIMYSQL_ENV *env;
    int allocated;
    int len;

    assert(m != NULL);
    assert(m->magic == MIMYSQL_MAGIC);
    assert(m->env != NULL);
    assert(m->env->magic == MIMYSQL_ENV_MAGIC_V0);

    env = m->env;

    allocated = m->allocated;

    if(m->connected) {
        mi_send_com(m, CMD_QUIT, NULL, 0);
        m->connected = 0;
    }

    if(m->mio) {
        env->close(m->mio);
        m->mio = NULL;
    }

    if(m->socket) {
        env->free((void*)m->socket);
        m->socket = NULL;
    }
    
    if(m->host) {
        env->free((void*)m->host);
        m->database = NULL;
    }
    if(m->database) {
        env->free((void*)m->database);
        m->database = NULL;
    }
    
    if(m->password) {
        len = strlen(m->password);
        memset((void*)m->password,0,len);
        env->free((void*)m->password);
        m->password = NULL;
    }
    if(m->user) {
        len = strlen(m->user);
        memset((void*)m->user,0,len);
        env->free((void*)m->user);
        m->user = NULL;
    }

    if(m->fields) {
        env->free((void*) m->fields);
        m->fields = NULL;
    }
    
    if(m->field_offsets) {
        env->free((void *) m->field_offsets);
        m->field_offsets = NULL;
    }

    if(m->row_data) {
        env->free((void *) m->row_data);
        m->row_data = NULL;
    }

    if(m->row_lengths) {
        env->free((void *) m->row_lengths);
        m->row_lengths = NULL;
    }
    if(m->bufa) {
        env->free((void*) m->bufa);
        m->bufa = NULL;
    }

    mi_buf_close(&m->outbuf);
    mi_buf_close(&m->field_data_buffer);
    mi_buf_close(&m->auth_data);
    mi_buf_close(&m->seed);

    mi_inbuf_close(&m->inbuf);

    memset(m,0, sizeof(MYSQL));
    
    if(allocated) {
        env->free((void*)m);
    }
}


void mimysql_query_reset(MYSQL *m) {
    mi_buf_reset(&m->outbuf);
    m->state = MI_ST_READY;
}


static uint8_t *find_string_end(uint8_t *p, uint8_t *e) {
    while(p < e) {
        if(!*p) {
            return p;
        }
        p++;
    }
    return NULL;
}

static char *str_dup(MYSQL *m, char *str) {
    char *n;
    if(str == NULL) {
        return NULL;
    }
    int len = strlen(str);
    n = m->env->alloc(len + 1);
    if(n == NULL) {
        mi_log(m,MI_LOG_ERROR,"cannot alloc memory for str_dup");
        return NULL;
    }
    memcpy(n,str,len+1);
    return n;
}


static int mi_write_fully(MIMYSQL_IO *mio, uint8_t *ptr, size_t size, int *err) {
    MIMYSQL_ENV *env = mio->env;
    size_t left =  size;
    int ret;
    while(left > 0) {
        ret = env->write(mio, ptr , left, err);
        if(ret < 0) {
            return ret;
        }
        ptr += ret;
        left -= ret;
    }
    return size;
}

int mi_write_outbuf(MYSQL *m) {
    MIMYSQL_IO *mio = m->mio;
    MI_BUF *o = &m->outbuf;
    uint8_t *buf = o->buf;    
    size_t  write_size = o->ptr - o->buf;
    int ret;
    int err = 0;

    assert(mio && o->buf);
    assert(o->ptr);
    assert(o->ptr > o->buf);
    assert(mio->env == o->env);

    if(m->log_level >= MI_LOG_TRACE) {
        mi_log(m,
               MI_LOG_TRACE,
               "write buf size(%d) seq(%d), size(%d)",
               mdata_uint24(buf),  buf[3], write_size);
    }

    if(m->log_level >= MI_LOG_TRACE) {    
        mi_display_packet(m, "WRITE", o->buf, o->ptr);
    }

    if((ret = mi_write_fully(mio,  buf, write_size, &err)) < 0) {
        mi_log(m,MI_LOG_ERROR,"write failed: %d", err);
        SET_MYSQL_ERROR(m,CR_TCP_CONNECTION,sqlstate_unknown,"write to socket failed: %d", err);
        mi_close_connection(m);
        return ret;
    }
    
    o->ptr = o->buf;
    
    return write_size;
}


static int mimysql_generate_handshake_reply(MYSQL *m) {
    MI_BUF *o = &m->outbuf;
    int ulen;
    int dblen;
    int plugin_len;
    const char *user = m->user ? m->user  : "";
    const char *db = m->database ? m->database : "";
    uint8_t *auth_data = m->auth_data.buf;
    size_t auth_data_len = mi_buf_size(&m->auth_data);
    char *plugin_name = "mysql_native_password";

    
    m->client_caps = m->server_caps & (CLIENT_MYSQL |
                                       CLIENT_CONNECT_WITH_DB |
                                       CLIENT_PROTOCOL_41 |
                                       CLIENT_SECURE_CONNECTION |
                                       CLIENT_PLUGIN_AUTH |
                                       CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA |
                                       CLIENT_DEPRECATE_EOF                                       
                                       );

    ulen = strlen(user);
    dblen = strlen(db);
    plugin_len = strlen(plugin_name);
    
    // just for usere have some extra space 
    
    if(mi_buf_reserve(o, 100 + ulen + dblen + plugin_len) < 0) {
        SET_MYSQL_ERROR(m,CR_OUT_OF_MEMORY,sqlstate_unknown,"out of memory");        
        return -1;
    }
    
    mi_buf_reset_header(o,1);
    
    mi_buf_add_uint32(o, m->client_caps);
    mi_buf_add_uint32(o, mimysql_max_packet);
    mi_buf_add_uint8(o, 45);
    mi_buf_add_zero(o, 19);
    mi_buf_add_zero(o, 4);
    mi_buf_add_str_nul(o, user, ulen);
    if(m->client_caps &  CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
        mi_buf_add_lenc(o, auth_data_len);
        mi_buf_add_data(o, auth_data, auth_data_len);        
    } else if(m->client_caps & CLIENT_SECURE_CONNECTION) {
        mi_buf_add_uint8(o, auth_data_len);
        mi_buf_add_data(o, auth_data, auth_data_len);
    } else {
        mi_buf_add_uint8(o,0);
    }
    if(m->client_caps & CLIENT_CONNECT_WITH_DB) {
        mi_buf_add_str_nul(o, db, dblen);
    }
    if(m->client_caps & CLIENT_PLUGIN_AUTH) {
        mi_buf_add_str_nul(o, plugin_name, plugin_len);
    }
    
    mi_buf_set_length(o);

    // mi_display_packet(m, "handshake-reply",o->buf, o->ptr);

    
    return 0;
}


int mi_send_com(MYSQL *m, int cmd, const char *data, size_t data_len) {
    MI_BUF *o = &m->outbuf;
    if(data == NULL) data_len = 0;

        
    mi_buf_reset(o);

    if(mi_buf_reserve(o, 5 + data_len) < 0) {
        return -1;
    }
    
    mi_buf_reset_header(o,0);
    mi_buf_reserve(o,1 + data_len);
    mi_buf_add_uint8(o,cmd);
    if(data_len > 0) {
        mi_buf_add_data(o, (uint8_t*) data, data_len);
    }
    
    mi_buf_set_length(o);
    
    return  mi_write_outbuf(m);
       
}

                

// ----------------------------------------------------------------------------------------------------

void mi_reset_reply_vars(MYSQL *m) {
    m->warnings = 0;
    m->affected_rows = 0;
    m->last_insert_id = 0;
    m->server_status = 0;
    m->errno = 0;
    m->error_text[0] = 0;
    strcpy(m->sqlstate,"00000");
}


//  PACKET_OK  0x00

int mi_is_ok_packet(uint8_t *p, uint8_t *e) {
    return (e -p) >= 6 && (p[0] == PACKET_OK);
}

int mi_is_okeof_packet(uint8_t *p, uint8_t *e) {
    return (e -p) >= 6 && ((e -p) < 0xffffff) && (p[0] == PACKET_EOF);
}


int mi_parse_ok_packet(MYSQL *m, uint8_t *p, uint8_t *e) {
    int ret;
    if((e - p) < 9) return 0;
    
    if(*p == PACKET_OK) {
        // ok
    } else if(*p == PACKET_EOF && m->client_caps & CLIENT_DEPRECATE_EOF) {
        // ok
    } else {
        return 0;
    }

    
    p++;

    mi_reset_reply_vars(m);

    if((ret = mdata_lenc64(&p, e, &m->affected_rows)) < 0)  return ret;
    if((ret = mdata_lenc64(&p, e, &m->last_insert_id)) < 0) return ret;
    if((e - p) < 4) return -1;

    m->server_status = mdata_uint16(p);  p += 2;
    m->warnings = mdata_uint16(p);  p += 2;

    mi_buf_reset(&m->info);
    mi_buf_add_data(&m->info,p,e-p);
    mi_buf_add_zero(&m->info,1);

    m->packet_type = PACKET_OK;
    return 1;
}


//  PACKET_EOF  0xfe


int mi_is_eof_packet(uint8_t *p, uint8_t *e) {
    return (e -p) < 9 && (p[0] == PACKET_EOF);    
}

int mi_parse_eof_packet(MYSQL *m, uint8_t *p, uint8_t *e) {
   if(*p != PACKET_EOF) return 0;
    if((e-p) >= 9) return 0;
    if((e - p) < 5) return -1;
    p++;

    mi_reset_reply_vars(m);

    m->packet_type = PACKET_EOF;
    m->warnings = mdata_uint16(p);       p += 2;
    m->server_status = mdata_uint16(p);  p += 2;

    return 1;
}


// PACKET_ERR  0xff

int mi_is_err_packet(uint8_t *p, uint8_t *e) {
    return (e-p) >= 3 && p[0] == PACKET_ERR;
}

int mi_parse_err_packet(MYSQL *m, uint8_t *p, uint8_t *e) {

   if(*p != PACKET_ERR) return 0;

    if((e - p) < 3) return -1;
    p++;
    m->packet_type = PACKET_ERR;
    m->errno = mdata_uint16(p); p += 2;
    if(*p == '#') {
        if((e - p) < 6) return -1;
        p++;
        strncpy(m->sqlstate, (char*) p, 5); p += 5;
    } else {
        strcpy(m->sqlstate,"HY000");
    }
    mi_set_error_text(m, (const char*) p, e-p);
    return 1;
}

// mimysql_parse_column_packet();
//  m->field_index = index of field,
//  m->field_data_buf should be reseted before first row.
//  m->field_offsets


#define FERR_OK           0
#define FERR_BAD_LENGTH  -1
#define FERR_TOO_BIG     -2
#define FERR_OUT_OF_MEM  -3

int parse_a_field_string_data(MYSQL *m, uint8_t **ptr, uint8_t *e,
                              uint32_t *length,
                              size_t *offset) {
    uint64_t len;
    uint8_t *p = *ptr;
    MI_BUF *o = &m->field_data_buffer;


    if((len = get_lenc64(&p,e)) == BAD_LENC64) {
        return FERR_BAD_LENGTH;
    }
    
    if((e - p) < len)
        return FERR_TOO_BIG;

    if(mi_buf_reserve(o,len +1) < 0) {
        return FERR_OUT_OF_MEM;
    }
    
    *offset = o->ptr - o->buf;
    *length = len;    

    memcpy(o->ptr, p, len);
    o->ptr[len] = 0;
    o->ptr += len + 1;
    
    p += len;
    *ptr    = p;



    return FERR_OK;
}



int mi_parse_column_packet(MYSQL *m, uint8_t *p, uint8_t *e,
                           MYSQL_FIELD *f,
                           MIMYSQL_FIELD_OFFSET *o) {
    int ret;
    uint32_t val;
    char *pos = "?";

    pos = "packet too short";
    if((e - p) < 10) goto bad;

    // 1.  string<lenenc>  catalog ("def")
    pos = "parse catalog";
    if((ret = parse_a_field_string_data(m, &p, e, &f->catalog_length, &o->catalog_offset)) < 0) goto err;
    
    // 2.  string<lenenc>  db
    pos = "parse db";
    if((ret = parse_a_field_string_data(m, &p, e, &f->db_length, &o->db_offset)) < 0) goto err;    

    // 3.  string<lenenc>  table_alias / table
    pos = "parse table_alias";
    if((ret = parse_a_field_string_data(m, &p, e, &f->table_length, &o->table_offset)) < 0) goto err;

    // 4.  string<lenenc>  table  / orig_table
    pos = "parse org_table";
    if((ret = parse_a_field_string_data(m, &p, e, &f->org_table_length, &o->org_table_offset)) < 0) goto err;    

    // 5. string<lenenc>  column_alias
    pos = "parse column_alias";
    if((ret = parse_a_field_string_data(m, &p, e, &f->name_length, &o->name_offset)) < 0) goto err;        

    // 6. string<lenenc>  column  (org column)
    pos = "parse org_column";
    if((ret = parse_a_field_string_data(m, &p, e, &f->org_name_length, &o->org_name_offset)) < 0) goto err;            

    // fixed length  // should 0xC
    pos ="get fixed fields";
    if(mdata_lenc32(&p,e,&val) <= 0) goto bad;

    pos = "fixed field len";
    if(val < 0x0c) goto bad;

    pos = "fixed field in message";    
    if((e - p) < 0xc) goto bad;
    
    f->charsetnr = mdata_uint16(p); p += 2;
    f->length    = mdata_uint32(p); p += 4;
    f->type      = *p++;
    f->flags     = mdata_uint16(p); p += 2;
    f->decimals  = *p++;
    
    if(m->log_level >= MI_LOG_TRACE) {
        mi_log(m,MI_LOG_TRACE, "(field) (%d) field has been parsed", m->field_index);
    }
    return 0;

 bad:
    mi_log(m,MI_LOG_ERROR, "(field) (%d) (%s) parsing error", m->field_index, pos);
    return -1;
    

 err:
    if(ret == FERR_BAD_LENGTH) {
        mi_log(m,MI_LOG_ERROR, "(field) (%d) (%s) bad length", m->field_index, pos);
    } else if(ret == FERR_TOO_BIG) {
        mi_log(m,MI_LOG_ERROR, "(field) (%d) (%s) too big length", m->field_index, pos);
    } else if(ret == FERR_OUT_OF_MEM) {
        mi_log(m,MI_LOG_ERROR, "(field) (%d) (%s) too big length", m->field_index, pos);
    }
    return -1;
}



void print_server_handshake(MYSQL *m) {
    MIMYSQL_ENV *env = m->env;
    int i;
    char *f;
    char *sa;

    sa = hex_string_buf(env,&m->seed);

    mi_log(m, MI_LOG_TRACE, "server handshake:");
    mi_log(m, MI_LOG_TRACE, "protocol-version: %d", m->protocol_version);
    mi_log(m, MI_LOG_TRACE, "server-version: %s", notnull(m->server_version));
    mi_log(m, MI_LOG_TRACE, "connection-id %d", m->connection_id);
    mi_log(m, MI_LOG_TRACE, "server-caps: %8lx", m->server_caps);
    mi_log(m, MI_LOG_TRACE, "server-collation: %d", m->server_collation);
    mi_log(m, MI_LOG_TRACE, "server-collation: %04x", m->server_status);
    mi_log(m, MI_LOG_TRACE, "seed-len: %d", mi_buf_size(&m->seed));
    mi_log(m, MI_LOG_TRACE, "scrmable: %s",  sa);
    mi_log(m, MI_LOG_TRACE, "auth-plugin: %s", notnull(m->auth_plugin_name));
    for(i=0; i < 64; i++) {
        f = mysql_cap_flags[i];
        if((m->server_caps & ((uint64_t) 1 << i)) != 0 && f) {
            mi_log(m, MI_LOG_TRACE,"cap: %s", f);
        }
    }
    mi_log(m, MI_LOG_TRACE,"all");

    env->free(sa);
}

                                       


int mi_parse_handshake_packet(MYSQL *m, uint8_t *p, uint8_t *e) {
    uint8_t *tmp;
    int l;

    mi_display_packet(m, "parse-handshake", p, e);

    if((e - p) < 30) {
        goto overflow;
    }

     m->protocol_version = *p++;

    if(m->protocol_version != MYSQL_PROTOCOL_VERSION) {
        mi_log(m,MI_LOG_ERROR, "(parse_handshake) unknown protocol version: %d", m->protocol_version);
        SET_MYSQL_ERROR(m,CR_VERSION_ERROR, sqlstate_unknown, "unknown protocol version: %d", m->protocol_version);
        return -1;
    }

    tmp = find_string_end(p,e);
    if(!tmp) {
        mi_log(m,MI_LOG_ERROR, "(parse-handshake) version does not end");
        goto overflow;
    }
    if((m->server_version = str_dup(m,(char*)p)) == NULL) {
        goto out_of_mem;
    }
    p = tmp + 1;

    mi_log(m,MI_LOG_DEBUG,"(parse-handshake) server version: (%s)", m->server_version);

    if((e - p) < 27) {
        goto overflow;        
    }

    m->connection_id = mdata_uint32(p); p += 4;
    mi_buf_add_data(&m->seed,p,8);  p += 8;
    /* reserved */                      p += 1;
    m->server_caps = (uint64_t) mdata_uint16(p);   p += 2;
    m->server_collation =  *p;             p += 1;
    m->server_status = mdata_uint16(p);    p += 2;
    m->server_caps |= ((uint64_t) (mdata_uint16(p)) << 16);  p += 2;


    if(m->server_caps & CLIENT_PLUGIN_AUTH) {
        m->plugin_data_len =  *p++;
    } else {
        m->plugin_data_len =  0;
        p++;
    }

    p += 6;
    if(!(m->server_caps & CLIENT_MYSQL)) {
        m->server_caps |= ((uint64_t) mdata_uint32(p)) << 32;
    }
    p += 4;

    if(m->server_caps & CLIENT_SECURE_CONNECTION) {
        l = m->plugin_data_len - 9;
        if(l < 12) l = 12;
        if((e - p) < 13)  goto overflow;
        mi_buf_add_data(&m->seed,p,l); p += l;
        p++;
    }

    if(m->server_caps & CLIENT_PLUGIN_AUTH) {
        tmp = find_string_end(p,e);
        if(!tmp) {
            mi_log(m,MI_LOG_ERROR, "(parse-handshake) plugin data no nul");
            goto overflow;
        }
        if((m->auth_plugin_name = str_dup(m, (char*)p)) == NULL) {
            goto out_of_mem;
        }
    }

    mi_log(m,MI_LOG_DEBUG,"(parse-handshake) auth_plugin_name (%s)", m->auth_plugin_name ?  m->auth_plugin_name : "NULL");

    if(m->log_level >= MI_LOG_DEBUG) {
        mi_display_caps(m, m->server_caps,"server");
    }
    if(m->log_level >= MI_LOG_TRACE) {
        print_server_handshake(m);
    }
    return 0;
    

 overflow:
    SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,sqlstate_unknown,"cannot parse handshake packet");
    return -1;
    
 out_of_mem:
    SET_MYSQL_ERROR(m,CR_OUT_OF_MEMORY,"HY000","out of memory");
    return -1;

}


int mimysql_native_password(MYSQL *m) {
    MIMYSQL_ENV *env  = m->env;
    const char *pass = m->password;
    char *sa;
    char *aa;
    
    MI_BUF *s = &m->seed;
    int seed_len;
    int pass_len;
    int i;
    uint8_t sha1[21];
    uint8_t sha2[21];
    uint8_t sha3[21];
    uint8_t apu[41];
    uint8_t sha4[21];
    

    seed_len = mi_buf_size(s);

    if(seed_len != 20) {
        mi_log(m,MI_LOG_ERROR,"(mysql_native_password) bad seed len: %d", seed_len);
        return -1;
    }
        
    if(pass == NULL) {
        pass = "";
    }

    pass_len = strlen(pass);

    env->sha1(sha1, (void*) pass, pass_len);
    env->sha1(sha2, (void*) sha1, 20);
    memcpy(apu, s->buf, 20);
    memcpy(apu + 20, sha2, 20);

    env->sha1(sha3, apu, 40);

    for(i=0; i < 20; i++) {
        sha4[i] = sha1[i] ^ sha3[i];
    }

    mi_buf_reset(&m->auth_data);
    mi_buf_add_data(&m->auth_data, sha4, 20);


    if(m->log_level >= MI_LOG_TRACE) {
        sa = hex_string_buf(env,&m->seed);
        aa = hex_string_buf(env,&m->auth_data);
        mi_log(m,MI_LOG_TRACE,"SEED:   %s", sa);
        mi_log(m,MI_LOG_TRACE,"RESULT: %s", aa);
        env->free(sa);
        env->free(aa);
    }
    
    return 0;
}



int mi_wait_for_ok(MYSQL *m) {
    int ret;
    uint8_t ptype;
    MI_INBUF *b = &m->inbuf;  

    if(mi_read_next_packet(m) < 0){
        return -1;
    }
 
    ptype = b->packet_data[0];
    
    if(mi_is_ok_packet(b->packet_data, b->packet_end)) {
        m->packet_type = PACKET_OK;
        ret = mi_parse_ok_packet(m, b->packet_data, b->packet_end);
        mi_log(m,MI_LOG_DEBUG,"(waitok) OK server-status: %d,  info=%s", m->server_status, m->info.buf ? (const char*) m->info.buf : "NULL");
    } else if(mi_is_err_packet(b->packet_data, b->packet_end)) {
        m->packet_type = PACKET_ERR;
        ret = mi_parse_err_packet(m, b->packet_data, b->packet_end);
        mi_log(m,MI_LOG_WARN,"(waitok) got error  packet: error-code: %d,  info=%s", m->errno,  m->error_text);
        return -1;
    } else {
        mi_log(m,MI_LOG_ERROR,"(waitok) illegal reply type: %d", ptype);
        return -1;
    }
    
    return 1;
}




MYSQL *mysql_real_connect(MYSQL *m,
                          const char *host,
                          const char *user,
                          const char *password,
                          const char *db,
                          unsigned int port,
                          const char *unix_socket,
                          unsigned long flags)
{
    MIMYSQL_ENV *env  = m->env;
    MIMYSQL_IO *mio = NULL;
    MI_INBUF *b;
    int err = 0;
    int ret;
    assert(m->magic == MIMYSQL_MAGIC);

    
    if(m->user) env->free((void*)m->user);
    if(m->password) env->free((void*)m->password);
    if(m->database) env->free((void*)m->database);
    if(m->socket) env->free((void*)m->socket);
    if(m->host)   env->free((void*)m->host);

    m->user = NULL;
    m->password = NULL;
    m->database = NULL;
    m->host = NULL;
    m->socket = NULL;
    m->port = 0;
    
    if(user) {
        m->user = str_dup(m,(char*)user);
        if(m->user == NULL) goto out_of_mem;        
    }
    if(password) {
        m->password = str_dup(m,(char*)password);
        if(m->password == NULL) goto out_of_mem;
    }
    if(db) {
        m->database = str_dup(m,(char*)db);
        if(m->database == NULL) goto out_of_mem;
    }
    if(unix_socket) {
        m->socket = str_dup(m,(char*)unix_socket);
        if(m->socket == NULL) goto out_of_mem;
    }
    if(host) {
        m->host = str_dup(m,(char*)host);
        if(m->host == NULL) goto out_of_mem;
    }
    if(port) {
        m->port = port;
    }
    
    if(unix_socket) {
        mio = env->connect_unix(m, unix_socket, 0, &err);
        if(mio == NULL) {
            SET_MYSQL_ERROR(m,CR_LOCALHOST_CONNECTION,sqlstate_unknown,"cannot connect unix socket errno=%d", err);
            return NULL;
        }
    } else {
        SET_MYSQL_ERROR(m,CR_SOCKET_CREATE_ERROR,sqlstate_unknown,"only unix domain is supported so far");
        mi_log(m,4,"only unix domain supported");
        return NULL;
    }

    if(mio == NULL) {
        SET_MYSQL_ERROR(m,CR_SOCKET_CREATE_ERROR,sqlstate_unknown,"cannot get connection: %d", err);
        mi_log(m,MI_LOG_ERROR,"cannot connect error: %d", err);
        return NULL;
    }

    m->mio = mio;
    b = &m->inbuf;

    if(mi_read_next_packet(m) < 0){
        return NULL;
    }

    mi_log(m,MI_LOG_DEBUG,"got handshake packet: seq=%d packet_size=%d", b->seq, b->packet_size);

    ret = mi_parse_handshake_packet(m, b->packet_data, b->packet_end);

    if(ret < 0) {
        if(ret == -2) {
            mi_log(m,MI_LOG_ERROR,"handshake packet overflow");
        }
        SET_MYSQL_ERROR(m,CR_SERVER_HANDSHAKE_ERR,sqlstate_unknown,"handshanke parsing error");
        mi_close_connection(m);
        return NULL;
    }

    mi_log(m,MI_LOG_DEBUG,"handlshake parsed: %s  auth-plugin: %s",  m->server_version, m->auth_plugin_name ? m->auth_plugin_name : "NULL");
    
    if(m->auth_plugin_name == NULL) {
        SET_MYSQL_ERROR(m,CR_AUTH_PLUGIN_ERR,sqlstate_unknown,"no auth plugin given by server");
        mi_close_connection(m);
        return NULL;
    } else if(strcmp(m->auth_plugin_name, "mysql_native_password") != 0) {
        SET_MYSQL_ERROR(m,CR_AUTH_PLUGIN_ERR,sqlstate_unknown,"do not support auth_plugin: %s", m->auth_plugin_name);
        mi_close_connection(m);
        return NULL;        
    }

    if(mimysql_native_password(m)) {
        if(m->errno == 0) {
            SET_MYSQL_ERROR(m,CR_AUTH_PLUGIN_ERR,sqlstate_unknown,"native handshake error");
        }
        mi_close_connection(m);
        return NULL;
    }

    mi_log(m,MI_LOG_DEBUG,"send reply");

    if(mimysql_generate_handshake_reply(m) < 0) {
        if(m->errno == 0) {
            SET_MYSQL_ERROR(m, CR_UNKOWN_ERROR, sqlstate_unknown,"generating handshake");
        }
        mi_close_connection(m);        
        return NULL;
    }

    if((ret = mi_write_outbuf(m)) < 0) {
        mi_close_connection(m);
        return NULL;
    }
    
    mi_log(m,MI_LOG_DEBUG,"handlshake reply sent");

    if(mi_wait_for_ok(m) < 0) {
        mi_log(m,MI_LOG_ERROR,"login not accept");
        mi_close_connection(m);        
        return NULL;
    }
    
    mi_log(m,MI_LOG_DEBUG,"connected");
          
    m->connected = 1;
    m->state = MI_ST_READY;
    return m->connected ? m : NULL;

 out_of_mem:
    mi_log(m,MI_LOG_ERROR,"out of memory in connect");
    SET_MYSQL_ERROR(m,CR_OUT_OF_MEMORY,"HY000","out of memory");
    return NULL;
}


int mysql_real_query(MYSQL *m,  const char *query, unsigned long length) {
    MIMYSQL_ENV *env  = m->env;    
    MI_INBUF *b = &m->inbuf;
    int ret;
    int i;
    uint8_t *p;
    uint8_t *e;
    char *bufbase;
    void *a;  /* helping for realloc */
    
    if(!(m->connected)) {
        SET_MYSQL_ERROR(m,CR_TCP_CONNECTION,"HY000","not connected");
        mi_log(m,3,"not connected");
        return -1;
    }

    if(m->state != MI_ST_READY) {
        mi_log(m,3,"wrong state: %d", m->state);
        SET_MYSQL_ERROR(m,CR_COMMANDS_OUT_OF_SYNC,"HY000","wrong starte in starting of query: %d %s", m->state, mi_state_str[m->state]);
        return -1;
    }

    CLEAR_MYSQL_ERROR(m);
    
    m->row_count = 0;
    m->field_count = 0;
    m->res_open = 0;
    
    if(mi_send_com(m, CMD_QUERY, query, length) < 0) {
        mi_log(m,4,"error wring query");
        goto write_error;
    }

    m->state = MI_ST_QUERY_SENT;


    // GET OK or FIELD COUNTER PACKET

    if(mi_read_next_packet(m) < 0) {
        mi_log(m,4,"(query) cannot get ok-packet");
        goto read_error;
    }

    if(b->packet_size < 1) {
        mi_log(m,4,"(query) ok/err/counter packet is empty");
        SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,sqlstate_unknown,"empty size packet");
        goto bad_packet;
    }

    p = b->packet_data;
    e = b->packet_end;


    //  CHECK FOR RESULT  / FIELD COUNT

    if(mi_is_err_packet(p,e)) {
        ret = mi_parse_err_packet(m, p, e);
        mi_log(m,MI_LOG_WARN,"query error : error-code: %d,  info=%s", m->errno,  m->error_text);
        m->state = MI_ST_READY;        
        return -1;
    }

    if(mi_is_eof_packet(p,e)) {
        ret = mi_parse_eof_packet(m, p, e);
        mi_log(m,MI_LOG_ERROR,"query eof?????? : error-code: %d,  info=%s", m->errno,  m->error_text);
        goto packet_out_of_sync;
    }

    if(mi_is_ok_packet(p,e)) {
        ret = mi_parse_ok_packet(m, b->packet_data, b->packet_end);
        m->state = MI_ST_READY;
        mi_log(m,MI_LOG_INFO,"(query) ok server-status: %d,  info=%s", m->errno, m->info.buf);
        return 0;
    }

    // should be field count
    
    if(mdata_lenc32(&p, e, &m->field_count) <= 0) {
        goto bad_packet;
    }
    
    if(p != e) {
        mi_log(m,3,"query: data after rowcount");
        goto bad_packet;        
    }

    if(m->field_count == 0) {
        mi_log(m,3,"query: zero field count");
        goto bad_packet;
    }

    m->state = MI_ST_QUERY_FIELDS;

    // GET FIELD VALUES 

    if(m->fields == NULL) {
        m->max_fields = 16;
        if(m->field_count > m->max_fields) {
            m->max_fields  = m->field_count;
        }
        if((m->fields = env->alloc(sizeof(MYSQL_FIELD) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        if((m->field_offsets = env->alloc(sizeof(MIMYSQL_FIELD_OFFSET) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        if((m->row_data = env->alloc(sizeof(char *) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        if((m->row_lengths = env->alloc(sizeof(uint32_t) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        
    } else if(m->field_count > m->max_fields) {
        m->max_fields = m->field_count;
        if((a = env->realloc(m->fields, sizeof(MYSQL_FIELD) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;            
        }
        m->fields = a;
        
        if((a = env->realloc(m->field_offsets, sizeof(MIMYSQL_FIELD_OFFSET) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        m->field_offsets = a;
        
        if((a = env->realloc(m->row_data, sizeof(char *) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        m->row_data = a;
        
        if((a = env->realloc(m->row_data, sizeof(uint32_t) * (m->max_fields + 1))) == NULL) {
            goto out_of_mem;
        }
        m->row_lengths = a;
        
    }
    
    memset((void*) m->fields, 0, sizeof(MYSQL_FIELD) * (m->field_count + 1));
    memset((void*) m->field_offsets, 0, sizeof(MIMYSQL_FIELD_OFFSET) * (m->field_count + 1));
    memset((void*) m->row_data, 0, sizeof(char *) * (m->field_count + 1));
    memset((void*) m->row_lengths, 0, sizeof(uint32_t) * (m->field_count + 1));
    
    mi_buf_reset(&m->field_data_buffer);


    for(m->field_index = 0; m->field_index < m->field_count; m->field_index++) {
        
        if(mi_read_next_packet(m) < 0){
            mi_log(m,4,"(query) field read error : index=%", m->field_index);
            goto read_error;
        }
        if(b->packet_size < 1) {
            mi_log(m,4,"(query) empty field packet index=%", m->field_index);
            goto bad_packet;
        }
        if(mi_parse_column_packet(m,
                                  b->packet_data,
                                  b->packet_end,
                                  &m->fields[m->field_index],
                                  &m->field_offsets[m->field_index]) < 0) {
            
            goto bad_packet;
        }
    }


    // get deprectead EOF packet (if needed)

    
    if(!(m->client_caps & CLIENT_DEPRECATE_EOF)) {

        m->state = MI_ST_QUERY_FIELDS_EOF;
        
        if(mi_read_next_packet(m) < 0){
            goto read_error;
        }
        if(b->packet_size < 1) {
            goto bad_packet;
        }
        
        if(!mi_is_eof_packet(b->packet_data, b->packet_end)) {
            goto packet_out_of_sync;
        }
    }

    // fix field offsets

    bufbase = (char *) m->field_data_buffer.buf;
    
    for(i = 0; i < m->field_count; i++) {
        MYSQL_FIELD *f = &m->fields[i];
        MIMYSQL_FIELD_OFFSET *o = &m->field_offsets[i];
        f->name = bufbase + o->name_offset;
        f->org_name = bufbase + o->org_name_offset;
        f->table = bufbase +  o->table_offset;
        f->org_table = bufbase + o->org_table_offset;
        f->db = bufbase + o->db_offset;
        f->catalog = bufbase + o->catalog_offset;
    }

    if(m->log_level >= MI_LOG_DEBUG) {
        for(i = 0; i < m->field_count; i++) {
            MYSQL_FIELD *f = &m->fields[i];
            mi_log(m, MI_LOG_DEBUG,"FIELD: %s, %s, %s, %s, %s, %s, %d", f->name, f->org_name, f->table, f->org_table, f->db, f->catalog, f->type);
        }
    }

    m->state = MI_ST_QUERY_ROWS;
    m->res_open = 1;
    m->resp[0].m = m;
    
    return 0;

 write_error:
    mi_log(m,4,"write error");
    mi_close_connection(m);
    return -1;
    

 read_error:
    mi_log(m,4,"read error");
    mi_close_connection(m);
    return -1;

 out_of_mem:
    mi_log(m,4,"out of memory");
    mi_close_connection(m);
    if(!m->errno) {
        SET_MYSQL_ERROR(m,CR_OUT_OF_MEMORY,"HY000","out of memory");
    }
    return -1;

 packet_out_of_sync:
    mi_log(m,4,"packet of sync");
    mi_close_connection(m);
    if(!m->errno) {
        SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,"HY000","n starting of query: %d %s", m->state, mi_state_str[m->state]);
    }
    return -1;

 bad_packet:
    mi_log(m,4,"bad packet");
    if(!m->errno) {
        SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,"HY000","bad packet");
    }
    mi_close_connection(m);
    return -1;
    
}


int mi_skip_results(MYSQL *m) {
     MI_INBUF *b = &m->inbuf;

    if(m->state == MI_ST_QUERY_ROWS) {
        return -1;
    }

    for(;;) {
        if(mi_read_next_packet(m) < 0){
            mi_close_connection(m);
            return -1;
        }
        
        if(b->packet_size < 1) {
            mi_close_connection(m);
            return -1;
        }
        
        if(mi_is_err_packet(b->packet_data, b->packet_end)) {
            if(mi_parse_err_packet(m,b->packet_data, b->packet_end) < 0)  {
            }
            break;
        }
        
        if(m->client_caps & CLIENT_DEPRECATE_EOF) {
            if(mi_is_okeof_packet(b->packet_data, b->packet_end)) {
                mi_parse_ok_packet(m,b->packet_data, b->packet_end);
                break;
            }
        } else {
            if(mi_is_eof_packet(b->packet_data, b->packet_end)) {
                mi_parse_eof_packet(m,b->packet_data, b->packet_end);
                break;
            }
        }
        m->row_count++;
    }

    
    m->state = MI_ST_READY;
    return 0;
}

                  

int mysql_query(MYSQL *m,  const char *query) {
    return mysql_real_query(m, query, strlen(query));
}

int mysql_prepare(MYSQL *m,  const char *query, size_t length, ...) {
    return 0;
}

uint32_t mysql_field_count(MYSQL *m) {
    return m->field_count;
}

uint32_t mysql_num_fields(MYSQL_RES *res) {
    return res->m->field_count;
}

MYSQL_FIELD * mysql_fetch_fields(MYSQL_RES * res) {
    MYSQL *m = res->m;
    return m->fields;
}

MYSQL_FIELD * mysql_fetch_field_direct(MYSQL_RES * res,
                                       unsigned int fieldnr)
{
    MYSQL *m = res->m;
    if(m->state != MI_ST_QUERY_ROWS) {    
        return NULL;
    }
    if(fieldnr >= m->field_count) {
        return NULL;
    }
    return &m->fields[fieldnr];
}


uint32_t *mysql_fetch_lengths(MYSQL_RES *res) {
    MYSQL *m = res->m;
    if(m->state != MI_ST_QUERY_ROWS) {
        return NULL;
    }
    return m->row_lengths;
}


MYSQL_RES *mysql_use_result(MYSQL *m) {
    if(m->state != MI_ST_QUERY_ROWS) {
        return NULL;
    }
    return &m->resp[0];
}

MYSQL_ROW mysql_fetch_row(MYSQL_RES *res) {
    MYSQL *m = res->m;
    MI_INBUF *b = &m->inbuf;
    uint8_t *prev;
    uint8_t *p;
    uint8_t *e;
    int i;
    int ret;
    uint64_t col_len;

    
    if(m->state != MI_ST_QUERY_ROWS) {
        return NULL;
    }

    if(!(m->res_open)) {
        return NULL;
    }
    
    if(mi_read_next_packet(m) < 0){
        return NULL;
    }
    
    if(b->packet_size < 1) {
        return NULL;

    }

    if(mi_is_err_packet(b->packet_data, b->packet_end)) {
        mi_parse_err_packet(m, b->packet_data, b->packet_end);
        mi_log(m,4,"error when skipping query : %d : %s", m->errno, m->error_text);
        m->state = MI_ST_READY;
        m->res_open = 0;
        return NULL;
    }
    
    if(m->client_caps & CLIENT_DEPRECATE_EOF) {
        if(mi_is_okeof_packet(b->packet_data, b->packet_end)) {
            mi_parse_ok_packet(m,b->packet_data, b->packet_end);
            m->state = MI_ST_READY;
            m->res_open = 0;            
            return NULL;            
        }
    } else {
        if(mi_is_eof_packet(b->packet_data, b->packet_end)) {
            mi_parse_ok_packet(m,b->packet_data, b->packet_end);
            m->state = MI_ST_READY;
            m->res_open = 0;            
            return NULL;
        }
    }

    p = b->packet_data;
    e = b->packet_end;
    prev = NULL;
    
    for(i=0; i < m->field_count; i++) {
        prev = p;
        ret = mdata_lenc64(&p,e,&col_len);
        *prev = 0;   // put NUL to end
        if(ret < 0) {
            SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,"HY000","bad lenc");
            mi_log(m,4,"(mysql_fetch_row) bad lenc : %d", ret);
            return NULL;            
        } else if(ret == 0) {
            m->row_data[i] = NULL;
            m->row_lengths[i] = -1;
        } else if((p + col_len) > e) {
            m->row_data[i] = NULL;
            m->row_lengths[i] = -1;
            SET_MYSQL_ERROR(m,CR_MALFORMED_PACKET,"HY000","bad packet: ");
            mi_log(m,4,"(mysql_fetch_row) field to long for packet: %d  room: %d", col_len, e - p);
            return NULL;
        } else {
            m->row_data[i] = (char *) p;
            m->row_lengths[i] = col_len;
        }
        p += col_len;
    }
    *p = 0;    // next rows first byte always saved.
    m->row_count++;
    
    return m->row_data;
}

size_t mysql_quote(MYSQL *mysql, char *to, size_t tolen, const char *from, unsigned long length) {
    return 0;
}

unsigned long mysql_real_escape_string(MYSQL * mysql, char * to, const char * from, unsigned long length) {
    return 0;
}

void mysql_free_result(MYSQL_RES *res) {
    // its do nothing here
    
}



int mysql_ping(MYSQL *m) {
    
    if(!m->connected) {
        return -1;
    }
    
    if(mi_send_com(m, CMD_PING, NULL, 0) < 0) {
        mi_log(m,MI_LOG_ERROR,"could not send ping");
        mi_close_connection(m);        
        return -1;
    }

    if(mi_wait_for_ok(m) < 0) {
        mi_log(m,MI_LOG_ERROR,"could not get pong");
        mi_close_connection(m);        
        return -1;
    }
    
    return 0;
}


const char * mysql_stat(MYSQL * m) {
    MI_INBUF *b = &m->inbuf;
    
    if(! m->connected) {
        return NULL;
    }
    
    if(mi_send_com(m, CMD_STATISTICS, NULL, 0) < 0) {
        mi_log(m,MI_LOG_ERROR,"could not send stats");
        mi_close_connection(m);        
        return NULL;
    }

    mi_log(m,MI_LOG_DEBUG ,"waiting stats");
    if(mi_read_next_packet(m) < 0){
        mi_log(m,4,"could not get stats reply");
        mi_close_connection(m);
        return NULL;
    }
    
    // mi_display_packet(m->env, b->packet_data, b->packet_end);

    return (const char *) b->packet_data;
}


int mysql_errno(MYSQL *m) {
    return m->errno;
}

 
const char * mysql_error(MYSQL *m) {
    return m->error_text;
}

const char * mysql_info(MYSQL *m) {
    return (const char *) m->info.buf;
}

unsigned int mysql_affected_rows(MYSQL * mysql) {
    return mysql->affected_rows;
}
unsigned int mysql_warning_count(MYSQL *mysql) {
    return mysql->warnings;
}




const char *mysql_get_type_name(int type) {
    switch(type) {
    case MYSQL_TYPE_DECIMAL:      return "DECIMAL";
    case MYSQL_TYPE_TINY:         return "TINY";
    case MYSQL_TYPE_SHORT:        return "SHORT";
    case MYSQL_TYPE_LONG:         return "LONG";
    case MYSQL_TYPE_FLOAT:        return "FLOAT";
    case MYSQL_TYPE_DOUBLE:       return "DOUBLE";
    case MYSQL_TYPE_NULL:         return "NULL";
    case MYSQL_TYPE_TIMESTAMP:    return "TIMESTAMP";
    case MYSQL_TYPE_LONGLONG:     return "LONGLONG";
    case MYSQL_TYPE_INT24:        return "INT24";
    case MYSQL_TYPE_DATE:         return "DATE";
    case MYSQL_TYPE_TIME:         return "TIME";
    case MYSQL_TYPE_DATETIME:     return "DATETIME";
    case MYSQL_TYPE_YEAR:         return "YEAR";
    case MYSQL_TYPE_NEWDATE:      return "NEWDATE";
    case MYSQL_TYPE_VARCHAR:      return "VARCHAR";
    case MYSQL_TYPE_BIT:          return "BIT";
    case MYSQL_TYPE_TIMESTAMP2:   return "TIMESTAMP2";
    case MYSQL_TYPE_DATETIME2:    return "DATETIME2";
    case MYSQL_TYPE_TIME2:        return "TIME2";
    case MYSQL_TYPE_JSON:         return "JSON";
    case MYSQL_TYPE_NEWDECIMAL:   return "NEWDECIMAL";
    case MYSQL_TYPE_ENUM:         return "ENUM";
    case MYSQL_TYPE_SET:          return "SET";
    case MYSQL_TYPE_TINY_BLOB:    return "TINY_BLOB";
    case MYSQL_TYPE_MEDIUM_BLOB:  return "MEDIUM_BLOB";
    case MYSQL_TYPE_LONG_BLOB:    return "LONG_BLOB";
    case MYSQL_TYPE_BLOB:         return "BLOB";
    case MYSQL_TYPE_VAR_STRING:   return "VAR_STRING";
    case MYSQL_TYPE_STRING:       return "STRING";
    case MYSQL_TYPE_GEOMETRY:     return "GEOMETRY";
    default: return "?";
    };
}


// # if defined(__unix__) or defined(unix)
// extern MIMYSQL_ENV mimysql_unix_env;

// MIMYSQL_ENV *mimysql_default_env = &mimysql_unix_env;;
// #endif
