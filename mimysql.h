/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef _MIMYSQL_H_
#define _MIMYSQL_H_

#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------------

#define MYSQL_PROTOCOL_VERSION 10
#define MYSQL_ERRMSG_SIZE	512

// -----------------------------------------------------------------------------------

#define CR_MIN_ERROR                2000
#define CR_MAX_ERROR                2999

#define CR_UNKOWN_ERROR             2000
#define CR_SOCKET_CREATE_ERROR      2001
#define CR_CONN_HOST_ERROR          2003
#define CR_IPSOCK_ERROR             2004
#define CR_UNKNOWN_HOST             2005
#define CR_VERSION_ERROR            2007
#define CR_OUT_OF_MEMORY            2008
#define CR_WRONG_HOST_INFO          2009
#define CR_LOCALHOST_CONNECTION     2010
#define CR_TCP_CONNECTION           2011
#define CR_SERVER_HANDSHAKE_ERR     2012
#define CR_SERVER_LOST              2013
#define CR_COMMANDS_OUT_OF_SYNC     2014
#define CR_NAMEDPIPE_CONNECTION     2015
#define CR_NAMEDPIPEWAIT_ERROR      2016
#define CR_NAMEDPIPEOPEN_ERROR      2017
#define CR_NAMEDPIPESETSTATE_ERROR  2018
#define CR_CANT_READ_CHARSET        2019
#define CR_NET_PACKET_TOO_LARGE     2020
#define CR_SSL_CONNECTION_ERROR     2026
#define CR_MALFORMED_PACKET         2027
#define CR_NO_PREPARE_STMT          2030
#define CR_PARAMS_NOT_BOUND         2031
#define CR_INVALID_PARAMETER_NO     2034
#define CR_INVALID_BUFFER_USE       2035
#define CR_UNSUPPORTED_PARAM_TYPE   2036
#define CR_SHARED_MEMORY_CONNECTION 2037
#define CR_SHARED_MEMORY_CONNECT_ERROR 2038
#define CR_CONN_UNKNOWN_PROTOCOL     2047
#define CR_SECURE_AUTH               2049
#define CR_NO_DATA                   2051
#define CR_NO_STMT_METADATA          2052
#define CR_NOT_IMPLEMENTED           2054
#define CR_STMT_CLOSED               2056
#define CR_NEW_STMT_METADATA         2057
#define CR_ALREADY_CONNECTED         2058
#define CR_AUTH_PLUGIN_CANNOT_LOAD   2059
#define CR_DUPLICATE_CONNECTION_ATTR 2060
#define CR_AUTH_PLUGIN_ERR           2061

#define CR_MYSQL_LAST_ERROR CR_AUTH_PLUGIN_ERR



#define NOT_NULL_FLAG	           1             // field cannot be null
#define PRIMARY_KEY_FLAG           2             // field is a primary key
#define UNIQUE_KEY_FLAG	           4             // field is unique
#define MULTIPLE_KEY_FLAG	       8             // field is in a multiple key
#define BLOB_FLAG	               16            // is this field a Blob
#define UNSIGNED_FLAG              32            // is this field unsigned
#define ZEROFILL_FLAG              64            // is this field a zerofill
#define BINARY_COLLATION_FLAG      128           // whether this field has a binary collation
#define ENUM_FLAG	               256           // Field is an enumeration
#define AUTO_INCREMENT_FLAG        512           // field auto-increment
#define TIMESTAMP_FLAG	           1024          // field is a timestamp value
#define SET_FLAG	               2048          // field is a SET
#define NO_DEFAULT_VALUE_FLG       4096          // field doesn't have default value
#define ON_UPDATE_NOW_FLAG	       8192          // field is set to NOW on UPDATE
#define NUM_FLAG	               32768         // field is num


#define SERVER_STATUS_IN_TRANS               1	/* Transaction has started */
#define SERVER_STATUS_AUTOCOMMIT             2	/* Server in auto_commit mode */
#define SERVER_MORE_RESULTS_EXIST            8
#define SERVER_QUERY_NO_GOOD_INDEX_USED     16
#define SERVER_QUERY_NO_INDEX_USED          32
#define SERVER_STATUS_CURSOR_EXISTS         64
#define SERVER_STATUS_LAST_ROW_SENT        128
#define SERVER_STATUS_DB_DROPPED           256
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES 512
#define SERVER_STATUS_METADATA_CHANGED    1024
#define SERVER_QUERY_WAS_SLOW             2048
#define SERVER_PS_OUT_PARAMS              4096
#define SERVER_STATUS_IN_TRANS_READONLY   8192
#define SERVER_SESSION_STATE_CHANGED     16384
#define SERVER_STATUS_ANSI_QUOTES        32768



#define CLIENT_LONG_PASSWORD    0       /* obsolete flag */
#define CLIENT_MYSQL            1ULL       /* mysql/old mariadb server/client */
#define CLIENT_FOUND_ROWS       2ULL    /* Found instead of affected rows */
#define CLIENT_LONG_FLAG        4ULL    /* Get all column flags */
#define CLIENT_CONNECT_WITH_DB  8ULL    /* One can specify db on connect */
#define CLIENT_NO_SCHEMA        16ULL   /* Don't allow database.table.column */
#define CLIENT_COMPRESS         32ULL   /* Can use compression protocol */
#define CLIENT_ODBC             64ULL   /* Odbc client */
#define CLIENT_LOCAL_FILES      128ULL  /* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE     256ULL  /* Ignore spaces before '(' */
#define CLIENT_PROTOCOL_41      512ULL  /* New 4.1 protocol */
#define CLIENT_INTERACTIVE      1024ULL /* This is an interactive client */
#define CLIENT_SSL              2048ULL /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE   4096ULL    /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS     8192ULL /* Client knows about transactions */
#define CLIENT_RESERVED         16384ULL   /* Old flag for 4.1 protocol  */
#define CLIENT_SECURE_CONNECTION 32768ULL  /* New 4.1 authentication */
#define CLIENT_MULTI_STATEMENTS (1ULL << 16) /* Enable/disable multi-stmt support */
#define CLIENT_MULTI_RESULTS    (1ULL << 17) /* Enable/disable multi-results */
#define CLIENT_PS_MULTI_RESULTS (1ULL << 18) /* Multi-results in PS-protocol */

#define CLIENT_PLUGIN_AUTH  (1ULL << 19) /* Client supports plugin authentication */
#define CLIENT_CONNECT_ATTRS (1ULL << 20) /* Client supports connection attributes */
/* Enable authentication response packet to be larger than 255 bytes. */
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA (1ULL << 21)
/* Don't close the connection for a connection with expired password. */
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS (1ULL << 22)

/**
  Capable of handling server state change information. Its a hint to the
  server to include the state change information in Ok packet.
*/
#define CLIENT_SESSION_TRACK (1ULL << 23)
/* Client no longer needs EOF packet */
#define CLIENT_DEPRECATE_EOF (1ULL << 24)

#define CLIENT_PROGRESS_OBSOLETE  (1ULL << 29)
#define CLIENT_SSL_VERIFY_SERVER_CERT (1ULL << 30)
/*
  It used to be that if mysql_real_connect() failed, it would delete any
  options set by the client, unless the CLIENT_REMEMBER_OPTIONS flag was
  given.
  That behaviour does not appear very useful, and it seems unlikely that
  any applications would actually depend on this. So from MariaDB 5.5 we
  always preserve any options set in case of failed connect, and this
  option is effectively always set.
*/
#define CLIENT_REMEMBER_OPTIONS (1ULL << 31)



/* MariaDB extended capability flags */
#define MARIADB_CLIENT_FLAGS_MASK 0xffffffff00000000ULL
/* Client support progress indicator */
#define MARIADB_CLIENT_PROGRESS (1ULL << 32)
/* support COM_MULTI */
#define MARIADB_CLIENT_COM_MULTI (1ULL << 33)
/* support of array binding */
#define MARIADB_CLIENT_STMT_BULK_OPERATIONS (1ULL << 34)

#ifdef HAVE_COMPRESS
#define CAN_CLIENT_COMPRESS CLIENT_COMPRESS
#else
#define CAN_CLIENT_COMPRESS 0
#endif

// -----------------------------------------------------------------------------------


#define MI_AUTH_OLD     2
#define MI_AUTH_SWITCH  1
#define MI_AUTH_OK      0
#define MI_AUTH_ERROR  -1

// -----------------------------------------------------------------------------------


#define MI_BUF_PTR_OFFSET(o) ((o)->ptr - (o)->buf)


#define mdata_int64(x,v) (*((int64_t*)(x))
#define mdata_int32(x,v) (*((int32_t*)(x)))
#define mdata_int16(x,v) (*((int16_t*)(x)))
#define mdata_int8(x,v)  (*((int8_t*)(x)))

#define mdata_uint64(x) (*((uint64_t*)(x)))
#define mdata_uint32(x) (*((uint32_t*)(x)))
#define mdata_uint16(x) (*((uint16_t*)(x)))
#define mdata_uint8(x)  (*((uint8_t*)(x)))

#define mdata_uint24(A)    (uint32_t) (((uint32_t) ((uint8_t) ((A)[0]))) + \
                                       (((uint32_t) ((uint8_t) ((A)[1]))) << 8) + \
                                       (((uint32_t) ((uint8_t) ((A)[2]))) << 16))



// -----------------------------------------------------------------------------------

#define mput_uint16(T,A)	do { uint8_t *pT= (uint8_t*)(T);     \
                             *((uint16_t*)(pT))= (uint16_t) (A); \
                        } while (0)

#define mput_uint24(T,A)  do { *(T)=  (uint8_t) (A); \
        *((T)+1)=(uint8_t) ((uint32_t) (A) >> 8);                   \
        *((T)+2)=(uint8_t) ((uint32_t) (A) >> 16);                  \
     } while (0)

#define mput_uint32(T,A)	do { uint8_t *pT= (uint8_t*)(T);\
                             *((uint32_t *) (pT))= (uint32_t) (A); \
                        } while (0)

#define mput_uint40(T,A)  do { uint8_t *pT= (uint8_t*)(T);\
                             *((uint32_t *) (pT))= (uint32_t) (A); \
                             *((pT)+4)=(uint8_t) (((A) >> 32));\
                        } while (0)

#define mput_uint48(T,A)  do { uint8_t *pT= (uint8_t*)(T);\
                             *((uint32_t *) (pT))= (uint32_t) (A); \
                             *((uint16_t*)(pT+4))= (uint16_t) (A >> 32);\
                        } while (0)

#define mput_uint64(T,A)	do { uint8_t *pT= (uint8_t*)(T);\
                          *((uint64_t *) (pT))= (uint64_t) (A);              \
                        } while(0)


#define mput_int64(x) (*((int64_t*)(x)))
#define mput_int32(x) (*((int32_t*)(x)))
#define mput_int16(x) (*((int16_t*)(x)))
#define mput_int8(x)  (*((int8_t*)(x)))

// -----------------------------------------------------------------------------------

enum enum_server_command
{
  COM_SLEEP = 0,
  COM_QUIT,
  COM_INIT_DB,
  COM_QUERY,
  COM_FIELD_LIST,
  COM_CREATE_DB,
  COM_DROP_DB,
  COM_REFRESH,
  COM_SHUTDOWN,
  COM_STATISTICS,
  COM_PROCESS_INFO,
  COM_CONNECT,
  COM_PROCESS_KILL,
  COM_DEBUG,
  COM_PING,
  COM_TIME = 15,
  COM_DELAYED_INSERT,
  COM_CHANGE_USER,
  COM_BINLOG_DUMP,
  COM_TABLE_DUMP,
  COM_CONNECT_OUT = 20,
  COM_REGISTER_SLAVE,
  COM_STMT_PREPARE = 22,
  COM_STMT_EXECUTE = 23,
  COM_STMT_SEND_LONG_DATA = 24,
  COM_STMT_CLOSE = 25,
  COM_STMT_RESET = 26,
  COM_SET_OPTION = 27,
  COM_STMT_FETCH = 28,
  COM_DAEMON= 29,
  COM_UNSUPPORTED= 30,
  COM_RESET_CONNECTION = 31,
  COM_STMT_BULK_EXECUTE = 250,
  COM_MULTI = 254,
  COM_END
};

// -----------------------------------------------------------------------------------

enum enum_mi_state
    {
     MI_ST_NULL,             // 0
     MI_ST_READY,            // 1
     MI_ST_ERROR,            // 2
     MI_ST_EOF,              // 3
     MI_ST_COM_SENT,         // 4
     MI_ST_QUERY_SENT,       // 5
     MI_ST_QUERY_OK,         // 6
     MI_ST_QUERY_FIELDS,     // 7
     MI_ST_QUERY_FIELDS_EOF, // 8
     MI_ST_QUERY_RESULT,     // 9
     MI_ST_QUERY_ROWS,       // 11
     MI_ST_QUERY_ROWS_EOF,   // 12
     MI_ST_END               // 13
    };


// -----------------------------------------------------------------------------------


#define MIMYSQL_MAGIC     0x5379472
#define MIMYSQL_RES_MAGIC 0x5333123
#define MIMYSQL_ENV_MAGIC_V0 0x45563300


#define MYSQL_FLAGS_PLUGIN_AUTH

#define MI_LOG_NONE   0    /* weelll nothing */
#define MI_LOG_ERROR  1    /* connection must be ended/restarted */
#define MI_LOG_WARN   2    /* non critical error .. can use connection */
#define MI_LOG_INFO   3    /* info what is going */
#define MI_LOG_DEBUG  4    /* debugging */
#define MI_LOG_TRACE  5    /* tracing .. packets etc */


#define MIMYSQL_ENV_VERBOSE 0x00001

#define PACKET_OK   0x00
#define PACKET_EOF  0xfe
#define PACKET_ERR  0xff

#define MI_LENC_2      0xfb
#define MI_LENC_3      0xfc
#define MI_LENC_8      0xfd
#define MI_LENC_NULL   0xfe
#define MI_LENC_EOF    0xff

#define CMD_QUIT         0x01
#define CMD_QUERY        0x03
#define CMD_STATISTICS   0x09
#define CMD_PING         0x0e



enum enum_field_types { MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
                        MYSQL_TYPE_SHORT,  MYSQL_TYPE_LONG,
                        MYSQL_TYPE_FLOAT,  MYSQL_TYPE_DOUBLE,
                        MYSQL_TYPE_NULL,   MYSQL_TYPE_TIMESTAMP,
                        MYSQL_TYPE_LONGLONG,MYSQL_TYPE_INT24,
                        MYSQL_TYPE_DATE,   MYSQL_TYPE_TIME,
                        MYSQL_TYPE_DATETIME, MYSQL_TYPE_YEAR,
                        MYSQL_TYPE_NEWDATE, MYSQL_TYPE_VARCHAR,
                        MYSQL_TYPE_BIT,
                        /*
                          the following types are not used by client,
                          only for mysqlbinlog!!
                        */
                        MYSQL_TYPE_TIMESTAMP2,
                        MYSQL_TYPE_DATETIME2,
                        MYSQL_TYPE_TIME2,
                        /* --------------------------------------------- */
                        MYSQL_TYPE_JSON=245,
                        MYSQL_TYPE_NEWDECIMAL=246,
                        MYSQL_TYPE_ENUM=247,
                        MYSQL_TYPE_SET=248,
                        MYSQL_TYPE_TINY_BLOB=249,
                        MYSQL_TYPE_MEDIUM_BLOB=250,
                        MYSQL_TYPE_LONG_BLOB=251,
                        MYSQL_TYPE_BLOB=252,
                        MYSQL_TYPE_VAR_STRING=253,
                        MYSQL_TYPE_STRING=254,
                        MYSQL_TYPE_GEOMETRY=255,
                        MAX_NO_FIELD_TYPES };


struct st_mimysql_env;
struct st_mimysql_io;
struct st_mysql;

typedef struct st_mimysql_env MIMYSQL_ENV;
typedef struct st_mimysql_io  MIMYSQL_IO;
typedef struct st_mysql  MYSQL;
typedef struct st_mysql_field MYSQL_FIELD;

struct st_mimysql_env  {
  int magic;
  void  (*log)(MYSQL *mysql, int level, const char *fmt, ...);
  void* (*alloc)(size_t size);
  void* (*realloc)(void *ptr, size_t size);
  void (*free)(void *ptr);
  void (*sha1)(uint8_t *sha1, void *ptr, size_t length);
  MIMYSQL_IO* (*connect_unix) (MYSQL *m, const char *socket, int flags, int *errp);
  MIMYSQL_IO* (*connect_tcp) (MYSQL *m,char *host, int port, int flags, int *errp);
  size_t (*read)(MIMYSQL_IO *mio, void *ptr, size_t length, int *errp);
  size_t (*write)(MIMYSQL_IO *mio, void *ptr, size_t length, int *errp);
  void (*close)(MIMYSQL_IO *mio);


};



typedef struct st_mysql_field_offsets {
    size_t name_offset;
    size_t org_name_offset;
    size_t table_offset;
    size_t org_table_offset;
    size_t db_offset;
    size_t catalog_offset;
} MIMYSQL_FIELD_OFFSET;



struct st_mimysql_io {
    MIMYSQL_ENV *env;
    MYSQL *mysql;
    int fd;
    int connected;
};

typedef struct st_mi_buf {
    uint8_t *buf;    // start of buffer
    uint8_t *ptr;    // current/end position
    uint8_t *endp;   // end mark in readoing
    MIMYSQL_ENV *env;
} MI_BUF;


typedef struct st_mi_inbuf {
    uint8_t *readptr; // pointer to read position
    uint8_t *buffer;     // start of buffer
    uint8_t *endbuf;  // end o buffer
    uint8_t *packet_start;  // start of current packet
    uint8_t *packet_end;    // end of packet
    uint8_t *packet_data;   // start of data

    MIMYSQL_ENV *env;

    uint32_t packet_size;
    uint32_t buffer_length;

    uint64_t reads;
    uint64_t packets;
    uint64_t compacts;
    uint64_t reallocs;

    int      error;

    uint8_t  save;
    uint8_t  seq;
    uint8_t  allocated;




} MI_INBUF;


typedef struct st_mysql_res {
    MYSQL *m;
} MYSQL_RES;


struct st_mysql {
    MIMYSQL_ENV *env;
    MIMYSQL_IO *mio;
    void *envdata;
    int magic;
    const char *user;
    const char *host;
    const char *socket;
    const char *database;
    const char *password;
    int port;
    size_t  max_packet;
    const char *server_version;
    uint32_t connection_id;

    uint64_t server_caps;
    uint64_t client_caps;
    uint8_t protocol_version;
    uint8_t server_collation;
    uint8_t client_collation;
    uint8_t fields_parsed;
    uint8_t packet_type;
    uint8_t allocated;
    uint8_t connected;
    size_t  plugin_data_len;
    char   *auth_plugin_name;
    enum enum_mi_state state;
    MI_INBUF inbuf;
    MI_BUF outbuf;
    MI_BUF field_packet_buffer;
    MI_BUF field_data_buffer;
    MI_BUF field_buffer;
    MI_BUF auth_data;
    MI_BUF seed;
    MI_BUF info;

    char  *bufa;

    MYSQL_FIELD *fields;
    MIMYSQL_FIELD_OFFSET *field_offsets;
    uint32_t  field_count;
    int  field_index;
    int  max_fields;
    char **row_data;
    uint32_t *row_lengths;
    uint64_t row_count;
    int res_open;


    char *log_buffer;
    int log_buffer_size;
    uint32_t log_level;
    void (*log_func)(void *ptr, const char *logline);
    void *log_ptr;

    uint8_t sequence;

    /* reply vars */


    uint16_t error_code;
    uint16_t server_status;
    uint16_t warnings;
    uint64_t affected_rows;
    uint64_t last_insert_id;
    uint32_t errno;
    char sqlstate[6];
    char error_text[MYSQL_ERRMSG_SIZE+1];
    MYSQL_RES resp[1];
};


typedef char **MYSQL_ROW;



struct st_mysql_field {
    char *name;			/* Name of column */
    char *org_name;		/* Name of original column (added after 3.23.58) */
    char *table;			/* Table of column if column was a field */
    char *org_table;		/* Name of original table (added after 3.23.58 */
    char *db;                     /* table schema (added after 3.23.58) */
    char *catalog;                /* table catalog (added after 3.23.58) */
    char *def;			/* Default value (set by mysql_list_fields) */
    uint64_t length;		/* Width of column */
    uint64_t max_length;	/* Max width of selected set */
    uint32_t name_length;
    uint32_t org_name_length;
    uint32_t table_length;
    uint32_t org_table_length;
    uint32_t db_length;
    uint32_t catalog_length;
    uint32_t def_length;
    /***********************/
    uint32_t flags;		/* Div flags */
    uint32_t decimals;	/* Number of decimals in field */
    uint32_t charsetnr;       /* char set number (added in 4.1) */
    enum enum_field_types type;	/* Type of field. Se mysql_com.h for types */
    void *extension;              /* added in 4.1 */
};


#define LENC_OK         1
#define LENC_NULL       0
#define LENC_EOF       -1
#define LENC_OVERFLOW  -2
#define LENC_NO_DATA   -3


int mdata_lenc32(uint8_t **ptr, uint8_t *ep, uint32_t * result);
int mdata_lenc64(uint8_t **ptr, uint8_t *ep, uint64_t * result);


#define BAD_LENC32 (~((uint32_t)0))
#define BAD_LENC64 (~((uint64_t)0))

uint32_t get_lenc32(uint8_t **ptr, uint8_t *ep);
uint64_t get_lenc64(uint8_t **ptr, uint8_t *ep);


/**
 * --------------------------------------------------------------------------------
 * API
 * --------------------------------------------------------------------------------
 */


void mimysql_library_init(MIMYSQL_ENV *env);

MYSQL *mysql_init(MYSQL *mysql);
void mysql_close(MYSQL *mysql);

MYSQL *mysql_real_connect(MYSQL *mysql,
			  const char *host,
			  const char *user,
			  const char *password,
			  const char *db,
			  unsigned int port,
			  const char *unix_socket,
			  unsigned long flags);


int mysql_real_query(MYSQL *mi,  const char *query, unsigned long length);
int mysql_query(MYSQL *mi,  const char *query);



MYSQL_RES *mysql_use_result(MYSQL *mysql);

unsigned int mysql_num_fields(MYSQL_RES * );
MYSQL_FIELD * mysql_fetch_fields(MYSQL_RES * res);
MYSQL_FIELD * mysql_fetch_field_direct(MYSQL_RES * res,
                                       unsigned int fieldnr);

MYSQL_ROW mysql_fetch_row(MYSQL_RES *res);

unsigned long mysql_real_escape_string(MYSQL * mysql, char * to, const char * from, unsigned long);

void mysql_free_result(MYSQL_RES *result);

unsigned int mysql_field_count(MYSQL *m);
int mysql_ping(MYSQL *m);
const char * mysql_stat(MYSQL * mysql);
const char * mysql_info(MYSQL * mysql);
const char * mysql_error(MYSQL * mysql);
unsigned int mysql_affected_rows(MYSQL * mysql);
unsigned int mysql_warning_count(MYSQL *mysql);
int mysql_errno(MYSQL *mysql);


extern MIMYSQL_ENV *mimysql_default_env;




/*  custom api */

int mysql_set_auth_plugin_name(MYSQL *m, const char *plugin_name);

int mysql_prepare(MYSQL *mi,  const char *query, size_t length, ...);

const char *mysql_get_type_name(int type);
char *mysql_get_field_flags(char *to, int length, uint16_t flags);



#endif
