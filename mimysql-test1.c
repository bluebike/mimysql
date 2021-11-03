/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mimysql.h"

#include "sha1.h"
#include "acutest.h"

uint64_t  alloc_counter = 0;
uint64_t  alloc_fail_counter = 0;
uint64_t  free_counter = 0;
uint64_t  realloc_counter = 0;
uint64_t  sha1_counter = 0;
uint64_t  read_counter = 0;
uint64_t  write_counter = 0;
uint64_t  close_counter = 0;

size_t fail_alloc = 0;

static void reset_counters() {
    alloc_counter = 0;
    alloc_fail_counter = 0;
    free_counter = 0;
    realloc_counter = 0;
    sha1_counter = 0;
    fail_alloc = 0;
}

static void* acutest_alloc(size_t size) {
    if(fail_alloc && size > fail_alloc) {
        alloc_fail_counter++;
        return NULL;
    }
    alloc_counter++;
    return calloc(size,1);
}

static void* acutest_realloc(void *old, size_t size) {
    return realloc(old, size);
}


static void acutest_free(void *ptr) {
    if(ptr != NULL) {
        free_counter++;
        free(ptr);
    }
}

static void acutest_sha1(uint8_t *sha1, void *ptr, size_t length) {
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, (unsigned char *) ptr, (uint32_t) length);
    SHA1Final(sha1, &context);
}

static MIMYSQL_IO* acutest_connect_unix(MIMYSQL_ENV *m, const char *socket_name, int flags, int *errp) {
    if(errp) { *errp = EINVAL; }    
    return NULL;
}
    

static MIMYSQL_IO* acutest_connect_tcp(MIMYSQL_ENV *m, const char *host, int port, int flags, int *errp) {
    if(errp) { *errp = EINVAL; }
    return NULL;
}

static size_t acutest_read(MIMYSQL_IO *mio, void *ptr, size_t length, int  *errp) {
    read_counter++;
    return 0;
}

static size_t acutest_write(MIMYSQL_IO *mio, void *ptr, size_t length, int *errp) {
    write_counter++;
    return -1;
}

static void acutest_close(MIMYSQL_IO *mio) {
    close_counter++;
}

static void  acutest_log(MIMYSQL_ENV *env, int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);    
    fprintf(stderr, "LOG: %d : ", level);
    vfprintf(stderr,fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}



MIMYSQL_ENV mimysql_test_env =  {
    .magic = MIMYSQL_ENV_MAGIC_V0,
    .log = acutest_log,
    .alloc = acutest_alloc,
    .realloc = acutest_realloc,
    .free = acutest_free,
    .sha1 = acutest_sha1,
    .connect_unix = acutest_connect_unix,
    .connect_tcp = acutest_connect_tcp,
    .read = acutest_read,
    .write = acutest_write,
    .close = acutest_close
};



void test_data(void)
{
    uint8_t arr[20] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    
    reset_counters();
    
    u16  = mdata_uint16(arr);
    TEST_CHECK_(u16 == 0x2301,  "uin16 %u == %u", u16, 0x2301);

    u32  = mdata_uint16(arr);
    TEST_CHECK_(u16 == 0x2301,  "uin16 %u == %u", u32, 0x2301);
    
    u32  = mdata_uint24(arr);
    TEST_CHECK(u32 == 0x452301);
    
    u32  = mdata_uint32(arr);
    TEST_CHECK(u32 == 0x67452301);
    
    u64  = mdata_uint64(arr);
    TEST_CHECK(u64 == 0xEFCDAB8967452301);
}

void test_lenc(void) {

    uint32_t u32;
    uint64_t u64;
    uint32_t v32;
    uint64_t v64;    
    uint8_t a[30];
    uint8_t *p;
    

    // ------------------------------------------------------    
    // some lenc32 (1 byte)
    
    a[0] = 00;
    
    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == 0);
    TEST_CHECK(p == a + 1);    
    
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+3) == 0);
    TEST_CHECK(p == a + 1);
    
    p = a;
    TEST_CHECK(get_lenc32(&p,p) == BAD_LENC32);    // zero length

    // ------------------------------------------------------
    // 10 as random value
    
    a[0] = 10;
    
    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == 10);
    TEST_CHECK(p == a + 1);    
    
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+3) == 10);
    TEST_CHECK(p == a + 1);
    
    p = a;
    TEST_CHECK(get_lenc32(&p,p) == BAD_LENC32);    // zero length

    // u32    
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_OK);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 10);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_OK);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 10);    
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);    // zero length

    // u64

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_OK);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 10);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_OK);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 10);    
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);    // zero length
    

    // ------------------------------------------------------
    // largets one byte

    a[0] = 0xfa;

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+1) == 0xFa);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+3) == 0xfa);
    TEST_CHECK(p == a + 1);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) == BAD_LENC32);


    // lenc32
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_OK);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0xfa);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_OK);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0xfa);    
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);    // zero length


    // lenc64

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_OK);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0xfa);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+20,&u64) == LENC_OK);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0xfa);    
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);    // zero length
    
    

    // ------------------------------------------------------
    // null char  (return bad every case with this get_lenc

    a[0] = 0xfb;  // NULL  

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);


    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NULL);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NULL);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);    
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);    // zero length
    TEST_CHECK(p == a);    
    TEST_CHECK(u32 == 0);        


    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NULL);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NULL);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);    // zero length




    // ------------------------------------------------------
    // eof char  (return bad every case with this get_lenc

    a[0] = 0xff;  // EOF

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);


    p = a;    
    TEST_CHECK(get_lenc64(&p,p) ==  BAD_LENC64);

    p = a;
    TEST_CHECK(get_lenc64(&p,p+1) == BAD_LENC64);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+2) == BAD_LENC64);
    

    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_EOF);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+2,&u32) == LENC_EOF);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);    
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);    // zero length
    TEST_CHECK(p == a);    
    TEST_CHECK(u32 == 0);        


    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_EOF);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+2,&u64) == LENC_EOF);    
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);    // zero length



    // ------------------------------------------------------
    // lenc  0xfc 0x01 0x02   short  (0x1234)

    a[0] = 0xfc;   // 1 + 2
    a[1] = 0x34;
    a[2] = 0x12;

    v32 = 0x1234;
    v64 = 0x1234;

    // get_lenc32 ( 1 + 2 )

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+3) == 0x1234);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+4) == 0x1234);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == 0x1234);
    TEST_CHECK(p == a + 3);


    // get_lenc64  ( 1 + 2 )

    p = a;    
    TEST_CHECK(get_lenc64(&p,p) ==  BAD_LENC64);

    p = a;
    TEST_CHECK(get_lenc64(&p,p+1) == BAD_LENC64);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+2) == BAD_LENC64);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+3) == 0x1234);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+4) == 0x1234);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == 0x1234);
    TEST_CHECK(p == a + 3);
        


    // mdata_lenc32 ( 1 + 2 )

    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);
    TEST_CHECK(u32 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NO_DATA);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+2,&u32) == LENC_NO_DATA);
    TEST_CHECK(u32 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+3,&u32) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u32 == 0x1234);    

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+4,&u32) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u32 == 0x1234);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+10,&u32) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u32 == 0x1234);


    // mdata_lenc64 ( 1 + 2 )

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 1);    
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+2,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+3,&u64) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u64 == v64);    

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+4,&u64) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u64 == v64);    

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+10,&u64) == LENC_OK);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u64 == v64);
    


    // ------------------------------------------------------
    // lenc  0xfd 0x56 0x34 0x12  ( 1 + 3 )   (0x123456)

    a[0] = 0xfd;   // 1 + 3
    a[1] = 0x56;
    a[2] = 0x34;    
    a[3] = 0x12;

    v32 = 0x123456;
    v64 = 0x123456;

    // get_lenc32 ( 1 + 3 )

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);
    
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+3) == BAD_LENC32);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+4) == 0x123456);
    TEST_CHECK(p == a + 4);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == 0x123456);
    TEST_CHECK(p == a + 4);


    // get_lenc64  ( 1 + 3 ) 

        p = a;    
    TEST_CHECK(get_lenc64(&p,p) ==  BAD_LENC64);
    TEST_CHECK(p == a);

    p = a;
    TEST_CHECK(get_lenc64(&p,p+1) == BAD_LENC64);
    TEST_CHECK(p == a + 1);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+2) == BAD_LENC64);
    TEST_CHECK(p == a + 2);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+3) == BAD_LENC64);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+4) == 0x123456);
    TEST_CHECK(p == a + 4);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == 0x123456);
    TEST_CHECK(p == a + 4);
        

    // mdata_lenc32 ( 1 + 3 )

    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a);    
    TEST_CHECK(u32 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a+1);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+2,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a+2);    
    TEST_CHECK(u32 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+3,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+4,&u32) == LENC_OK);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u32 == 0x123456);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+10,&u32) == LENC_OK);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u32 == 0x123456);
    

    // mdata_lenc64 ( 1 + 3 )

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+2,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 2);    
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+3,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 3);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+4,&u64) == LENC_OK);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u64 == 0x123456);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+5,&u64) == LENC_OK);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u64 == 0x123456);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+10,&u64) == LENC_OK);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u64 == 0x123456);


    // ------------------------------------------------------
    // lenc  0xfd 0x56 0x34 0x12  ( 1 + 8 )   (0x123456789ABCDEF0)

    a[0] = 0xfe;   // 1 + 9
    a[1] = 0x78;
    a[2] = 0x56;    
    a[3] = 0x34;
    a[4] = 0x12;
    a[5] = 0x00;    
    a[6] = 0x00;
    a[7] = 0x00;    
    a[8] = 0x00;

    v64 = 0x12345678;
    v32 = 0x12345678;

    // get_lenc32 ( 1 + 8 )

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);
    
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+7) == BAD_LENC32);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+8) == BAD_LENC32);
    
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+9) == v32);
    TEST_CHECK(p == a + 9);
        
    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == v32);
    TEST_CHECK(p == a + 9);


    // get_lenc64  ( 1 +  8)

    p = a;    
    TEST_CHECK(get_lenc64(&p,p) ==  BAD_LENC64);
    TEST_CHECK(p == a);
    

    p = a;
    TEST_CHECK(get_lenc64(&p,p+1) == BAD_LENC64);
    TEST_CHECK(p == a + 1);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+7) == BAD_LENC64);
    TEST_CHECK(p == a + 7);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+8) == BAD_LENC64);
    TEST_CHECK(p == a + 8);    

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+9) == v64);
    TEST_CHECK(p == a + 9);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+10) == v64);
    TEST_CHECK(p == a + 9);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+11) == v64);
    TEST_CHECK(p == a + 9);

    // mdata_lenc32 ( 1 +  8) small

    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a);
    TEST_CHECK(u32 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+7,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 7);
    TEST_CHECK(u32 == 0);    

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+8,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 8);
    TEST_CHECK(u32 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+9,&u32) == LENC_OK);
    TEST_CHECK(p == a + 9);    
    TEST_CHECK(u32 == v32);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+10,&u32) == LENC_OK);
    TEST_CHECK(p == a + 9);    
    TEST_CHECK(u32 == v32);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+11,&u32) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u32 == v32);
    

    // mdata_lenc64  ( 1 + 8) small

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+4,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 4);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+7,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 7);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+8,&u64) == LENC_NO_DATA);
    TEST_CHECK(p == a + 8);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+9,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+10,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+13,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);
    


    // ------------------------------------------------------
    // lenc   ( 1 + 8 )   (0x123456789ABCDEF0)  big valuve .. overflows u32

    a[0] = 0xfe;   // 1 + 8
    a[1] = 0xF0;
    a[2] = 0xDE;    
    a[3] = 0xBC;
    a[4] = 0x9A;
    a[5] = 0x78;    
    a[6] = 0x56;
    a[7] = 0x34;    
    a[8] = 0x12;

    v64 = 0x123456789ABCDEF0;
    v32 = 0x9ABCDEF0;

    // get_lenc32 ( 1 + 8 )

    p = a;    
    TEST_CHECK(get_lenc32(&p,p) ==  BAD_LENC32);
    TEST_CHECK(p == a);    

    p = a;
    TEST_CHECK(get_lenc32(&p,p+1) == BAD_LENC32);
    TEST_CHECK(p == a + 1);    

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+2) == BAD_LENC32);
    TEST_CHECK(p == a + 2);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+3) == BAD_LENC32);
    TEST_CHECK(p == a + 3);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+4) == BAD_LENC32);
    TEST_CHECK(p == a + 4);

    p = a;    
    TEST_CHECK(get_lenc32(&p,p+10) == BAD_LENC32);
    TEST_CHECK(p == a + 9);    


    // get_lenc64  ( 1 +  8)

        p = a;    
    TEST_CHECK(get_lenc64(&p,p) ==  BAD_LENC64);
    TEST_CHECK(p == a);

    p = a;
    TEST_CHECK(get_lenc64(&p,p+1) == BAD_LENC64);
    TEST_CHECK(p == a + 1);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+7) == BAD_LENC64);
    TEST_CHECK(p == a + 7);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+8) == BAD_LENC64);
    TEST_CHECK(p == a + 8);    

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+9) == v64);
    TEST_CHECK(p == a + 9);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+10) == v64);
    TEST_CHECK(p == a + 9);

    p = a;    
    TEST_CHECK(get_lenc64(&p,p+10) == v64);
    TEST_CHECK(p == a + 9);
        

    // mdata_lenc32 ( 1 +  8) big : overflow

    p = a;
    TEST_CHECK(mdata_lenc32(&p,p,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a);
    TEST_CHECK(u32 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc32(&p,p+1,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 1);
    TEST_CHECK(u32 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+7,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 7);   
    TEST_CHECK(u32 == 0);    

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+8,&u32) == LENC_NO_DATA);
    TEST_CHECK(p == a + 8);
    TEST_CHECK(u32 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+9,&u32) == LENC_OVERFLOW);
    TEST_CHECK(p == a + 9);
    TEST_CHECK_(u32 == v32, " ? %x = %x", u32, v32);    

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+10,&u32) == LENC_OVERFLOW);
    TEST_CHECK(p == a + 9);
    TEST_CHECK_(u32 == v32, " ? %x = %x", u32, v32);

    p = a;    
    TEST_CHECK(mdata_lenc32(&p,p+11,&u32) == LENC_OVERFLOW);
    TEST_CHECK(p == a + 9);
    TEST_CHECK_(u32 == v32, " ? %x = %x", u32, v32);

    // mdata_lenc64  ( 1 + 8 ) big

    p = a;
    TEST_CHECK(mdata_lenc64(&p,p,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);
    
    p = a;
    TEST_CHECK(mdata_lenc64(&p,p+1,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+4,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+7,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);
    
    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+8,&u64) == LENC_NO_DATA);
    TEST_CHECK(u64 == 0);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+9,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+10,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);

    p = a;    
    TEST_CHECK(mdata_lenc64(&p,p+13,&u64) == LENC_OK);
    TEST_CHECK(p == a + 9);
    TEST_CHECK(u64 == v64);
}


void test_mysql_init(void) {
    MYSQL *m;
    
    reset_counters();
    m = mysql_init(NULL);
    TEST_CHECK(m != NULL);
    mysql_close(m);
    TEST_CHECK_(alloc_counter == free_counter, "alloc_counter(%lld) == free_counter(%lld)", alloc_counter, free_counter);

}

    

MIMYSQL_ENV *mimysql_default_env = &mimysql_test_env;

TEST_LIST = {
             { "data", test_data },
             { "lenc", test_lenc },
             { "mysql_init", test_mysql_init },
             { NULL }
};

