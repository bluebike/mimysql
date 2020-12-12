/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/**
 * mimysql-common.c 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <math.h>

#include "mimysql.h"



char *mi_hex_string(MIMYSQL_ENV *env, uint8_t *data, size_t len) {
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

char *mi_hex_string_buf(MIMYSQL_ENV *env, MI_BUF *bu) {
    return mi_hex_string(env, bu->buf, bu->ptr - bu->buf);
}

uint8_t *mi_find_string_end(uint8_t *p, uint8_t *e) {
    while(p < e) {
        if(!*p) {
            return p;
        }
        p++;
    }
    return NULL;
}



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

char * mi_int2str10(char *buf, int64_t d) {
    char *p;
    int neg = 0;
    if(d < 0) {
      // if(d == -9223372036854775808L) {  // 0x8000000000000000
      if(d == 0x8000000000000000) { 
            strcpy(buf,"-9223372036854775808");
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
        if(d == 0x8000000000000000) {       
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
    va_list ap;
    int d;
    char *s;
    int start_size;

    va_start(ap,fmt);
    p = (char *) fmt;
    mark = p;
    eot = 0;

    start_size = mi_buf_size(o);


    while((ch = *p) && !eot)  {
        if(ch != '%') {
            p++;
            continue;
        }
        if(p > mark) {
            mi_buf_add_data(o,(uint8_t*)mark,p-mark);
        }
        num = done = op = zero = neg = space = l = 0;
        ch = *p++;

        switch(ch) {
        case '-':
            neg = 1;
            p++;
            break;

        case '0':
            zero = 1;
            p++;
            break;
        default:
            break;
        }

        do {
            switch(ch) {
            case 0:
                mi_buf_add_uint8(o,'%');
                eot = 1;
                done = 1;
                break;
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
                mi_buf_add_uint8(o,'%');
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
            case 'i':                
            case 'd':
                d = va_arg(ap, int);
                mi_int2str10(apu,d);
                mi_buf_add_str(o,apu,strlen(apu));
                done = 1;
                break;
            case 's':
                s = va_arg(ap, char *);
                if(s) {
                    mi_buf_add_str(o,s,strlen(s));
                } 
                done = 1;                
                break;
                
            }
        } while(!done && !eot);
        
        mark = p;
    }
    if(p > mark) {
        mi_buf_add_data(o,(uint8_t*)mark,p-mark);
    }
    return mi_buf_size(o) - start_size;
}




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



