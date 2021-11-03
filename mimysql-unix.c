/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "mimysql.h"
#include "sha1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>
#include <netdb.h>
#include <assert.h>



extern MIMYSQL_ENV mimysql_unix_env;

static void* unix_alloc(size_t size) {
    return calloc(size,1);
}

static void* unix_realloc(void *old, size_t size) {
    return realloc(old, size);
}


static void unix_free(void *ptr) {
    if(ptr != NULL) {
        free(ptr);
    }
}

static void unix_sha1(uint8_t *sha1, void *ptr, size_t length) {
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, (unsigned char *) ptr, (uint32_t) length);
    SHA1Final(sha1, &context);
}

static MIMYSQL_IO* unix_connect_unix(MIMYSQL_ENV *env, const char *socket_name, int flags, int *errp) {
    MIMYSQL_IO *mio;
    int fd;
    int name_len;
	struct sockaddr_un uaddr;
    *errp = 0;
    name_len = strlen(socket_name);
    if(name_len <= 0 || name_len > 100) {
        // m->env->log(m, MIMYSQL_LOG_ERROR,"socket name too long: %d\n", name_len);
        *errp =  EINVAL;
        return NULL;
    }

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        // m->env->log(m, MIMYSQL_LOG_ERROR,"cannot make socket : %s", strerror(errno));
        *errp = errno;
        return NULL;
    }


    memset(&uaddr, 0, sizeof(uaddr));
    uaddr.sun_family = AF_UNIX;
    strcpy(uaddr.sun_path, socket_name);

    if(connect(fd, (struct sockaddr *) &uaddr, sizeof(uaddr)) < 0) {
        // m->env->log(m, MIMYSQL_LOG_ERROR,"connect to unix socket: '%s' : %s", socket_name, strerror(errno));
        *errp = errno;
        return NULL;
    }

    mio = calloc(sizeof(MIMYSQL_IO), 1);
    if(mio == NULL) {
        // m->env->log(m, MIMYSQL_LOG_ERROR,"cannot allocate MIMYSQL_IO: %s", strerror(errno));
        *errp = errno;
        return NULL;
    }
    mio->mio_magic = MIMYSQL_MIO_MAGIC_V0;
    mio->fd = fd;
    mio->env = env;
    mio->connected = 1;
    return mio;
};


static MIMYSQL_IO* unix_connect_tcp(MIMYSQL_ENV *env, const char *host, int port, int flags, int *errp) {
    MIMYSQL_IO *mio;
    int fd;
    struct hostent *hp;
    struct sockaddr_in addr;

    *errp = 0;
    // get addres

    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    if(!host) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if(!inet_aton(host, &addr.sin_addr)) {
        hp = gethostbyname(host);
        if(!hp) {
            *errp = HOST_NOT_FOUND;
            return NULL;
        }
        addr.sin_addr = *((struct in_addr *) hp->h_addr);
    }

    // get port for address

    if((port <= 0) || (port > 0xffff)) {
        port = 3306;
    }

    addr.sin_port = htons(port);


    // socket

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
        *errp = errno;
        return NULL;
    }

    if(connect(fd, (struct sockaddr *) &addr, sizeof(addr))) {
        *errp = errno;
        close(fd);
        return NULL;
    }

    mio = calloc(sizeof(*mio), 1);
    if(mio == NULL) {
        *errp = errno;
        close(fd);
        // env->log(m, MIMYSQL_LOG_ERROR,"cannot allocate MIMYSQL_IO: %s", strerror(errno));
        return NULL;
    }
    
    mio->mio_magic = MIMYSQL_MIO_MAGIC_V0;    
    mio->fd = fd;
    mio->env = env;
    mio->connected = 1;
    mio->userptr = NULL;
    
    return mio;
}

static size_t unix_read(MIMYSQL_IO *mio, void *ptr, size_t length, int  *errp) {
    assert(mio->mio_magic == MIMYSQL_MIO_MAGIC_V0);
    int ret = read(mio->fd, ptr, length);
    if(ret < 0) {
        // m->env->log(m,MIMYSQL_LOG_ERROR,"cannot read socket : %s", strerror(errno));
        *errp = errno;
        return -1;
    }
    return ret;
}

static size_t unix_write(MIMYSQL_IO *mio, void *ptr, size_t length, int *errp) {
    assert(mio->mio_magic == MIMYSQL_MIO_MAGIC_V0);    
    int ret = write(mio->fd, ptr, length);
    if(ret < 0) {
        // m->env->log(m,MIMYSQL_LOG_ERROR,"cannot write socket : %s", strerror(errno));
        *errp = errno;
        return -1;
    }
    return ret;
}

static void unix_close(MIMYSQL_IO *mio) {
    assert(mio->mio_magic == MIMYSQL_MIO_MAGIC_V0);    
    if(mio->fd >= 0) {
        close(mio->fd);
        mio->fd = -1;
        mio->connected = 0;
        free(mio);
    }
}

static void  unix_log(MIMYSQL_ENV *m, int level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "LOG: %d : ", level);
    vfprintf(stderr,fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

MIMYSQL_ENV mimysql_unix_env =  {
    .magic = MIMYSQL_ENV_MAGIC_V0,
    .log = unix_log,
    .alloc = unix_alloc,
    .realloc = unix_realloc,
    .free = unix_free,
    .sha1 = unix_sha1,
    .connect_unix = unix_connect_unix,
    .connect_tcp = unix_connect_tcp,
    .read = unix_read,
    .write = unix_write,
    .close = unix_close
};


MIMYSQL_ENV *mimysql_default_env = &mimysql_unix_env;;
