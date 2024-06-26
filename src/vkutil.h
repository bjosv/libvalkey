/*
 * Copyright (c) 2015-2017, Ieshen Zheng <ieshen.zheng at 163 dot com>
 * Copyright (c) 2020, Nick <heronr1 at gmail dot com>
 * Copyright (c) 2020-2021, Bjorn Svensson <bjorn.a.svensson at est dot tech>
 * Copyright (c) 2020-2021, Viktor Söderqvist <viktor.soderqvist at est dot tech>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef VALKEY_VKUTIL_H
#define VALKEY_VKUTIL_H

#include <stdint.h>
#include <sys/types.h>

#define VK_ERROR -1
#define VK_EAGAIN -2

#define VK_INET4_ADDRSTRLEN (sizeof("255.255.255.255") - 1)
#define VK_INET6_ADDRSTRLEN                                                    \
    (sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1)
#define VK_INET_ADDRSTRLEN MAX(VK_INET4_ADDRSTRLEN, VK_INET6_ADDRSTRLEN)
#define VK_UNIX_ADDRSTRLEN                                                     \
    (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

#define VK_MAXHOSTNAMELEN 256

/*
 * Length of 1 byte, 2 bytes, 4 bytes, 8 bytes and largest integral
 * type (uintmax_t) in ascii, including the null terminator '\0'
 *
 * From stdint.h, we have:
 * # define UINT8_MAX   (255)
 * # define UINT16_MAX  (65535)
 * # define UINT32_MAX  (4294967295U)
 * # define UINT64_MAX  (__UINT64_C(18446744073709551615))
 */
#define VK_UINT8_MAXLEN (3 + 1)
#define VK_UINT16_MAXLEN (5 + 1)
#define VK_UINT32_MAXLEN (10 + 1)
#define VK_UINT64_MAXLEN (20 + 1)
#define VK_UINTMAX_MAXLEN VK_UINT64_MAXLEN

/*
 * Make data 'd' or pointer 'p', n-byte aligned, where n is a power of 2
 * of 2.
 */
#define VK_ALIGNMENT sizeof(unsigned long) /* platform word */
#define VK_ALIGN(d, n) (((d) + (n - 1)) & ~(n - 1))
#define VK_ALIGN_PTR(p, n)                                                     \
    (void *)(((uintptr_t)(p) + ((uintptr_t)n - 1)) & ~((uintptr_t)n - 1))

/*
 * Wrapper to workaround well known, safe, implicit type conversion when
 * invoking system calls.
 */
#define vk_gethostname(_name, _len) gethostname((char *)_name, (size_t)_len)

#define vk_atoi(_line, _n) _vk_atoi((uint8_t *)_line, (size_t)_n)
#define vk_itoa(_line, _n) _vk_itoa((uint8_t *)_line, (int)_n)

#define uint_len(_n) _uint_len((uint32_t)_n)

#ifndef _WIN32
int vk_set_blocking(int sd);
int vk_set_nonblocking(int sd);
int vk_set_reuseaddr(int sd);
int vk_set_tcpnodelay(int sd);
int vk_set_linger(int sd, int timeout);
int vk_set_sndbuf(int sd, int size);
int vk_set_rcvbuf(int sd, int size);
int vk_get_soerror(int sd);
int vk_get_sndbuf(int sd);
int vk_get_rcvbuf(int sd);
#endif

int _vk_atoi(uint8_t *line, size_t n);
void _vk_itoa(uint8_t *s, int num);

int vk_valid_port(int n);

int _uint_len(uint32_t num);

#ifndef _WIN32
/*
 * Wrappers to send or receive n byte message on a blocking
 * socket descriptor.
 */
#define vk_sendn(_s, _b, _n) _vk_sendn(_s, _b, (size_t)(_n))

#define vk_recvn(_s, _b, _n) _vk_recvn(_s, _b, (size_t)(_n))
#endif

/*
 * Wrappers to read or write data to/from (multiple) buffers
 * to a file or socket descriptor.
 */
#define vk_read(_d, _b, _n) read(_d, _b, (size_t)(_n))

#define vk_readv(_d, _b, _n) readv(_d, _b, (int)(_n))

#define vk_write(_d, _b, _n) write(_d, _b, (size_t)(_n))

#define vk_writev(_d, _b, _n) writev(_d, _b, (int)(_n))

#ifndef _WIN32
ssize_t _vk_sendn(int sd, const void *vptr, size_t n);
ssize_t _vk_recvn(int sd, void *vptr, size_t n);
#endif

/*
 * Wrappers for defining custom assert based on whether macro
 * VK_ASSERT_PANIC or VK_ASSERT_LOG was defined at the moment
 * ASSERT was called.
 */
#ifdef VK_ASSERT_PANIC

#define ASSERT(_x)                                                             \
    do {                                                                       \
        if (!(_x)) {                                                           \
            vk_assert(#_x, __FILE__, __LINE__, 1);                             \
        }                                                                      \
    } while (0)

#define NOT_REACHED() ASSERT(0)

#elif VK_ASSERT_LOG

#define ASSERT(_x)                                                             \
    do {                                                                       \
        if (!(_x)) {                                                           \
            vk_assert(#_x, __FILE__, __LINE__, 0);                             \
        }                                                                      \
    } while (0)

#define NOT_REACHED() ASSERT(0)

#else

#define ASSERT(_x)

#define NOT_REACHED()

#endif

void vk_assert(const char *cond, const char *file, int line, int panic);
void vk_stacktrace(int skip_count);
void vk_stacktrace_fd(int fd);

int64_t vk_usec_now(void);
int64_t vk_msec_now(void);

uint16_t crc16(const char *buf, int len);

#endif /* VALKEY_VKUTIL_H */
