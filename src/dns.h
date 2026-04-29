/*
 * Copyright (c) 2026, the libvalkey contributors
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
 *   * Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
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

#ifndef VALKEY_DNS_H
#define VALKEY_DNS_H

#include "fmacros.h"

#include "sockcompat.h"

/**
 * Resolve a hostname to a list of addrinfo results.
 *
 * @param host     Hostname or IP address to resolve.
 * @param port     Port number as a string (e.g. "6379"), or NULL.
 * @param hints    Standard addrinfo hints (ai_family, ai_socktype, etc.).
 * @param timeout_msec  Timeout in milliseconds (-1 for no timeout).
 *                      Only used with c-ares; ignored for plain getaddrinfo.
 * @param result   Output: linked list of addrinfo results. Caller must free
 *                 with valkeyFreeDnsResult().
 * @param err_msg  Output: on failure, points to a static error string.
 *
 * @return 0 on success, non-zero on failure.
 */
int valkeyDnsResolve(const char *host, const char *port,
                     const struct addrinfo *hints, long timeout_msec,
                     struct addrinfo **result, const char **err_msg);

/**
 * Free the result returned by valkeyDnsResolve().
 */
void valkeyFreeDnsResult(struct addrinfo *result);

/**
 * Initialize the DNS subsystem. Called once during library init.
 * Returns 0 on success, non-zero on failure.
 */
int valkeyDnsInit(void);

/**
 * Clean up the DNS subsystem.
 */
void valkeyDnsCleanup(void);

#endif /* VALKEY_DNS_H */
