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

#include "fmacros.h"

#include "dns.h"

#ifdef USE_CARES
#include <ares.h>
#include <stdlib.h>
#include <string.h>

int valkeyDnsInit(void) {
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    return (status == ARES_SUCCESS) ? 0 : -1;
}

void valkeyDnsCleanup(void) {
    ares_library_cleanup();
}

/* Convert c-ares addrinfo results to standard struct addrinfo linked list.
 * This allows net.c to remain unchanged regardless of DNS backend. */
static struct addrinfo *caresNodeToAddrinfo(struct ares_addrinfo_node *node) {
    struct addrinfo *head = NULL, *tail = NULL;

    for (struct ares_addrinfo_node *n = node; n != NULL; n = n->ai_next) {
        struct addrinfo *ai = calloc(1, sizeof(*ai));
        if (ai == NULL)
            goto fail;

        ai->ai_family = n->ai_family;
        ai->ai_socktype = n->ai_socktype;
        ai->ai_protocol = n->ai_protocol;
        ai->ai_addrlen = n->ai_addrlen;
        ai->ai_addr = malloc(n->ai_addrlen);
        if (ai->ai_addr == NULL) {
            free(ai);
            goto fail;
        }
        memcpy(ai->ai_addr, n->ai_addr, n->ai_addrlen);
        ai->ai_next = NULL;

        if (tail == NULL) {
            head = tail = ai;
        } else {
            tail->ai_next = ai;
            tail = ai;
        }
    }
    return head;

fail:
    /* Free partially built list */
    while (head) {
        struct addrinfo *next = head->ai_next;
        free(head->ai_addr);
        free(head);
        head = next;
    }
    return NULL;
}

typedef struct {
    struct ares_addrinfo *result;
    int status;
    int done;
} caresResolveState;

static void caresAddrInfoCallback(void *arg, int status, int timeouts,
                                  struct ares_addrinfo *result) {
    caresResolveState *state = arg;
    (void)timeouts;
    state->status = status;
    state->result = result;
    state->done = 1;
}

int valkeyDnsResolve(const char *host, const char *port,
                     const struct addrinfo *hints, long timeout_msec,
                     struct addrinfo **result, const char **err_msg) {
    ares_channel channel;
    int r;

    r = ares_init(&channel);
    if (r != ARES_SUCCESS) {
        *err_msg = ares_strerror(r);
        return r;
    }

    struct ares_addrinfo_hints cares_hints = {0};
    cares_hints.ai_family = hints->ai_family;
    cares_hints.ai_socktype = hints->ai_socktype;
    cares_hints.ai_flags = hints->ai_flags;

    caresResolveState state = {0};
    ares_getaddrinfo(channel, host, port, &cares_hints,
                     caresAddrInfoCallback, &state);

    /* Poll on c-ares fds until resolution completes or timeout. */
    while (!state.done) {
        ares_socket_t socks[ARES_GETSOCK_MAXNUM];
        struct pollfd pfds[ARES_GETSOCK_MAXNUM];
        int bitmask = ares_getsock(channel, socks, ARES_GETSOCK_MAXNUM);
        int nfds = 0;

        for (int i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
            if (ARES_GETSOCK_READABLE(bitmask, i) ||
                ARES_GETSOCK_WRITABLE(bitmask, i)) {
                pfds[nfds].fd = socks[i];
                pfds[nfds].events = 0;
                pfds[nfds].revents = 0;
                if (ARES_GETSOCK_READABLE(bitmask, i))
                    pfds[nfds].events |= POLLIN;
                if (ARES_GETSOCK_WRITABLE(bitmask, i))
                    pfds[nfds].events |= POLLOUT;
                nfds++;
            }
        }

        if (nfds == 0)
            break;

        int poll_timeout = (timeout_msec > 0) ? (int)timeout_msec : 1000;
        r = poll(pfds, nfds, poll_timeout);
        if (r == 0 && timeout_msec > 0) {
            ares_cancel(channel);
            ares_destroy(channel);
            *err_msg = "DNS resolution timed out";
            return ARES_ETIMEOUT;
        }

        for (int i = 0; i < nfds; i++) {
            ares_socket_t rfd = (pfds[i].revents & POLLIN) ? pfds[i].fd : ARES_SOCKET_BAD;
            ares_socket_t wfd = (pfds[i].revents & POLLOUT) ? pfds[i].fd : ARES_SOCKET_BAD;
            ares_process_fd(channel, rfd, wfd);
        }
    }

    ares_destroy(channel);

    if (state.status != ARES_SUCCESS) {
        *err_msg = ares_strerror(state.status);
        if (state.result)
            ares_freeaddrinfo(state.result);
        return state.status;
    }

    /* Convert c-ares result to standard addrinfo */
    *result = caresNodeToAddrinfo(state.result->nodes);
    ares_freeaddrinfo(state.result);

    if (*result == NULL) {
        *err_msg = "Out of memory converting DNS results";
        return -1;
    }

    return 0;
}

void valkeyFreeDnsResult(struct addrinfo *result) {
    while (result) {
        struct addrinfo *next = result->ai_next;
        free(result->ai_addr);
        free(result);
        result = next;
    }
}

#else /* !USE_CARES — plain getaddrinfo backend */

int valkeyDnsInit(void) {
    return 0;
}

void valkeyDnsCleanup(void) {
}

int valkeyDnsResolve(const char *host, const char *port,
                     const struct addrinfo *hints, long timeout_msec,
                     struct addrinfo **result, const char **err_msg) {
    (void)timeout_msec; /* getaddrinfo has no timeout support */
    int rv = getaddrinfo(host, port, hints, result);
    if (rv != 0) {
        *err_msg = gai_strerror(rv);
    }
    return rv;
}

void valkeyFreeDnsResult(struct addrinfo *result) {
    if (result)
        freeaddrinfo(result);
}

#endif /* USE_CARES */
