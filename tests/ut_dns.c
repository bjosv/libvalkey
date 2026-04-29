/* Unit tests for the DNS resolution abstraction layer (dns.c).
 *
 * Tests valkeyDnsResolve() and valkeyFreeDnsResult() with both numeric
 * addresses (no real DNS needed) and guaranteed-failure domains. Works
 * identically with the getaddrinfo and c-ares backends.
 */

#include "fmacros.h"

#include "dns.h"
#include "sockcompat.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_resolve_numeric_ipv4(void) {
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    const char *err_msg = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    printf("Test: resolve numeric IPv4 address... ");
    int rv = valkeyDnsResolve("127.0.0.1", "6379", &hints, -1, &result, &err_msg);
    assert(rv == 0);
    assert(result != NULL);
    assert(result->ai_family == AF_INET);
    assert(result->ai_addrlen > 0);
    assert(result->ai_addr != NULL);
    valkeyFreeDnsResult(result);
    printf("PASS\n");
}

static void test_resolve_numeric_ipv6(void) {
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    const char *err_msg = NULL;

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    printf("Test: resolve numeric IPv6 address... ");
    int rv = valkeyDnsResolve("::1", "6379", &hints, -1, &result, &err_msg);
    assert(rv == 0);
    assert(result != NULL);
    assert(result->ai_family == AF_INET6);
    valkeyFreeDnsResult(result);
    printf("PASS\n");
}

static void test_resolve_failure(void) {
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    const char *err_msg = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    /* RFC 2606: .invalid is guaranteed to not resolve. */
    printf("Test: resolve nonexistent domain fails... ");
    int rv = valkeyDnsResolve("nonexistent.test.invalid", "6379", &hints, -1,
                              &result, &err_msg);
    assert(rv != 0);
    assert(err_msg != NULL);
    assert(strlen(err_msg) > 0);
    printf("PASS (err: %s)\n", err_msg);
}

static void test_free_null(void) {
    printf("Test: valkeyFreeDnsResult(NULL) is safe... ");
    valkeyFreeDnsResult(NULL);
    printf("PASS\n");
}

int main(void) {
    valkeyDnsInit();

    test_resolve_numeric_ipv4();
    test_resolve_numeric_ipv6();
    test_resolve_failure();
    test_free_null();

    valkeyDnsCleanup();
    return 0;
}
