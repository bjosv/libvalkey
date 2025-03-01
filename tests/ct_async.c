#include "adapters/libevent.h"
#include "cluster.h"
#include "test_utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define CLUSTER_NODE "127.0.0.1:7000"

void getCallback(valkeyClusterAsyncContext *acc, void *r, void *privdata) {
    UNUSED(privdata);
    valkeyReply *reply = (valkeyReply *)r;
    ASSERT_MSG(reply != NULL, acc->errstr);

    /* Disconnect after receiving the first reply to GET */
    valkeyClusterAsyncDisconnect(acc);
}

void setCallback(valkeyClusterAsyncContext *acc, void *r, void *privdata) {
    UNUSED(privdata);
    valkeyReply *reply = (valkeyReply *)r;
    ASSERT_MSG(reply != NULL, acc->errstr);
}

void connectCallback(valkeyAsyncContext *ac, int status) {
    ASSERT_MSG(status == VALKEY_OK, ac->errstr);
    printf("Connected to %s:%d\n", ac->c.tcp.host, ac->c.tcp.port);
}

void disconnectCallback(const valkeyAsyncContext *ac, int status) {
    ASSERT_MSG(status == VALKEY_OK, ac->errstr);
    printf("Disconnected from %s:%d\n", ac->c.tcp.host, ac->c.tcp.port);
}

void eventCallback(const valkeyClusterContext *cc, int event, void *privdata) {
    (void)cc;
    valkeyClusterAsyncContext *acc = (valkeyClusterAsyncContext *)privdata;

    /* We send our commands when the client is ready to accept commands. */
    if (event == VALKEYCLUSTER_EVENT_READY) {
        int status;
        status = valkeyClusterAsyncCommand(acc, setCallback, (char *)"ID",
                                           "SET key12345 value");
        ASSERT_MSG(status == VALKEY_OK, acc->errstr);

        /* This command will trigger a disconnect in its reply callback. */
        status = valkeyClusterAsyncCommand(acc, getCallback, (char *)"ID",
                                           "GET key12345");
        ASSERT_MSG(status == VALKEY_OK, acc->errstr);

        status = valkeyClusterAsyncCommand(acc, setCallback, (char *)"ID",
                                           "SET key23456 value2");
        ASSERT_MSG(status == VALKEY_OK, acc->errstr);

        status = valkeyClusterAsyncCommand(acc, getCallback, (char *)"ID",
                                           "GET key23456");
        ASSERT_MSG(status == VALKEY_OK, acc->errstr);
    }
}

int main(void) {
    struct event_base *base = event_base_new();

    valkeyClusterOptions options = {0};
    options.initial_nodes = CLUSTER_NODE;
    options.async_connect_callback = connectCallback;
    options.async_disconnect_callback = disconnectCallback;
    valkeyClusterOptionsUseLibevent(&options, base);

    valkeyClusterAsyncContext *acc = valkeyClusterAsyncContextInit(&options);
    assert(acc);

    /* Set an event callback that uses acc as privdata */
    int status = valkeyClusterAsyncSetEventCallback(acc, eventCallback, acc);
    assert(status == VALKEY_OK);

    status = valkeyClusterAsyncConnect(acc);
    assert(status == VALKEY_OK);

    event_base_dispatch(base);

    valkeyClusterAsyncFree(acc);
    event_base_free(base);
    return 0;
}
