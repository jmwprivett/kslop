#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <xpc/xpc.h>

int main(int argc, char **argv)
{
    unsigned seconds = 45U;
    if (argc == 2) {
        unsigned long parsed = strtoul(argv[1], NULL, 10);
        if (parsed >= 5UL && parsed <= 120UL) seconds = (unsigned)parsed;
    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [seconds]\n", argv[0]);
        return 64;
    }

    typedef xpc_connection_t (*CreateMachService)(
        const char *, dispatch_queue_t, uint64_t);
    CreateMachService create = (CreateMachService)dlsym(
        RTLD_DEFAULT, "xpc_connection_create_mach_service");
    xpc_connection_t connection = create ? create(
        "com.apple.iconservices", dispatch_get_global_queue(
            QOS_CLASS_USER_INITIATED, 0), 0) : NULL;
    if (!connection) {
        fprintf(stderr, "could not create com.apple.iconservices connection\n");
        return 1;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);

    printf("CND_ICON_HOLD_READY pid=%d seconds=%u\n", getpid(), seconds);
    fflush(stdout);
    for (unsigned elapsed = 0; elapsed < seconds; elapsed++) {
        if (elapsed % 5U == 0U) {
            xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
            xpc_connection_send_message(connection, message);
            xpc_release(message);
        }
        sleep(1);
    }
    xpc_connection_cancel(connection);
    xpc_release(connection);
    return 0;
}
