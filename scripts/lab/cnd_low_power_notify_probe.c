#include <notify.h>
#include <objc/message.h>
#include <objc/runtime.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *const kCNDLowPowerNotification =
    "com.apple.system.lowpowermode";

static int CNDProcessInfoLowPowerModeEnabled(void)
{
    Class processInfoClass = objc_getClass("NSProcessInfo");
    id processInfo = processInfoClass
        ? ((id (*)(id, SEL))objc_msgSend)(
              (id)processInfoClass, sel_registerName("processInfo"))
        : nil;
    return processInfo
        ? ((BOOL (*)(id, SEL))objc_msgSend)(
              processInfo, sel_registerName("isLowPowerModeEnabled"))
        : -1;
}

static int CNDReadState(int token, uint64_t *state)
{
    uint32_t status = notify_get_state(token, state);
    if (status != NOTIFY_STATUS_OK) {
        fprintf(stderr, "notify_get_state status=%u\n", status);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "usage: %s read | set 0|1 | set-no-post 0|1\n",
                argv[0]);
        return 64;
    }

    int token = 0;
    uint32_t status = notify_register_check(kCNDLowPowerNotification, &token);
    if (status != NOTIFY_STATUS_OK) {
        fprintf(stderr, "notify_register_check status=%u\n", status);
        return 1;
    }

    uint64_t before = 0;
    if (CNDReadState(token, &before) != 0) {
        (void)notify_cancel(token);
        return 1;
    }
    printf("name=%s before=%" PRIu64 "\n", kCNDLowPowerNotification,
           before);
    printf("process-info-low-power=%d\n",
           CNDProcessInfoLowPowerModeEnabled());

    if (strcmp(argv[1], "read") == 0 && argc == 2) {
        (void)notify_cancel(token);
        return 0;
    }
    int shouldPost = strcmp(argv[1], "set") == 0;
    int shouldSetWithoutPost = strcmp(argv[1], "set-no-post") == 0;
    if ((!shouldPost && !shouldSetWithoutPost) || argc != 3 ||
        (strcmp(argv[2], "0") != 0 && strcmp(argv[2], "1") != 0)) {
        fprintf(stderr, "usage: %s read | set 0|1 | set-no-post 0|1\n",
                argv[0]);
        (void)notify_cancel(token);
        return 64;
    }

    uint64_t requested = (uint64_t)(argv[2][0] - '0');
    status = notify_set_state(token, requested);
    printf("set=%" PRIu64 " status=%u\n", requested, status);
    if (status != NOTIFY_STATUS_OK) {
        (void)notify_cancel(token);
        return 1;
    }

    if (shouldPost) {
        status = notify_post(kCNDLowPowerNotification);
        printf("post-status=%u\n", status);
        if (status != NOTIFY_STATUS_OK) {
            (void)notify_cancel(token);
            return 1;
        }
    } else {
        printf("post-skipped=1\n");
    }

    uint64_t after = 0;
    int result = CNDReadState(token, &after);
    if (result == 0) printf("after=%" PRIu64 "\n", after);
    (void)notify_cancel(token);
    return result;
}
