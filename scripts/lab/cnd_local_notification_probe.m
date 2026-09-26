#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#ifndef CND_NOTIFICATION_PROBE_OUTPUT_TOKEN
#define CND_NOTIFICATION_PROBE_OUTPUT_TOKEN ""
#endif

#ifndef CND_NOTIFICATION_PROBE_OUTPUT_PATH
#define CND_NOTIFICATION_PROBE_OUTPUT_PATH \
    "/var/tmp/cyanide-local-notification-probe.log"
#endif

#ifndef CND_NOTIFICATION_PROBE_NONCE
#define CND_NOTIFICATION_PROBE_NONCE "0"
#endif

static int gCNDNotificationProbeFD = -1;

static void CNDNotificationProbeLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDNotificationProbeLog(const char *format, ...)
{
    if (gCNDNotificationProbeFD < 0) return;
    char line[2048] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDNotificationProbeFD, line, amount);
    (void)fsync(gCNDNotificationProbeFD);
}

__attribute__((constructor))
static void CNDNotificationProbeStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_NOTIFICATION_PROBE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_NOTIFICATION_PROBE_OUTPUT_TOKEN) : -1;
        gCNDNotificationProbeFD = open(
            CND_NOTIFICATION_PROBE_OUTPUT_PATH,
            O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
        if (gCNDNotificationProbeFD < 0) return;
        CNDNotificationProbeLog(
            "[CND_NOTIFICATION_PROBE] START pid=%d token=%lld main=%d "
            "nonce=%s\n", getpid(), (long long)token,
            [NSThread isMainThread] ? 1 : 0, CND_NOTIFICATION_PROBE_NONCE);

        UNUserNotificationCenter *center =
            [UNUserNotificationCenter currentNotificationCenter];
        [center requestAuthorizationWithOptions:
            UNAuthorizationOptionAlert | UNAuthorizationOptionSound |
            UNAuthorizationOptionBadge
            completionHandler:^(BOOL granted, NSError *error) {
                CNDNotificationProbeLog(
                    "[CND_NOTIFICATION_PROBE] authorization granted=%d "
                    "error=%s\n", granted ? 1 : 0,
                    error.description.UTF8String ?: "-");
                if (!granted) return;
                UNMutableNotificationContent *content =
                    [[UNMutableNotificationContent alloc] init];
                content.title = @"Cyanide cache probe";
                content.body = @"Files notification icon refresh";
                content.sound = [UNNotificationSound defaultSound];
                UNTimeIntervalNotificationTrigger *trigger =
                    [UNTimeIntervalNotificationTrigger
                        triggerWithTimeInterval:5.0 repeats:NO];
                NSString *identifier = [NSString stringWithFormat:
                    @"com.cyanide.cache-probe.%llu",
                    (unsigned long long)(NSDate.date.timeIntervalSince1970 *
                                         1000.0)];
                UNNotificationRequest *request =
                    [UNNotificationRequest requestWithIdentifier:identifier
                                                         content:content
                                                         trigger:trigger];
                [center addNotificationRequest:request
                         withCompletionHandler:^(NSError *addError) {
                    CNDNotificationProbeLog(
                        "[CND_NOTIFICATION_PROBE] scheduled id=%s error=%s\n",
                        identifier.UTF8String,
                        addError.description.UTF8String ?: "-");
                }];
            }];
    }
}
