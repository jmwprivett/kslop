#import "CNDLabThreadCallPACBoundary.h"

#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Standalone vPhone entry point for the existing reversible PM/M68 dispatch.
 * Set CFFIXED_USER_HOME to the lab app's current data container so the
 * VM-only provider resolves that container's authenticated Unix socket.
 */
uint64_t g_kernel_base;
uint64_t g_kernel_slide;

/* CNDLabKernelProvider mirrors diagnostics into the UIKit log in-app. */
void log_write(const char *message)
{
    (void)message;
}

int main(void)
{
    @autoreleasepool {
        NSString *home = NSHomeDirectory();
        if (home.length == 0) {
            fprintf(stderr, "unable to resolve the provider container\n");
            return 64;
        }

        CNDLabThreadCallPACBoundaryRunPMM68Dispatch(
            ^(NSDictionary<NSString *, id> *report) {
                NSError *error = nil;
                NSData *data = [NSJSONSerialization dataWithJSONObject:
                    report ?: @{} options:NSJSONWritingSortedKeys
                    error:&error];
                if (data.length != 0) {
                    fwrite(data.bytes, 1, data.length, stdout);
                    fputc('\n', stdout);
                    fflush(stdout);
                } else {
                    fprintf(stderr, "report serialization failed: %s\n",
                        error.localizedDescription.UTF8String ?: "unknown");
                    fflush(stderr);
                }
                BOOL success =
                    [report[@"exactPMM68Dispatch"] boolValue] &&
                    [report[@"exactTargetDriver"] boolValue] &&
                    [report[@"stagedExactly"] boolValue] &&
                    [report[@"pmCompletionObserved"] boolValue] &&
                    [report[@"controllingDriverRestored"] boolValue] &&
                    [report[@"powerStateRestored"] boolValue] &&
                    [report[@"pmStateRestored"] boolValue] &&
                    [report[@"timerFieldsRestored"] boolValue] &&
                    [report[@"timerDestroyed"] boolValue] &&
                    ![report[@"usedKernelCall"] boolValue];
                _exit(success ? 0 : 1);
            });
        dispatch_main();
    }
}
