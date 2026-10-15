#import <Foundation/Foundation.h>

#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

#import "vphoned_install.h"

static BOOL CNDIsVPhoneGuest(void)
{
    char model[128] = {0};
    size_t size = sizeof(model);
    return sysctlbyname("hw.model", model, &size, NULL, 0) == 0 &&
        strncmp(model, "VPHONE", strlen("VPHONE")) == 0;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2 || !CNDIsVPhoneGuest()) {
            fprintf(stderr,
                "usage: cnd-vphone-builtin-install "
                "/var/mobile/Documents/vphone-installs/<package>.ipa\n");
            return 64;
        }

        NSString *path = [NSString stringWithUTF8String:argv[1]];
        NSString *standardPath = path.stringByStandardizingPath;
        NSString *installRoot =
            @"/var/mobile/Documents/vphone-installs/";
        if (![standardPath hasPrefix:installRoot] ||
            ![standardPath.pathExtension.lowercaseString isEqualToString:
                @"ipa"] ||
            ![[NSFileManager defaultManager] fileExistsAtPath:standardPath]) {
            fprintf(stderr, "refusing package path outside the VM install root\n");
            return 65;
        }

        NSDictionary *response = vp_handle_custom_install(@{
            @"id": @"cnd-lab-installer",
            @"path": standardPath,
            @"registration": @"User",
        });
        NSData *json = [NSJSONSerialization dataWithJSONObject:response
            options:NSJSONWritingSortedKeys error:nil];
        if (json) {
            fwrite(json.bytes, 1, json.length, stdout);
            fputc('\n', stdout);
        }
        return [response[@"t"] isEqualToString:@"ok"] ? 0 : 1;
    }
}
