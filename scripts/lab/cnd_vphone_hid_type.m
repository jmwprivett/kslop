#import <Foundation/Foundation.h>

#import "../../../vphone-cli-1.0.13/scripts/vphoned/vphoned_hid.h"

#include <string.h>

static uint32_t CNDHIDUsage(unichar character)
{
    if (character >= 'a' && character <= 'z') {
        return 0x04U + (uint32_t)(character - 'a');
    }
    if (character >= 'A' && character <= 'Z') {
        return 0x04U + (uint32_t)(character - 'A');
    }
    if (character == ' ') return 0x2cU;
    return 0;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2 || !vp_hid_load()) return 1;
        if (!strcmp(argv[1], "--paste")) {
            vp_hid_key(0x07U, 0xe3U, YES);
            vp_hid_press(0x07U, 0x19U);
            vp_hid_key(0x07U, 0xe3U, NO);
            usleep(500000);
            return 0;
        }
        NSString *text = [NSString stringWithUTF8String:argv[1]];
        /* Clear a short existing query without relying on selection state. */
        for (unsigned index = 0; index < 32U; index++) {
            vp_hid_press(0x07U, 0x2aU);
        }
        for (NSUInteger index = 0; index < text.length; index++) {
            unichar character = [text characterAtIndex:index];
            uint32_t usage = CNDHIDUsage(character);
            if (!usage) continue;
            BOOL uppercase = character >= 'A' && character <= 'Z';
            if (uppercase) vp_hid_key(0x07U, 0xe1U, YES);
            vp_hid_press(0x07U, usage);
            if (uppercase) vp_hid_key(0x07U, 0xe1U, NO);
        }
        usleep(500000);
    }
    return 0;
}
