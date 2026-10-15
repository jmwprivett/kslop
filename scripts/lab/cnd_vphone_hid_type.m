#import <Foundation/Foundation.h>

#import "../../../vphone-cli-1.0.13/scripts/vphoned/vphoned_hid.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static BOOL CNDParseUInt32(const char *text, uint32_t *valueOut)
{
    if (!text || !text[0] || !valueOut) return NO;
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 0);
    if (errno != 0 || !end || end == text || *end != '\0' || value > UINT32_MAX) {
        return NO;
    }
    *valueOut = (uint32_t)value;
    return YES;
}

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
        if (argc == 4 && !strcmp(argv[1], "--press")) {
            uint32_t page = 0;
            uint32_t usage = 0;
            if (!CNDParseUInt32(argv[2], &page) ||
                !CNDParseUInt32(argv[3], &usage) ||
                !vp_hid_load()) {
                return 1;
            }
            vp_hid_press(page, usage);
            usleep(500000);
            return 0;
        }
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
