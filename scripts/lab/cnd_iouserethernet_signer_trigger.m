#import <Foundation/Foundation.h>

#import <IOKit/IOCFSerialize.h>
#import <IOKit/IOKitLib.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Create one entitlement-gated IOUserEthernet controller through selector 0.
 * The controller owns a fresh IOUserEthernetInterface, giving the lab a normal
 * IOKit path through IONetworkInterface::attachToDataLinkLayer and the
 * IOEthernetInterface::initIfnetParams PAC signer.  This program performs no
 * kernel read, write, or call and deliberately avoids the historical
 * IOUserEthernet statistics selectors.
 */

static NSString *CNDHex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%016llx", value];
}

static NSArray<NSDictionary<NSString *, id> *> *CNDInterfaces(void)
{
    NSMutableArray<NSDictionary<NSString *, id> *> *result =
        [NSMutableArray array];
    CFMutableDictionaryRef matching =
        IOServiceMatching("IOUserEthernetInterface");
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = matching != NULL
        ? IOServiceGetMatchingServices(MACH_PORT_NULL, matching, &iterator)
        : KERN_RESOURCE_SHORTAGE;
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(iterator)) {
        return result;
    }

    for (;;) {
        io_service_t service = IOIteratorNext(iterator);
        if (!MACH_PORT_VALID(service)) break;
        uint64_t registryID = 0;
        (void)IORegistryEntryGetRegistryEntryID(service, &registryID);
        CFTypeRef bsdName = IORegistryEntryCreateCFProperty(
            service, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        io_string_t path = {0};
        kern_return_t pathKR = IORegistryEntryGetPath(
            service, kIOServicePlane, path);
        NSMutableDictionary<NSString *, id> *entry =
            [NSMutableDictionary dictionaryWithDictionary:@{
                @"registryID": CNDHex(registryID),
                @"path": pathKR == KERN_SUCCESS
                    ? [NSString stringWithUTF8String:path] : @"",
            }];
        if (bsdName != NULL) {
            if (CFGetTypeID(bsdName) == CFStringGetTypeID()) {
                entry[@"bsdName"] = (__bridge NSString *)bsdName;
            }
            CFRelease(bsdName);
        }
        [result addObject:entry];
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    return result;
}

static int CNDParseHoldSeconds(int argc, const char *argv[])
{
    if (argc == 1) return 0;
    if (argc != 3 || strcmp(argv[1], "--hold") != 0) return -1;
    char *end = NULL;
    errno = 0;
    long value = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' ||
        value < 0 || value > 300) {
        return -1;
    }
    return (int)value;
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        int holdSeconds = CNDParseHoldSeconds(argc, argv);
        if (holdSeconds < 0) {
            fprintf(stderr, "usage: cnd_iouserethernet_signer_trigger "
                "[--hold SECONDS]\n");
            return 64;
        }

        NSArray *before = CNDInterfaces();
        io_service_t resource = IOServiceGetMatchingService(
            MACH_PORT_NULL, IOServiceMatching("IOUserEthernetResource"));
        io_connect_t connection = IO_OBJECT_NULL;
        kern_return_t openKR = MACH_PORT_VALID(resource)
            ? IOServiceOpen(resource, mach_task_self(), 0, &connection)
            : KERN_NOT_FOUND;
        if (MACH_PORT_VALID(resource)) IOObjectRelease(resource);

        kern_return_t callKR = KERN_FAILURE;
        uint64_t controllerCookie = 0;
        uint32_t scalarOutputCount = 1;
        CFDataRef serialized = NULL;
        if (openKR == KERN_SUCCESS && MACH_PORT_VALID(connection)) {
            const uint8_t mac[6] = {0x02, 0xc0, 0xde, 0x26, 0x00, 0x01};
            NSDictionary *properties = @{
                @"HardwareAddress": [NSData dataWithBytes:mac length:6],
                @"MinPacketSize": @64,
                @"MaxPacketSize": @1514,
                @"MaxTransferUnit": @1500,
                @"NamePrefix": @"cnd",
            };
            serialized = IOCFSerialize(
                (__bridge CFTypeRef)properties, kIOCFSerializeToBinary);
            if (serialized != NULL) {
                callKR = IOConnectCallMethod(
                    connection, 0, NULL, 0,
                    CFDataGetBytePtr(serialized),
                    (size_t)CFDataGetLength(serialized),
                    &controllerCookie, &scalarOutputCount,
                    NULL, NULL);
            }
        }

        if (callKR == KERN_SUCCESS) usleep(250000);
        NSArray *after = CNDInterfaces();
        NSMutableSet<NSString *> *beforeIDs = [NSMutableSet set];
        for (NSDictionary *entry in before) {
            NSString *value = entry[@"registryID"];
            if (value != nil) [beforeIDs addObject:value];
        }
        NSMutableArray *created = [NSMutableArray array];
        for (NSDictionary *entry in after) {
            if (![beforeIDs containsObject:entry[@"registryID"]]) {
                [created addObject:entry];
            }
        }

        NSDictionary *report = @{
            @"schema": @"com.zeroxjf.cyanide.iouserethernet-signer-trigger",
            @"schemaVersion": @1,
            @"normalTrigger": @"IOUserEthernetResource selector 0",
            @"requiredEntitlement":
                @"com.apple.networking.ethernet.user-access",
            @"kernelReadUsed": @NO,
            @"kernelWriteUsed": @NO,
            @"kernelCallUsed": @NO,
            @"openKR": CNDHex((uint32_t)openKR),
            @"callKR": CNDHex((uint32_t)callKR),
            @"controllerCookie": CNDHex(controllerCookie),
            @"scalarOutputCount": @(scalarOutputCount),
            @"interfacesBefore": before,
            @"interfacesAfter": after,
            @"createdInterfaces": created,
            @"holdSeconds": @(holdSeconds),
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:report
            options:NSJSONWritingSortedKeys error:nil];
        if (json != nil) {
            fwrite(json.bytes, 1, json.length, stdout);
            fputc('\n', stdout);
            fflush(stdout);
        }

        if (callKR == KERN_SUCCESS && holdSeconds != 0) {
            sleep((unsigned int)holdSeconds);
        }
        if (serialized != NULL) CFRelease(serialized);
        if (MACH_PORT_VALID(connection)) IOServiceClose(connection);
        return callKR == KERN_SUCCESS && created.count != 0 ? 0 : 1;
    }
}
