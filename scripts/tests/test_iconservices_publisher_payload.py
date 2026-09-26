"""Host-executable checks for typed publisher payload descriptor setup."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "Cyanide/installer"
PAYLOAD_SOURCE = INSTALLER / "CNDIconServicesPublisherPayload.c"


HARNESS = r"""
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import "CNDIconServicesPublisherPayload.h"

typedef struct {
    double width;
    double height;
} CNDTestSize;

@interface CNDTestDescriptor : NSObject <NSCopying>
@property(nonatomic) CNDTestSize size;
@property(nonatomic) double scale;
@property(nonatomic) NSUInteger appearance;
@property(nonatomic) NSUInteger factoryPreset;
@property(nonatomic) NSUInteger variantOptions;
@property(nonatomic) NSUInteger options;
@property(nonatomic) BOOL ignoreCache;
@end

@implementation CNDTestDescriptor
+ (instancetype)imageDescriptorWithIconVariant:(int)iconVariant
                                        options:(int)options
{
    CNDTestDescriptor *descriptor = [[self alloc] init];
    descriptor.factoryPreset = iconVariant;
    descriptor.options = options;
    return descriptor;
}
- (id)copyWithZone:(NSZone *)zone
{
    CNDTestDescriptor *copy = [[[self class] allocWithZone:zone] init];
    copy.size = self.size;
    copy.scale = self.scale;
    copy.appearance = self.appearance;
    copy.factoryPreset = self.factoryPreset;
    copy.variantOptions = self.variantOptions;
    copy.options = self.options;
    copy.ignoreCache = self.ignoreCache;
    return copy;
}
@end

static int fail(const char *reason)
{
    fprintf(stderr, "publisher payload fixture failed: %s\n", reason);
    return 1;
}

int main(void)
{
    @autoreleasepool {
        CNDIconServicesPublisherPayloadContext context = {0};
        char staging[8] = "x";
        context.magic = CND_ICON_PUBLISHER_PAYLOAD_MAGIC;
        context.version = CND_ICON_PUBLISHER_PAYLOAD_VERSION;
        context.objcMsgSend = (uint64_t)(uintptr_t)dlsym(
            RTLD_DEFAULT, "objc_msgSend");
        context.methodSetImplementation = (uint64_t)(uintptr_t)dlsym(
            RTLD_DEFAULT, "method_setImplementation");
        context.objcAutoreleasePoolPush = (uint64_t)(uintptr_t)dlsym(
            RTLD_DEFAULT, "objc_autoreleasePoolPush");
        context.objcAutoreleasePoolPop = (uint64_t)(uintptr_t)dlsym(
            RTLD_DEFAULT, "objc_autoreleasePoolPop");
        context.generationMethod = 1;
        context.originalGenerate = 1;
        context.descriptorClass = (uint64_t)(uintptr_t)CNDTestDescriptor.class;
        context.stringClass = (uint64_t)(uintptr_t)NSString.class;
        context.stagingAddress = (uint64_t)(uintptr_t)staging;
        context.stagingCapacity = sizeof(staging);
        context.stagingBundleLength = 1;
        context.stagingDataOffset = 2;
        context.expectedWidth = 68.0;
        context.expectedHeight = 68.0;
        context.expectedScale = 3.0;
        context.expectedAppearance = 1;
        context.expectedIconVariant = 2;
        context.expectedOptions = 3;
        context.selRespondsToSelector = (uint64_t)(uintptr_t)
            sel_registerName("respondsToSelector:");
        context.selAlloc = (uint64_t)(uintptr_t)sel_registerName("alloc");
        context.selInitWithUTF8String = (uint64_t)(uintptr_t)
            sel_registerName("initWithUTF8String:");
        context.selImageDescriptorWithIconVariantOptions =
            (uint64_t)(uintptr_t)
            sel_registerName("imageDescriptorWithIconVariant:options:");
        context.selCopy = (uint64_t)(uintptr_t)sel_registerName("copy");
        context.selSetSize = (uint64_t)(uintptr_t)sel_registerName("setSize:");
        context.selSetScale = (uint64_t)(uintptr_t)sel_registerName("setScale:");
        context.selSetAppearance = (uint64_t)(uintptr_t)
            sel_registerName("setAppearance:");
        context.selSetVariantOptions = (uint64_t)(uintptr_t)
            sel_registerName("setVariantOptions:");
        context.selSetIgnoreCache = (uint64_t)(uintptr_t)
            sel_registerName("setIgnoreCache:");
        context.selSize = (uint64_t)(uintptr_t)sel_registerName("size");
        context.selScale = (uint64_t)(uintptr_t)sel_registerName("scale");
        context.selAppearance = (uint64_t)(uintptr_t)
            sel_registerName("appearance");
        context.selVariantOptions = (uint64_t)(uintptr_t)
            sel_registerName("variantOptions");
        context.selRelease = (uint64_t)(uintptr_t)sel_registerName("release");
        uint64_t address =
            cnd_icon_publisher_payload_prepare_descriptor_body(&context);
        if (!address || context.descriptorTemplate != address ||
            context.descriptorPrepared != 1) {
            return fail("descriptor not prepared");
        }
        uint64_t required =
            CND_ICON_PUBLISHER_DESCRIPTOR_POOL_READY |
            CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_READY |
            CND_ICON_PUBLISHER_DESCRIPTOR_FACTORY_RETURNED |
            CND_ICON_PUBLISHER_DESCRIPTOR_COPIED |
            CND_ICON_PUBLISHER_DESCRIPTOR_CONFIGURED |
            CND_ICON_PUBLISHER_DESCRIPTOR_VERIFIED;
        if ((context.descriptorPreparationBits & required) != required) {
            return fail("preparation gates incomplete");
        }
        CNDTestDescriptor *descriptor = (__bridge CNDTestDescriptor *)
            (void *)(uintptr_t)address;
        if (descriptor.size.width != 68.0 ||
            descriptor.size.height != 68.0 || descriptor.scale != 3.0 ||
            descriptor.appearance != 1 || descriptor.factoryPreset != 0 ||
            descriptor.variantOptions != 2 ||
            descriptor.options != 3 || !descriptor.ignoreCache) {
            return fail("typed descriptor values differ");
        }
        uint64_t reused =
            cnd_icon_publisher_payload_prepare_descriptor_body(&context);
        if (reused != address) return fail("retained template not reused");
        id ownedDescriptor = (__bridge_transfer id)(void *)(uintptr_t)address;
        (void)ownedDescriptor;
        return 0;
    }
}
"""


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("xcrun"),
    "Objective-C payload fixture requires macOS Xcode",
)
class IconServicesPublisherPayloadTests(unittest.TestCase):
    def test_typed_descriptor_preparation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cnd-publisher-payload-") as directory:
            root = Path(directory)
            harness = root / "harness.m"
            binary = root / "harness"
            harness.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
            sdk = subprocess.check_output(
                ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
            ).strip()
            clang = subprocess.check_output(
                ["xcrun", "--sdk", "macosx", "--find", "clang"], text=True
            ).strip()
            subprocess.run(
                [
                    clang,
                    "-fobjc-arc",
                    "-fobjc-runtime=macosx-14.0",
                    "-Wno-cast-of-sel-type",
                    "-isysroot",
                    sdk,
                    "-I",
                    str(INSTALLER),
                    str(PAYLOAD_SOURCE),
                    str(harness),
                    "-framework",
                    "Foundation",
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
