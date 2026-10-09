#import <Foundation/Foundation.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>

int main(void)
{
    @autoreleasepool {
        dlopen("/System/Library/Frameworks/QuickLookThumbnailing.framework/"
               "QuickLookThumbnailing", RTLD_NOW | RTLD_LOCAL);
        dlopen("/System/Library/PrivateFrameworks/FileProvider.framework/"
               "FileProvider", RTLD_NOW | RTLD_LOCAL);
        Class itemIDClass = NSClassFromString(@"FPItemID");
        id itemIDAllocation = ((id (*)(id, SEL))objc_msgSend)(
            itemIDClass, sel_registerName("alloc"));
        id itemID = ((id (*)(id, SEL, id, id, id))objc_msgSend)(
            itemIDAllocation,
            sel_registerName(
                "initWithProviderID:domainIdentifier:itemIdentifier:"),
            @"com.apple.FileProvider.LocalStorage",
            @"NSFileProviderDomainDefaultIdentifier",
            @"NSFileProviderRootContainerItemIdentifier");
        Class proxyClass = NSClassFromString(@"QLThumbnailServiceProxy");
        id proxy = ((id (*)(id, SEL))objc_msgSend)(
            proxyClass, sel_registerName("sharedInstance"));
        __block BOOL finished = NO;
        void (^completion)(id) = ^(id result) {
            fprintf(stderr, "quicklook result=%s\n",
                    [[result description] UTF8String] ?: "-");
            finished = YES;
        };
        ((void (*)(id, SEL, id, id))objc_msgSend)(
            proxy, sel_registerName("getAllThumbnailsForFPItemID:"
                                    "completionHandler:"),
            itemID, completion);
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:5.0];
        while (!finished && deadline.timeIntervalSinceNow > 0.0) {
            [NSRunLoop.currentRunLoop runUntilDate:
                [NSDate dateWithTimeIntervalSinceNow:0.05]];
        }
        return finished ? 0 : 1;
    }
}
