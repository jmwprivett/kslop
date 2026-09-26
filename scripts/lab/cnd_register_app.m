#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <string.h>

int main(int argc, char **argv)
{
    BOOL openMode = argc == 3 && strcmp(argv[1], "--open") == 0;
    if ((!openMode && (argc != 2 || argv[1][0] != '/')) ||
        (openMode && argv[2][0] == '\0')) return 64;
    @autoreleasepool {
        void *handle = dlopen(
            "/System/Library/Frameworks/CoreServices.framework/CoreServices",
            RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            handle = dlopen(
                "/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices",
                RTLD_NOW | RTLD_LOCAL);
        }
        Class workspaceClass = NSClassFromString(@"LSApplicationWorkspace");
        SEL defaultSelector = NSSelectorFromString(@"defaultWorkspace");
        id workspace = workspaceClass &&
            [workspaceClass respondsToSelector:defaultSelector]
            ? ((id (*)(id, SEL))objc_msgSend)(workspaceClass, defaultSelector)
            : nil;
        SEL actionSelector = NSSelectorFromString(openMode
            ? @"openApplicationWithBundleID:" : @"registerApplication:");
        if (!handle || !workspace ||
            ![workspace respondsToSelector:actionSelector]) return 69;
        if (openMode) {
            NSString *identifier = [NSString stringWithUTF8String:argv[2]];
            BOOL accepted = ((BOOL (*)(id, SEL, id))objc_msgSend)(
                workspace, actionSelector, identifier);
            fprintf(stderr, "openApplicationWithBundleID returned %s\n",
                    accepted ? "YES" : "NO");
            return accepted ? 0 : 1;
        }
        NSURL *url = [NSURL fileURLWithPath:
            [NSString stringWithUTF8String:argv[1]] isDirectory:YES];
        BOOL accepted = ((BOOL (*)(id, SEL, id))objc_msgSend)(
            workspace, actionSelector, url);
        fprintf(stderr, "registerApplication returned %s\n",
                accepted ? "YES" : "NO");
        return accepted ? 0 : 1;
    }
}
