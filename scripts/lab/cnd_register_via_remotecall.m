#import "CNDLabRemoteCallClient.h"
#import <Foundation/Foundation.h>

#include <stdio.h>
#include <string.h>

static uint64_t call_symbol(CNDLabRemoteCallClient *client,
                            const char *symbol,
                            uint64_t a0, uint64_t a1, uint64_t a2,
                            uint64_t a3, uint64_t a4)
{
    uint64_t arguments[8] = {a0, a1, a2, a3, a4, 0, 0, 0};
    uint64_t value = 0;
    int result = cnd_lab_remotecall_call_symbol(
        client, 10000, symbol, arguments, &value);
    if (result != 0) {
        fprintf(stderr, "%s failed: %d\n", symbol, result);
        return 0;
    }
    return value;
}

static uint64_t call_symbol6(CNDLabRemoteCallClient *client,
                             const char *symbol,
                             uint64_t a0, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5)
{
    uint64_t arguments[8] = {a0, a1, a2, a3, a4, a5, 0, 0};
    uint64_t value = 0;
    int result = cnd_lab_remotecall_call_symbol(
        client, 10000, symbol, arguments, &value);
    if (result != 0) {
        fprintf(stderr, "%s failed: %d\n", symbol, result);
        return 0;
    }
    return value;
}

static uint64_t remote_string(CNDLabRemoteCallClient *client,
                              const char *text)
{
    size_t length = strlen(text) + 1;
    uint64_t remote = call_symbol(
        client, "malloc", length, 0, 0, 0, 0);
    if (!remote || cnd_lab_remotecall_write(
            client, remote, text, length) != 0) return 0;
    return remote;
}

static uint64_t selector(CNDLabRemoteCallClient *client, const char *name)
{
    uint64_t remote = remote_string(client, name);
    if (!remote) return 0;
    uint64_t value = call_symbol(
        client, "sel_registerName", remote, 0, 0, 0, 0);
    (void)call_symbol(client, "free", remote, 0, 0, 0, 0);
    return value;
}

static uint64_t objc_class(CNDLabRemoteCallClient *client, const char *name)
{
    uint64_t remote = remote_string(client, name);
    if (!remote) return 0;
    uint64_t value = call_symbol(
        client, "objc_getClass", remote, 0, 0, 0, 0);
    (void)call_symbol(client, "free", remote, 0, 0, 0, 0);
    return value;
}

int main(int argc, char **argv)
{
    if (argc != 2 && argc != 3) return 64;
    BOOL dictionaryMode = argc == 3 && strcmp(argv[1], "--dictionary") == 0;
    const char *inputPath = dictionaryMode ? argv[2] : argv[1];
    if ((!dictionaryMode && argc != 2) || !inputPath || inputPath[0] != '/') {
        return 64;
    }
    CNDLabRemoteCallClient client = {.socketFD = -1, .responseFD = -1};
    char error[128] = {0};
    int result = cnd_lab_remotecall_connect(
        "installd", &client, error, sizeof(error));
    if (result != 0) {
        fprintf(stderr, "connect failed: %d (%s)\n", result, error);
        return 2;
    }
    uint64_t pool = call_symbol(
        &client, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0);
    uint64_t frameworkPath = remote_string(
        &client,
        "/System/Library/Frameworks/CoreServices.framework/CoreServices");
    uint64_t handle = frameworkPath ? call_symbol(
        &client, "dlopen", frameworkPath, 2, 0, 0, 0) : 0;
    if (frameworkPath) (void)call_symbol(
        &client, "free", frameworkPath, 0, 0, 0, 0);

    uint64_t registrationObject = 0;
    if (dictionaryMode) {
        NSData *plist = [NSData dataWithContentsOfFile:
            [NSString stringWithUTF8String:inputPath]];
        uint64_t remoteBytes = plist.length > 0 ? call_symbol(
            &client, "malloc", plist.length, 0, 0, 0, 0) : 0;
        if (!remoteBytes || cnd_lab_remotecall_write(
                &client, remoteBytes, plist.bytes, plist.length) != 0) {
            return 70;
        }
        uint64_t dataClass = objc_class(&client, "NSData");
        uint64_t remoteData = call_symbol(
            &client, "objc_msgSend", dataClass,
            selector(&client, "dataWithBytes:length:"),
            remoteBytes, plist.length, 0);
        (void)call_symbol(&client, "free", remoteBytes, 0, 0, 0, 0);
        uint64_t plistClass = objc_class(
            &client, "NSPropertyListSerialization");
        registrationObject = call_symbol6(
            &client, "objc_msgSend", plistClass,
            selector(&client, "propertyListWithData:options:format:error:"),
            remoteData, 0, 0, 0);
    } else {
        uint64_t pathBytes = remote_string(&client, inputPath);
        uint64_t stringClass = objc_class(&client, "NSString");
        uint64_t pathString = call_symbol(
            &client, "objc_msgSend", stringClass,
            selector(&client, "stringWithUTF8String:"), pathBytes, 0, 0);
        if (pathBytes) (void)call_symbol(
            &client, "free", pathBytes, 0, 0, 0, 0);
        uint64_t urlClass = objc_class(&client, "NSURL");
        registrationObject = call_symbol(
            &client, "objc_msgSend", urlClass,
            selector(&client, "fileURLWithPath:isDirectory:"),
            pathString, 1, 0);
    }
    uint64_t workspaceClass = objc_class(
        &client, "LSApplicationWorkspace");
    uint64_t workspace = call_symbol(
        &client, "objc_msgSend", workspaceClass,
        selector(&client, "defaultWorkspace"), 0, 0, 0);
    uint64_t accepted = call_symbol(
        &client, "objc_msgSend", workspace,
        selector(&client, dictionaryMode
            ? "registerApplicationDictionary:" : "registerApplication:"),
        registrationObject, 0, 0);

    if (pool) (void)call_symbol(
        &client, "objc_autoreleasePoolPop", pool, 0, 0, 0, 0);
    int closeResult = cnd_lab_remotecall_close(&client);
    fprintf(stderr,
        "handle=%#llx workspace=%#llx accepted=%llu close=%d\n",
        handle, workspace, accepted, closeResult);
    return accepted && closeResult == 0 ? 0 : 1;
}
