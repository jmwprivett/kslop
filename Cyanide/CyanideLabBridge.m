#import "CyanideLabBridge.h"

#import <UIKit/UIKit.h>
#import <arpa/inet.h>
#import <errno.h>
#import <fcntl.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <unistd.h>

static const uint16_t kCyanideLabBridgePort = 49494;
static const NSUInteger kCyanideLabBridgeRequestLimit = 64 * 1024;
static const NSTimeInterval kCyanideLabBridgeBackgroundGraceSeconds = 25.0;

static int gLabListenFD = -1;
static dispatch_source_t gLabAcceptSource;
static dispatch_queue_t gLabAcceptQueue;
static dispatch_queue_t gLabCommandQueue;
static NSString *gLabToken;
static CyanideLabBridgeRequestHandler gLabHandler;
static dispatch_block_t gLabStopHandler;
static id gLabResignObserver;
static id gLabActiveObserver;
static UIBackgroundTaskIdentifier gLabBackgroundTask = NSUIntegerMax;
static NSUInteger gLabBackgroundGeneration;

static NSObject *lab_state_lock(void)
{
    static NSObject *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [NSObject new]; });
    return lock;
}

static NSDictionary *lab_error(NSString *code, NSString *message)
{
    return @{ @"ok": @NO,
              @"error": code ?: @"bridge-error",
              @"message": message ?: @"Unknown bridge error.",
              @"protocolVersion": @1 };
}

static NSData *lab_json_line(NSDictionary *response)
{
    NSMutableDictionary *body = [response mutableCopy] ?: [NSMutableDictionary dictionary];
    if (!body[@"protocolVersion"]) body[@"protocolVersion"] = @1;
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:&error];
    if (!json) {
        json = [NSJSONSerialization dataWithJSONObject:
            lab_error(@"response-encoding",error.localizedDescription)
            options:0 error:nil];
    }
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    return line;
}

static void lab_send_all(int fd, NSData *data)
{
    const uint8_t *bytes = data.bytes;
    NSUInteger remaining = data.length;
    while (remaining) {
        ssize_t sent = send(fd,bytes,remaining,0);
        if (sent > 0) {
            bytes += sent;
            remaining -= (NSUInteger)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        break;
    }
}

static NSDictionary *lab_handle_data(NSData *data)
{
    if (!data.length) return lab_error(@"empty-request",@"Request was empty.");
    NSError *error = nil;
    id decoded = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![decoded isKindOfClass:NSDictionary.class]) {
        return lab_error(@"invalid-json",error.localizedDescription ?: @"Top level must be an object.");
    }
    NSDictionary *request = decoded;
    NSString *token = [request[@"token"] isKindOfClass:NSString.class]
        ? request[@"token"] : nil;
    NSString *expected = nil;
    CyanideLabBridgeRequestHandler handler = nil;
    @synchronized (lab_state_lock()) {
        expected = gLabToken;
        handler = gLabHandler;
    }
    if (!expected.length || ![token isEqualToString:expected]) {
        return lab_error(@"unauthorized",@"The per-launch bridge token did not match.");
    }
    if (!handler) return lab_error(@"bridge-stopped",@"The bridge is stopping.");
    @try {
        NSDictionary *response = handler(request);
        return response ?: lab_error(@"empty-response",@"Command returned no response.");
    } @catch (NSException *exception) {
        return lab_error(@"handler-exception",
                         [NSString stringWithFormat:@"%@: %@",
                          exception.name ?: @"exception",
                          exception.reason ?: @"unknown"]);
    }
}

static void lab_handle_client(int fd)
{
    int flags = fcntl(fd,F_GETFL,0);
    if (flags >= 0) (void)fcntl(fd,F_SETFL,flags & ~O_NONBLOCK);
    int one = 1;
    setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct timeval timeout = { .tv_sec = 15, .tv_usec = 0 };
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));

    NSMutableData *request = [NSMutableData data];
    uint8_t buffer[2048];
    BOOL complete = NO;
    while (request.length < kCyanideLabBridgeRequestLimit) {
        ssize_t count = recv(fd,buffer,sizeof(buffer),0);
        if (count > 0) {
            const uint8_t *newline = memchr(buffer,'\n',(size_t)count);
            NSUInteger accepted = newline
                ? (NSUInteger)(newline - buffer) : (NSUInteger)count;
            [request appendBytes:buffer length:accepted];
            if (newline) { complete = YES; break; }
            continue;
        }
        if (count == 0) { complete = YES; break; }
        if (errno == EINTR) continue;
        break;
    }

    NSDictionary *response = nil;
    if (request.length >= kCyanideLabBridgeRequestLimit) {
        response = lab_error(@"request-too-large",@"Requests are limited to 64 KiB.");
    } else if (!complete) {
        response = lab_error(@"request-timeout",@"A complete JSON line was not received.");
    } else {
        response = lab_handle_data(request);
    }
    lab_send_all(fd,lab_json_line(response));
    shutdown(fd,SHUT_RDWR);
    close(fd);
}

static NSString *lab_new_token(void)
{
    NSString *a = [NSUUID.UUID.UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
    NSString *b = [NSUUID.UUID.UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];
    return [a stringByAppendingString:b].lowercaseString;
}

static void lab_end_background_task(UIBackgroundTaskIdentifier task)
{
    if (task == UIBackgroundTaskInvalid) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        [[UIApplication sharedApplication] endBackgroundTask:task];
    });
}

static void lab_application_did_become_active(void)
{
    UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;
    @synchronized (lab_state_lock()) {
        gLabBackgroundGeneration++;
        task = gLabBackgroundTask;
        gLabBackgroundTask = UIBackgroundTaskInvalid;
    }
    lab_end_background_task(task);
    printf("[LAB_BRIDGE] foreground-resumed backgroundLeaseEnded=%d\n",
           task != UIBackgroundTaskInvalid);
}

static void lab_begin_background_window(void)
{
    UIApplication *application = UIApplication.sharedApplication;
    __block UIBackgroundTaskIdentifier task = UIBackgroundTaskInvalid;
    task = [application beginBackgroundTaskWithName:@"Cyanide Lab Bridge"
                                  expirationHandler:^{
        printf("[LAB_BRIDGE] background-expired stopping=1\n");
        cyanide_lab_bridge_stop();
    }];
    if (task == UIBackgroundTaskInvalid) {
        printf("[LAB_BRIDGE] background-begin-failed stopping=1\n");
        cyanide_lab_bridge_stop();
        return;
    }

    NSUInteger generation = 0;
    UIBackgroundTaskIdentifier oldTask = UIBackgroundTaskInvalid;
    BOOL accepted = NO;
    @synchronized (lab_state_lock()) {
        if (gLabListenFD >= 0) {
            oldTask = gLabBackgroundTask;
            gLabBackgroundTask = task;
            generation = ++gLabBackgroundGeneration;
            accepted = YES;
        }
    }
    lab_end_background_task(oldTask);
    if (!accepted) {
        lab_end_background_task(task);
        return;
    }

    printf("[LAB_BRIDGE] background-begin graceSeconds=%.0f remaining=%.1f\n",
           kCyanideLabBridgeBackgroundGraceSeconds,
           application.backgroundTimeRemaining);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                   (int64_t)(kCyanideLabBridgeBackgroundGraceSeconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        BOOL shouldStop = NO;
        @synchronized (lab_state_lock()) {
            shouldStop = gLabListenFD >= 0 &&
                         gLabBackgroundGeneration == generation &&
                         gLabBackgroundTask == task;
        }
        if (shouldStop) {
            printf("[LAB_BRIDGE] background-grace-elapsed stopping=1\n");
            cyanide_lab_bridge_stop();
        }
    });
}

BOOL cyanide_lab_bridge_start(
    CyanideLabBridgeRequestHandler handler,
    dispatch_block_t stopHandler,
    NSError **errorOut)
{
    if (!handler) {
        if (errorOut) *errorOut = [NSError errorWithDomain:@"CyanideLabBridge"
            code:1 userInfo:@{NSLocalizedDescriptionKey:@"A request handler is required."}];
        return NO;
    }
    @synchronized (lab_state_lock()) {
        if (gLabListenFD >= 0) return YES;

        int fd = socket(AF_INET6,SOCK_STREAM,0);
        if (fd < 0) {
            if (errorOut) *errorOut = [NSError errorWithDomain:NSPOSIXErrorDomain
                code:errno userInfo:nil];
            return NO;
        }
        int one = 1;
        int zero = 0;
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
        setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&zero,sizeof(zero));
        fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) | O_NONBLOCK);

        struct sockaddr_in6 address = {0};
        address.sin6_len = sizeof(address);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(kCyanideLabBridgePort);
        address.sin6_addr = in6addr_any;
        if (bind(fd,(struct sockaddr *)&address,sizeof(address)) != 0 ||
            listen(fd,4) != 0) {
            int saved = errno;
            close(fd);
            if (errorOut) *errorOut = [NSError errorWithDomain:NSPOSIXErrorDomain
                code:saved userInfo:nil];
            return NO;
        }

        gLabListenFD = fd;
        gLabToken = lab_new_token();
        gLabHandler = [handler copy];
        gLabStopHandler = [stopHandler copy];
        gLabAcceptQueue = dispatch_queue_create("com.cyanide.lab-bridge.accept",DISPATCH_QUEUE_SERIAL);
        gLabCommandQueue = dispatch_queue_create("com.cyanide.lab-bridge.commands",DISPATCH_QUEUE_SERIAL);
        gLabAcceptSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
                                                   (uintptr_t)fd,0,gLabAcceptQueue);
        dispatch_source_set_event_handler(gLabAcceptSource, ^{
            for (;;) {
                int client = accept(gLabListenFD,NULL,NULL);
                if (client < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                dispatch_async(gLabCommandQueue, ^{ lab_handle_client(client); });
            }
        });
        dispatch_resume(gLabAcceptSource);
        gLabResignObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationWillResignActiveNotification
                        object:nil queue:NSOperationQueue.mainQueue
                    usingBlock:^(__unused NSNotification *note) {
            lab_begin_background_window();
        }];
        gLabActiveObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidBecomeActiveNotification
                        object:nil queue:NSOperationQueue.mainQueue
                    usingBlock:^(__unused NSNotification *note) {
            lab_application_did_become_active();
        }];
    }
    printf("[LAB_BRIDGE] started port=%u transport=tcp foregroundOnly=0 backgroundGraceSeconds=%.0f authenticated=1 publicUploader=0\n",
           kCyanideLabBridgePort,kCyanideLabBridgeBackgroundGraceSeconds);
    return YES;
}

void cyanide_lab_bridge_stop(void)
{
    dispatch_block_t stopHandler = nil;
    id resignObserver = nil;
    id activeObserver = nil;
    UIBackgroundTaskIdentifier backgroundTask = UIBackgroundTaskInvalid;
    @synchronized (lab_state_lock()) {
        if (gLabListenFD < 0) return;
        int fd = gLabListenFD;
        gLabListenFD = -1;
        shutdown(fd,SHUT_RDWR);
        close(fd);
        if (gLabAcceptSource) dispatch_source_cancel(gLabAcceptSource);
        gLabAcceptSource = nil;
        resignObserver = gLabResignObserver;
        activeObserver = gLabActiveObserver;
        gLabResignObserver = nil;
        gLabActiveObserver = nil;
        backgroundTask = gLabBackgroundTask;
        gLabBackgroundTask = UIBackgroundTaskInvalid;
        gLabBackgroundGeneration++;
        stopHandler = gLabStopHandler;
        gLabStopHandler = nil;
        gLabHandler = nil;
        gLabToken = nil;
    }
    if (resignObserver) [[NSNotificationCenter defaultCenter] removeObserver:resignObserver];
    if (activeObserver) [[NSNotificationCenter defaultCenter] removeObserver:activeObserver];
    lab_end_background_task(backgroundTask);
    if (stopHandler) dispatch_async(gLabCommandQueue ?: dispatch_get_global_queue(0,0),stopHandler);
    printf("[LAB_BRIDGE] stopped reason=manual-or-background-expiry leaseCleanupRequested=1\n");
}

BOOL cyanide_lab_bridge_is_running(void)
{
    @synchronized (lab_state_lock()) { return gLabListenFD >= 0; }
}

NSString *cyanide_lab_bridge_token(void)
{
    @synchronized (lab_state_lock()) { return [gLabToken copy]; }
}

uint16_t cyanide_lab_bridge_port(void)
{
    return kCyanideLabBridgePort;
}
