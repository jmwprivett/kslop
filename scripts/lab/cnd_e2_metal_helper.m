#import <Foundation/Foundation.h>
#import <IOKit/IODataQueueClient.h>
#import <IOKit/IOKitLib.h>
#import <Metal/Metal.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <os/lock.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    CNDE2Magic = 0x45324558, // "E2EX"
    CNDE2Version = 5,
    CNDE2Ready = 1,
    CNDE2Exiting = 2,
    CNDE2Completed = 3,
    CNDE2TokenBytes = 16,
    CNDE2PageSize = 0x4000,
    CNDE2ReleaseByte = 0xa5,
    CNDE2SubmitByte = 0x5a,
    CNDE2ReleaseTimeoutMS = 75000,
    CNDE2RetireMode = 1,
    CNDE2LatchMode = 2,
    CNDE4InflightMode = 3,
    CNDE5OwnerReleaseMode = 4,
    CNDE5DeviceReleaseMode = 5,
    CNDE5ConnectionReleaseMode = 6,
    CNDE5RawQueueReleaseMode = 7,
    CNDE5RawQueueBindReleaseMode = 8,
    CNDE2LatchCandidateLimit = 32,
    CNDE2RetirePattern = 0x6d,
    CNDE2LatchPattern = 0xa7,
    CNDE2LatchPrimaryInitial = 0x31,
    CNDE2LatchSecondaryInitial = 0x52,
    CNDE4ConfigMagic = 0x45344346, // "E4CF"
    CNDE4ConfigVersion = 2,
    CNDE4ControlMarker = 0xe4c01101,
    CNDE4TerminalMarker = 0xe4f1a104,
    CNDE5ReleaseMarker = 0xe5d00105,
    CNDE5DeviceReleaseMarker = 0xe5d00205,
    CNDE5DeviceControlMarker = 0xd5d5d5d5,
    CNDE5ConnectionReleaseMarker = 0xe5d00305,
    CNDE5ConnectionControlMarker = 0xc5c5c5c5,
    CNDE5RawQueueReleaseMarker = 0xe5d00405,
    CNDE5RawQueueControlMarker = 0xa5a5a5a5,
    CNDE5RawQueueBindReleaseMarker = 0xe5d00505,
    CNDE5RawQueueBindControlMarker = 0xb5b5b5b5,
    CNDE4WorkloadRounds = 8000000,
    CNDE4WorkloadThreads = 64,
    CNDE5WeakReleasePollLimit = 300,
    CNDE5WeakReleasePollIntervalUS = 10000,
    CNDE5CleanupSourceOffset = 0x328,
    CNDE5CleanupLockOffset = 0x330,
    CNDE5CleanupScheduledOffset = 0x334,
    CNDE5CleanupRequestedOffset = 0x335,
};

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    int32_t result;
    uint32_t pid;
    uint32_t metalStatus;
    uint32_t fillVerified;
    uint32_t mode;
    uint64_t gpuAddress;
    uint64_t secondaryGPUAddress;
    uint32_t primaryPatternBytes;
    uint32_t secondaryPatternBytes;
    uint8_t token[CNDE2TokenBytes];
    uint32_t surfaceID;
    uint32_t workloadRounds;
    uint32_t markerValue;
    uint32_t reserved;
} CNDE2Message;

_Static_assert(sizeof(CNDE2Message) == 88,
               "E2 helper wire message must remain stable");

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t controlMarker;
    uint32_t terminalMarker;
    uint32_t workloadRounds;
    uint32_t reserved;
    uint64_t fileDevice;
    uint64_t fileInode;
    uint8_t token[CNDE2TokenBytes];
} CNDE4Config;

_Static_assert(sizeof(CNDE4Config) == 56,
               "E4 helper config must remain stable");

static NSString *const CNDE4AppGroupIdentifier =
    @"group.com.zeroxjf.cyanide.e4.ztgmy9fa3v";

static uint16_t gPort;
static uint8_t gToken[CNDE2TokenBytes];
static uint32_t gMode;
static uint64_t gAvoidGPUAddress;
static uint32_t gRequiredRootIndex = UINT32_MAX;

static bool CNDE5GlobalDeviceArrayContainsPrivateDevice(
    id device, bool *checkedOut, uint32_t *countOut)
{
    bool checked = false;
    bool contains = false;
    uint32_t count = 0;
    if (@available(iOS 18.0, *)) {
        @autoreleasepool {
            NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();
            checked = devices != nil;
            NSUInteger deviceCount = devices.count;
            count = deviceCount > UINT32_MAX
                ? UINT32_MAX : (uint32_t)deviceCount;
            contains = checked &&
                [devices indexOfObjectIdenticalTo:device] != NSNotFound;
        }
    }
    if (checkedOut != NULL) *checkedOut = checked;
    if (countOut != NULL) *countOut = count;
    return contains;
}

static bool CNDE2ParseHexToken(const char *text, uint8_t *token)
{
    if (text == NULL || token == NULL || strlen(text) != CNDE2TokenBytes * 2) {
        return false;
    }
    for (size_t index = 0; index < CNDE2TokenBytes; index++) {
        char byteText[3] = {text[index * 2], text[index * 2 + 1], '\0'};
        char *end = NULL;
        unsigned long value = strtoul(byteText, &end, 16);
        if (end == byteText || *end != '\0' || value > UINT8_MAX) return false;
        token[index] = (uint8_t)value;
    }
    return true;
}

static bool CNDE2ParseArguments(int argc, char *argv[])
{
    const char *portText = NULL;
    const char *tokenText = NULL;
    const char *modeText = NULL;
    const char *avoidText = NULL;
    const char *rootIndexText = NULL;
    for (int index = 1; index + 1 < argc; index++) {
        if (strcmp(argv[index], "--port") == 0) portText = argv[++index];
        else if (strcmp(argv[index], "--token") == 0) tokenText = argv[++index];
        else if (strcmp(argv[index], "--mode") == 0) modeText = argv[++index];
        else if (strcmp(argv[index], "--avoid-gpu-address") == 0) {
            avoidText = argv[++index];
        } else if (strcmp(argv[index], "--root-index") == 0) {
            rootIndexText = argv[++index];
        }
    }
    if (portText == NULL || tokenText == NULL || modeText == NULL) return false;
    char *end = NULL;
    unsigned long port = strtoul(portText, &end, 10);
    if (end == portText || *end != '\0' || port == 0 || port > UINT16_MAX) {
        return false;
    }
    if (strcmp(modeText, "retire") == 0) {
        gMode = CNDE2RetireMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "latch") == 0) {
        gMode = CNDE2LatchMode;
        if (rootIndexText == NULL) return false;
        if (avoidText != NULL) {
            end = NULL;
            unsigned long long avoid = strtoull(avoidText, &end, 0);
            if (end == avoidText || *end != '\0') return false;
            gAvoidGPUAddress = (uint64_t)avoid;
        }
        end = NULL;
        unsigned long rootIndex = strtoul(rootIndexText, &end, 0);
        if (end == rootIndexText || *end != '\0' || rootIndex > 1) {
            return false;
        }
        gRequiredRootIndex = (uint32_t)rootIndex;
    } else if (strcmp(modeText, "inflight") == 0) {
        gMode = CNDE4InflightMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "owner-release") == 0) {
        gMode = CNDE5OwnerReleaseMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "device-release") == 0) {
        gMode = CNDE5DeviceReleaseMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "connection-release") == 0) {
        gMode = CNDE5ConnectionReleaseMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "raw-queue-release") == 0) {
        gMode = CNDE5RawQueueReleaseMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else if (strcmp(modeText, "raw-queue-bind-release") == 0) {
        gMode = CNDE5RawQueueBindReleaseMode;
        if (avoidText != NULL || rootIndexText != NULL) return false;
    } else {
        return false;
    }
    gPort = (uint16_t)port;
    return CNDE2ParseHexToken(tokenText, gToken);
}

static bool CNDE2ReadAll(int fd, void *bytes, size_t length)
{
    uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t consumed = read(fd, cursor, length);
        if (consumed < 0 && errno == EINTR) continue;
        if (consumed <= 0) return false;
        cursor += (size_t)consumed;
        length -= (size_t)consumed;
    }
    return true;
}

static bool CNDE2WriteAll(int fd, const void *bytes, size_t length)
{
    const uint8_t *cursor = bytes;
    while (length != 0) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static int CNDE2Connect(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(gPort);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0) {
            return fd;
        }
        if (errno != ECONNREFUSED && errno != EINTR) break;
        usleep(20000);
    }
    close(fd);
    return -1;
}

static bool CNDE2ReadControlByte(int fd, uint8_t expected,
                                const char *label)
{
    struct pollfd pollFD = {.fd = fd, .events = POLLIN, .revents = 0};
    int pollResult = 0;
    do {
        pollResult = poll(&pollFD, 1, CNDE2ReleaseTimeoutMS);
    } while (pollResult < 0 && errno == EINTR);
    uint8_t value = 0;
    ssize_t consumed = pollResult == 1 ? read(fd, &value, 1) : -1;
    bool passed = consumed == 1 && value == expected;
    if (!passed) {
        fprintf(stderr,
                "[E2_HELPER] %s failed pid=%d poll=%d read=%zd byte=0x%02x expected=0x%02x\n",
                label, getpid(), pollResult, consumed, value, expected);
        fflush(stderr);
    }
    return passed;
}

static uint32_t CNDE2CountPatternBytes(const void *contents, uint8_t pattern)
{
    if (contents == NULL) return 0;
    const uint8_t *bytes = contents;
    uint32_t count = 0;
    for (NSUInteger index = 0; index < CNDE2PageSize; index++) {
        if (bytes[index] == pattern) count++;
    }
    return count;
}

static NSString *const CNDE4ShaderSource =
    @"#include <metal_stdlib>\n"
     "using namespace metal;\n"
     "kernel void cnd_e4_work(device volatile uint *state [[buffer(0)]],\n"
     "                         constant uint &rounds [[buffer(1)]],\n"
     "                         uint tid [[thread_position_in_grid]]) {\n"
     "  uint value = state[tid] ^ (0x9e3779b9u + tid);\n"
     "  for (uint i = 0; i < rounds; i++) {\n"
     "    value = value * 1664525u + 1013904223u + tid;\n"
     "    if ((i & 255u) == 0u) state[tid] = value;\n"
     "  }\n"
     "  state[tid] = value;\n"
     "}\n"
     "kernel void cnd_e4_mark(device uint *shared [[buffer(0)]],\n"
     "                         constant uint &marker [[buffer(1)]]) {\n"
     "  shared[0] = marker;\n"
     "}\n";

static void CNDE4TokenHex(char output[CNDE2TokenBytes * 2 + 1])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < CNDE2TokenBytes; index++) {
        output[index * 2] = digits[gToken[index] >> 4];
        output[index * 2 + 1] = digits[gToken[index] & 0xf];
    }
    output[CNDE2TokenBytes * 2] = '\0';
}

static void CNDE4RunInflightAction(int fd)
{
    CNDE4Config config = {0};
    bool configRead = CNDE2ReadAll(fd, &config, sizeof(config));
    bool configPassed = configRead &&
        config.magic == CNDE4ConfigMagic &&
        config.version == CNDE4ConfigVersion &&
        config.controlMarker == CNDE4ControlMarker &&
        config.terminalMarker == CNDE4TerminalMarker &&
        config.workloadRounds == CNDE4WorkloadRounds &&
        config.reserved == 0 && config.fileDevice != 0 &&
        config.fileInode != 0 &&
        memcmp(config.token, gToken, sizeof(gToken)) == 0;
    if (!configPassed) {
        fprintf(stderr,
                "[E4_HELPER] config failed pid=%d read=%d magic=0x%08x version=%u dev=0x%llx inode=0x%llx\n",
                getpid(), configRead, config.magic, config.version,
                (unsigned long long)config.fileDevice,
                (unsigned long long)config.fileInode);
        fflush(stderr);
        close(fd);
        _exit(75);
    }

    char tokenHex[CNDE2TokenBytes * 2 + 1] = {0};
    CNDE4TokenHex(tokenHex);
    NSString *fileName = [NSString stringWithFormat:@"e4-%s.bin", tokenHex];
    NSURL *containerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDE4AppGroupIdentifier];
    NSURL *fileURL = containerURL != nil
        ? [containerURL URLByAppendingPathComponent:fileName isDirectory:NO]
        : nil;
    int sharedFD = fileURL != nil
        ? open(fileURL.fileSystemRepresentation, O_RDWR | O_CLOEXEC) : -1;
    struct stat sharedStat = {0};
    bool identityPassed = sharedFD >= 0 && fstat(sharedFD, &sharedStat) == 0 &&
        S_ISREG(sharedStat.st_mode) &&
        sharedStat.st_size == CNDE2PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev == config.fileDevice &&
        (uint64_t)sharedStat.st_ino == config.fileInode;
    void *sharedMapping = identityPassed
        ? mmap(NULL, CNDE2PageSize, PROT_READ | PROT_WRITE,
               MAP_SHARED, sharedFD, 0)
        : MAP_FAILED;
    uint32_t *sharedWords = sharedMapping != MAP_FAILED
        ? (uint32_t *)sharedMapping : NULL;

    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLBuffer> sharedBuffer = sharedWords != NULL && device != nil
        ? [device newBufferWithBytesNoCopy:sharedWords
                                   length:CNDE2PageSize
                                  options:MTLResourceStorageModeShared
                              deallocator:nil]
        : nil;
    NSError *libraryError = nil;
    id<MTLLibrary> library = [device newLibraryWithSource:CNDE4ShaderSource
                                                  options:nil
                                                    error:&libraryError];
    NSError *workError = nil;
    NSError *markError = nil;
    id<MTLComputePipelineState> workPipeline = library != nil
        ? [device newComputePipelineStateWithFunction:
            [library newFunctionWithName:@"cnd_e4_work"] error:&workError]
        : nil;
    id<MTLComputePipelineState> markPipeline = library != nil
        ? [device newComputePipelineStateWithFunction:
            [library newFunctionWithName:@"cnd_e4_mark"] error:&markError]
        : nil;
    id<MTLBuffer> state = [device
        newBufferWithLength:CNDE4WorkloadThreads * sizeof(uint32_t)
                    options:MTLResourceStorageModeShared];
    if (state.contents != NULL) {
        memset(state.contents, 0x3c,
               CNDE4WorkloadThreads * sizeof(uint32_t));
    }

    id<MTLCommandBuffer> controlCommand = [queue commandBuffer];
    id<MTLComputeCommandEncoder> controlEncoder =
        [controlCommand computeCommandEncoder];
    uint32_t controlMarker = CNDE4ControlMarker;
    bool controlEncoded = false;
    if (controlEncoder != nil && markPipeline != nil && sharedBuffer != nil) {
        [controlEncoder setComputePipelineState:markPipeline];
        [controlEncoder setBuffer:sharedBuffer offset:0 atIndex:0];
        [controlEncoder setBytes:&controlMarker
                          length:sizeof(controlMarker) atIndex:1];
        [controlEncoder dispatchThreads:MTLSizeMake(1, 1, 1)
                   threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        controlEncoded = true;
    }
    if (controlEncoder != nil) {
        [controlEncoder endEncoding];
    }
    if (controlCommand != nil && controlEncoded) {
        [controlCommand commit];
        [controlCommand waitUntilCompleted];
    }
    uint32_t observedControl = 0;
    if (sharedWords != NULL) {
        __sync_synchronize();
        observedControl = __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST);
    }

    id<MTLCommandBuffer> command = [queue commandBuffer];
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    uint32_t rounds = CNDE4WorkloadRounds;
    uint32_t terminalMarker = CNDE4TerminalMarker;
    bool workloadEncoded = false;
    if (encoder != nil && workPipeline != nil && markPipeline != nil &&
        state != nil && sharedBuffer != nil) {
        [encoder setComputePipelineState:workPipeline];
        [encoder setBuffer:state offset:0 atIndex:0];
        [encoder setBytes:&rounds length:sizeof(rounds) atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(CNDE4WorkloadThreads, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(CNDE4WorkloadThreads, 1, 1)];
        [encoder setComputePipelineState:markPipeline];
        [encoder setBuffer:sharedBuffer offset:0 atIndex:0];
        [encoder setBytes:&terminalMarker
                   length:sizeof(terminalMarker) atIndex:1];
        [encoder dispatchThreads:MTLSizeMake(1, 1, 1)
               threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
        workloadEncoded = true;
    }
    if (encoder != nil) {
        [encoder endEncoding];
    }

    bool prepared = containerURL != nil && fileURL != nil &&
        identityPassed && sharedWords != NULL &&
        device != nil && queue != nil && sharedBuffer != nil && library != nil &&
        workPipeline != nil && markPipeline != nil && state != nil &&
        state.contents != NULL && controlCommand != nil && controlEncoded &&
        controlCommand.status == MTLCommandBufferStatusCompleted &&
        controlCommand.error == nil && observedControl == CNDE4ControlMarker &&
        command != nil && encoder != nil && workloadEncoded;
    CNDE2Message ready = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Ready,
        .result = prepared ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)controlCommand.status,
        .fillVerified = prepared ? 1U : 0U,
        .mode = CNDE4InflightMode,
        .gpuAddress = (uint64_t)sharedStat.st_dev,
        .secondaryGPUAddress = (uint64_t)sharedStat.st_ino,
        .surfaceID = 0,
        .workloadRounds = rounds,
        .markerValue = observedControl,
    };
    memcpy(ready.token, gToken, sizeof(ready.token));
    bool announced = CNDE2WriteAll(fd, &ready, sizeof(ready));
    fprintf(stderr,
            "[E4_HELPER] ready pid=%d file=%s dev=0x%llx inode=0x%llx size=%lld mapped=%d buffer=%d control=0x%08x status=%u prepared=%d announced=%d libError=%s workError=%s markError=%s\n",
            getpid(), fileName.UTF8String,
            (unsigned long long)sharedStat.st_dev,
            (unsigned long long)sharedStat.st_ino,
            (long long)sharedStat.st_size, sharedWords != NULL,
            sharedBuffer != nil,
            observedControl, ready.metalStatus, prepared, announced,
            libraryError.localizedDescription.UTF8String ?: "none",
            workError.localizedDescription.UTF8String ?: "none",
            markError.localizedDescription.UTF8String ?: "none");
    fflush(stderr);
    if (!prepared || !announced) {
        if (sharedMapping != MAP_FAILED) {
            (void)munmap(sharedMapping, CNDE2PageSize);
        }
        if (sharedFD >= 0) close(sharedFD);
        close(fd);
        _exit(76);
    }

    if (!CNDE2ReadControlByte(fd, CNDE2SubmitByte, "inflight-submit")) {
        (void)munmap(sharedMapping, CNDE2PageSize);
        close(sharedFD);
        close(fd);
        _exit(77);
    }
    [command commit];
    [command waitUntilScheduled];
    CNDE2Message exiting = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Exiting,
        .result = command.error == nil ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)command.status,
        .fillVerified = 1,
        .mode = CNDE4InflightMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .surfaceID = 0,
        .workloadRounds = rounds,
        .markerValue = terminalMarker,
    };
    memcpy(exiting.token, gToken, sizeof(exiting.token));
    bool exitAnnounced = CNDE2WriteAll(fd, &exiting, sizeof(exiting));
    fprintf(stderr,
            "[E4_HELPER] exiting pid=%d file=%s dev=0x%llx inode=0x%llx status=%u terminal=0x%08x announced=%d with Metal owners live\n",
            getpid(), fileName.UTF8String,
            (unsigned long long)config.fileDevice,
            (unsigned long long)config.fileInode, exiting.metalStatus,
            terminalMarker, exitAnnounced);
    fflush(stderr);
    if (!exitAnnounced) {
        close(fd);
        _exit(78);
    }

    // The command is scheduled but deliberately not waited.  Task exit is the
    // lifecycle edge under observation; the Metal buffer, MAP_SHARED mapping,
    // and file descriptor remain live until the kernel tears down this process.
    _exit(0);
}

enum {
    CNDE5OwnerQueue = 1U << 0,
    CNDE5OwnerSharedBuffer = 1U << 1,
    CNDE5OwnerLibrary = 1U << 2,
    CNDE5OwnerFunction = 1U << 3,
    CNDE5OwnerPipeline = 1U << 4,
    CNDE5OwnerCommand = 1U << 5,
    CNDE5OwnerEncoder = 1U << 6,
    CNDE5OwnerDevice = 1U << 7,
    CNDE5RequiredOwnerMask =
        CNDE5OwnerQueue | CNDE5OwnerSharedBuffer | CNDE5OwnerLibrary |
        CNDE5OwnerFunction | CNDE5OwnerPipeline | CNDE5OwnerCommand |
        CNDE5OwnerEncoder,
    CNDE5RequiredDeviceMask =
        CNDE5OwnerQueue | CNDE5OwnerSharedBuffer | CNDE5OwnerLibrary |
        CNDE5OwnerFunction | CNDE5OwnerPipeline | CNDE5OwnerCommand |
        CNDE5OwnerEncoder | CNDE5OwnerDevice,
    CNDE5RequiredConnectionMask =
        CNDE5OwnerQueue | CNDE5OwnerDevice,
};

@protocol CNDE5PrivateDeviceInit <MTLDevice>
- (instancetype)initWithAcceleratorPort:(io_service_t)acceleratorPort;
- (void)initLimits;
- (void)initFeatureQueries;
- (void)initWorkarounds;
@end

@protocol CNDE5IOGPUConnectionDevice <NSObject>
- (instancetype)initWithAcceleratorPort:(io_service_t)acceleratorPort;
- (void *)deviceRef;
@end

@protocol CNDE5IOGPUCommandQueueInit <NSObject>
- (instancetype)initWithDevice:(id)device
                     descriptor:(MTLCommandQueueDescriptor *)descriptor;
@end

static void CNDE5RunOwnerReleaseAction(int fd)
{
    bool releaseDevice = gMode == CNDE5DeviceReleaseMode;
    bool releaseConnection = gMode == CNDE5ConnectionReleaseMode;
    bool releasePrivateOwner = releaseDevice || releaseConnection;
    uint32_t expectedMode = releaseConnection
        ? CNDE5ConnectionReleaseMode
        : (releaseDevice ? CNDE5DeviceReleaseMode : CNDE5OwnerReleaseMode);
    uint32_t releaseMarker = releaseConnection
        ? CNDE5ConnectionReleaseMarker
        : (releaseDevice ? CNDE5DeviceReleaseMarker : CNDE5ReleaseMarker);
    uint32_t controlMarker = releaseConnection
        ? CNDE5ConnectionControlMarker
        : (releaseDevice ? CNDE5DeviceControlMarker : CNDE4ControlMarker);
    uint32_t requiredOwnerMask = releaseConnection
        ? CNDE5RequiredConnectionMask
        : (releaseDevice ? CNDE5RequiredDeviceMask : CNDE5RequiredOwnerMask);
    const char *modeName = releaseConnection
        ? "connection-release" : (releaseDevice
            ? "device-release" : "owner-release");
    CNDE4Config config = {0};
    bool configRead = CNDE2ReadAll(fd, &config, sizeof(config));
    bool configPassed = configRead &&
        config.magic == CNDE4ConfigMagic &&
        config.version == CNDE4ConfigVersion &&
        config.controlMarker == controlMarker &&
        config.terminalMarker == releaseMarker &&
        config.workloadRounds == 0 && config.reserved == 0 &&
        config.fileDevice != 0 && config.fileInode != 0 &&
        memcmp(config.token, gToken, sizeof(gToken)) == 0;
    if (!configPassed) {
        fprintf(stderr,
                "[E5_HELPER] config failed pid=%d read=%d magic=0x%08x version=%u dev=0x%llx inode=0x%llx\n",
                getpid(), configRead, config.magic, config.version,
                (unsigned long long)config.fileDevice,
                (unsigned long long)config.fileInode);
        fflush(stderr);
        close(fd);
        _exit(79);
    }

    char tokenHex[CNDE2TokenBytes * 2 + 1] = {0};
    CNDE4TokenHex(tokenHex);
    NSString *fileName = [NSString stringWithFormat:
        releaseConnection ? @"e5c-%s.bin" :
            (releaseDevice ? @"e5d-%s.bin" : @"e5-%s.bin"), tokenHex];
    NSURL *containerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDE4AppGroupIdentifier];
    NSURL *fileURL = containerURL != nil
        ? [containerURL URLByAppendingPathComponent:fileName isDirectory:NO]
        : nil;
    int sharedFD = fileURL != nil
        ? open(fileURL.fileSystemRepresentation, O_RDWR | O_CLOEXEC) : -1;
    struct stat sharedStat = {0};
    bool identityPassed = sharedFD >= 0 && fstat(sharedFD, &sharedStat) == 0 &&
        S_ISREG(sharedStat.st_mode) && sharedStat.st_size == CNDE2PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev == config.fileDevice &&
        (uint64_t)sharedStat.st_ino == config.fileInode;
    void *sharedMapping = identityPassed
        ? mmap(NULL, CNDE2PageSize, PROT_READ | PROT_WRITE,
               MAP_SHARED, sharedFD, 0)
        : MAP_FAILED;
    volatile uint32_t *sharedWords = sharedMapping != MAP_FAILED
        ? (volatile uint32_t *)sharedMapping : NULL;

    __weak id weakDevice = nil;
    __weak id<MTLDevice> weakBootstrapDevice = nil;
    __weak id<MTLCommandQueue> weakQueue = nil;
    __weak id<MTLBuffer> weakSharedBuffer = nil;
    __weak id<MTLLibrary> weakLibrary = nil;
    __weak id<MTLFunction> weakFunction = nil;
    __weak id<MTLComputePipelineState> weakPipeline = nil;
    __weak id<MTLCommandBuffer> weakCommand = nil;
    __weak id<MTLComputeCommandEncoder> weakEncoder = nil;
    uint32_t controlStatus = 0;
    bool readyAnnounced = false;
    bool prepared = false;
    bool acceleratorFound = false;
    bool privateDeviceClassPassed = false;
    bool privateDeviceFactoryFinalized = false;
    bool privateDeviceCleanupLayoutPassed = false;
    bool privateDeviceCleanupCancelled = false;
    bool privateDeviceCleanupHandlerReplaced = false;
    bool privateDeviceCleanupRequested = false;
    uint32_t privateDeviceCleanupCancelPolls = 0;
    bool privateDeviceArrayChecked = false;
    bool privateDeviceInGlobalArray = false;
    uint32_t globalDeviceArrayCount = 0;
    bool connectionDeviceClassPassed = false;
    bool connectionDeviceRefPassed = false;
    bool connectionQueueClassPassed = false;
    bool workCompletionPassed = true;
    id deviceReleaseOwner = nil;

    @autoreleasepool {
        id device = nil;
        id<MTLDevice> bootstrapDevice = nil;
        MTLCommandQueueDescriptor *connectionQueueDescriptor = nil;
        if (releasePrivateOwner) {
            // MTLCreateSystemDefaultDevice loads the target AGX plug-in, but
            // the returned principal device is not used for this context. A
            // separately allocated exact concrete device owns the connection
            // being measured and can reach its real dealloc while the process
            // and framework singleton remain alive.
            bootstrapDevice = MTLCreateSystemDefaultDevice();
            weakBootstrapDevice = bootstrapDevice;
            Class connectionBaseClass = releaseConnection
                ? NSClassFromString(@"IOGPUMetalDevice") : Nil;
            Protocol *deviceSPI = releaseConnection
                ? NSProtocolFromString(@"MTLDeviceSPI") : nil;
            Class deviceClass = Nil;
            if (releaseConnection && connectionBaseClass != Nil &&
                deviceSPI != nil) {
                deviceClass = objc_lookUpClass(
                    "CNDE5IOGPUConnectionDevice");
                if (deviceClass == Nil) {
                    deviceClass = objc_allocateClassPair(
                        connectionBaseClass,
                        "CNDE5IOGPUConnectionDevice", 0);
                    if (deviceClass != Nil &&
                        !class_addProtocol(deviceClass, deviceSPI)) {
                        objc_disposeClassPair(deviceClass);
                        deviceClass = Nil;
                    }
                    if (deviceClass != Nil) {
                        objc_registerClassPair(deviceClass);
                    }
                }
            } else if (!releaseConnection) {
                deviceClass = NSClassFromString(@"AGXG17PDevice");
            }
            privateDeviceClassPassed = !releaseConnection &&
                bootstrapDevice != nil && deviceClass != Nil &&
                [NSStringFromClass(deviceClass) isEqualToString:
                    @"AGXG17PDevice"];
            connectionDeviceClassPassed = releaseConnection &&
                bootstrapDevice != nil && deviceClass != Nil &&
                [NSStringFromClass(deviceClass) isEqualToString:
                    @"CNDE5IOGPUConnectionDevice"] &&
                class_getSuperclass(deviceClass) == connectionBaseClass &&
                class_conformsToProtocol(deviceClass, deviceSPI) &&
                [deviceClass instancesRespondToSelector:
                    @selector(initWithAcceleratorPort:)] &&
                [deviceClass instancesRespondToSelector:@selector(deviceRef)];
            io_service_t accelerator = IOServiceGetMatchingService(
                kIOMainPortDefault,
                IOServiceMatching("AGXAcceleratorG17P"));
            acceleratorFound = accelerator != IO_OBJECT_NULL;
            if ((privateDeviceClassPassed || connectionDeviceClassPassed) &&
                acceleratorFound) {
                if (releaseConnection) {
                    device = [(id<CNDE5IOGPUConnectionDevice>)[deviceClass alloc]
                        initWithAcceleratorPort:accelerator];
                    connectionDeviceRefPassed = device != nil &&
                        [(id<CNDE5IOGPUConnectionDevice>)device deviceRef] != NULL;
                } else {
                    device = [(id<CNDE5PrivateDeviceInit>)[deviceClass alloc]
                        initWithAcceleratorPort:accelerator];
                }
                bool finalizersPassed = device != nil &&
                    !releaseConnection &&
                    [device respondsToSelector:@selector(initLimits)] &&
                    [device respondsToSelector:@selector(initFeatureQueries)] &&
                    [device respondsToSelector:@selector(initWorkarounds)];
                if (finalizersPassed) {
                    // This is the exact pre-insertion sequence in 23A341's
                    // exported MTLAddDevice. Deliberately omit only its final
                    // global-array insertion, which would retain the private
                    // device and invalidate this lifetime experiment.
                    [(id<CNDE5PrivateDeviceInit>)device initLimits];
                    [(id<CNDE5PrivateDeviceInit>)device initFeatureQueries];
                    [(id<CNDE5PrivateDeviceInit>)device initWorkarounds];
                    privateDeviceFactoryFinalized = true;
                }
                Ivar cleanupSourceIvar = class_getInstanceVariable(
                    deviceClass, "_device_pool_cleanup_source");
                Ivar cleanupLockIvar = class_getInstanceVariable(
                    deviceClass, "_device_pool_cleanup_lock");
                Ivar cleanupScheduledIvar = class_getInstanceVariable(
                    deviceClass, "_device_pool_cleanup_scheduled");
                Ivar cleanupRequestedIvar = class_getInstanceVariable(
                    deviceClass, "_device_pool_cleanup_requested");
                privateDeviceCleanupLayoutPassed = device != nil &&
                    !releaseConnection && cleanupSourceIvar != NULL &&
                    cleanupLockIvar != NULL && cleanupScheduledIvar != NULL &&
                    cleanupRequestedIvar != NULL &&
                    strcmp(ivar_getTypeEncoding(cleanupSourceIvar),
                           "@\"NSObject<OS_dispatch_source>\"") == 0 &&
                    ivar_getOffset(cleanupSourceIvar) ==
                        CNDE5CleanupSourceOffset &&
                    ivar_getOffset(cleanupLockIvar) ==
                        CNDE5CleanupLockOffset &&
                    ivar_getOffset(cleanupScheduledIvar) ==
                        CNDE5CleanupScheduledOffset &&
                    ivar_getOffset(cleanupRequestedIvar) ==
                        CNDE5CleanupRequestedOffset;
            }
            if (accelerator != IO_OBJECT_NULL) {
                IOObjectRelease(accelerator);
                accelerator = IO_OBJECT_NULL;
            }
            if (releaseDevice && device != nil) {
                privateDeviceInGlobalArray =
                    CNDE5GlobalDeviceArrayContainsPrivateDevice(
                        device, &privateDeviceArrayChecked,
                        &globalDeviceArrayCount);
            }
        } else {
            device = MTLCreateSystemDefaultDevice();
        }
        id<MTLCommandQueue> queue = nil;
        if (releaseConnection) {
            Class queueClass = NSClassFromString(@"IOGPUMetalCommandQueue");
            connectionQueueClassPassed = queueClass != Nil &&
                [NSStringFromClass(queueClass) isEqualToString:
                    @"IOGPUMetalCommandQueue"] &&
                [queueClass instancesRespondToSelector:
                    @selector(initWithDevice:descriptor:)];
            if (connectionQueueClassPassed) {
                connectionQueueDescriptor =
                    [[MTLCommandQueueDescriptor alloc] init];
                queue = [(id<CNDE5IOGPUCommandQueueInit>)[queueClass alloc]
                    initWithDevice:device
                         descriptor:connectionQueueDescriptor];
            }
        } else {
            queue = [(id<MTLDevice>)device newCommandQueue];
        }
        id<MTLBuffer> sharedBuffer = !releaseConnection &&
            sharedWords != NULL && device != nil
            ? [(id<MTLDevice>)device newBufferWithBytesNoCopy:(void *)sharedWords
                                       length:CNDE2PageSize
                                      options:MTLResourceStorageModeShared
                                  deallocator:nil]
            : nil;
        NSError *libraryError = nil;
        id<MTLLibrary> library = nil;
        id<MTLFunction> markFunction = nil;
        NSError *pipelineError = nil;
        id<MTLComputePipelineState> pipeline = nil;
        bool controlPhasePassed = releaseConnection;
        uint32_t observedControl = 0;
        if (!releaseConnection) {
            library = [(id<MTLDevice>)device newLibraryWithSource:CNDE4ShaderSource
                                            options:nil
                                              error:&libraryError];
            // The completed marker command is only a control.  Keep a second,
            // deliberately long command scheduled while the observer takes its
            // TTBAT snapshot; otherwise waitUntilCompleted retires a transient
            // root before the rendezvous can observe it.
            @autoreleasepool {
                id<MTLFunction> controlFunction = releaseDevice
                    ? nil : [library newFunctionWithName:@"cnd_e4_mark"];
                NSError *controlPipelineError = nil;
                id<MTLComputePipelineState> controlPipeline =
                    !releaseDevice && controlFunction != nil
                    ? [(id<MTLDevice>)device
                        newComputePipelineStateWithFunction:controlFunction
                                                     error:&controlPipelineError]
                    : nil;
                id<MTLCommandBuffer> controlCommand = [queue commandBuffer];
                id controlEncoder = releaseDevice
                    ? (id)[controlCommand blitCommandEncoder]
                    : (id)[controlCommand computeCommandEncoder];
                bool controlEncoded = false;
                if (releaseDevice && controlEncoder != nil &&
                    sharedBuffer != nil) {
                    [(id<MTLBlitCommandEncoder>)controlEncoder
                        fillBuffer:sharedBuffer
                             range:NSMakeRange(0, sizeof(controlMarker))
                             value:(uint8_t)controlMarker];
                    controlEncoded = true;
                } else if (!releaseDevice && controlEncoder != nil &&
                    controlPipeline != nil && sharedBuffer != nil) {
                    [(id<MTLComputeCommandEncoder>)controlEncoder
                        setComputePipelineState:controlPipeline];
                    [(id<MTLComputeCommandEncoder>)controlEncoder
                        setBuffer:sharedBuffer offset:0 atIndex:0];
                    [(id<MTLComputeCommandEncoder>)controlEncoder
                        setBytes:&controlMarker
                          length:sizeof(controlMarker) atIndex:1];
                    [(id<MTLComputeCommandEncoder>)controlEncoder
                        dispatchThreads:MTLSizeMake(1, 1, 1)
                        threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
                    controlEncoded = true;
                }
                if (controlEncoder != nil) {
                    [(id<MTLCommandEncoder>)controlEncoder endEncoding];
                }
                if (controlCommand != nil && controlEncoded) {
                    [controlCommand commit];
                    [controlCommand waitUntilCompleted];
                }
                observedControl = sharedWords != NULL
                    ? __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST) : 0;
                controlPhasePassed = controlEncoded &&
                    (releaseDevice ||
                        (controlFunction != nil && controlPipeline != nil)) &&
                    controlCommand != nil && controlEncoder != nil &&
                    controlCommand.status == MTLCommandBufferStatusCompleted &&
                    controlCommand.error == nil &&
                    observedControl == controlMarker;
                (void)controlPipelineError;
            }
            markFunction = [library newFunctionWithName:@"cnd_e4_work"];
            pipeline = markFunction != nil
                ? [(id<MTLDevice>)device newComputePipelineStateWithFunction:markFunction
                                                        error:&pipelineError]
                : nil;
        }
        id<MTLCommandBuffer> command = releaseConnection
            ? nil : [queue commandBuffer];
        id encoder = releaseConnection
            ? nil : (id)[command computeCommandEncoder];
        bool encoded = false;
        if (releaseConnection) {
            if (sharedWords != NULL) {
                __atomic_store_n(sharedWords, controlMarker, __ATOMIC_SEQ_CST);
                (void)msync(sharedMapping, CNDE2PageSize, MS_SYNC);
                encoded = true;
            }
        } else if (encoder != nil && pipeline != nil && sharedBuffer != nil) {
            uint32_t rounds = CNDE4WorkloadRounds;
            [(id<MTLComputeCommandEncoder>)encoder
                setComputePipelineState:pipeline];
            [(id<MTLComputeCommandEncoder>)encoder
                setBuffer:sharedBuffer offset:0x100 atIndex:0];
            [(id<MTLComputeCommandEncoder>)encoder
                setBytes:&rounds length:sizeof(rounds) atIndex:1];
            [(id<MTLComputeCommandEncoder>)encoder
                dispatchThreads:MTLSizeMake(CNDE4WorkloadThreads, 1, 1)
                threadsPerThreadgroup:
                    MTLSizeMake(CNDE4WorkloadThreads, 1, 1)];
            encoded = true;
        }
        if (encoder != nil) [(id<MTLCommandEncoder>)encoder endEncoding];
        if (command != nil && encoded) {
            [command commit];
            [command waitUntilScheduled];
        }
        if (releaseConnection) {
            observedControl = sharedWords != NULL
                ? __atomic_load_n(sharedWords, __ATOMIC_SEQ_CST) : 0;
        }
        bool graphPassed = releaseConnection
            ? (connectionDeviceRefPassed && encoded)
            : (controlPhasePassed && library != nil && markFunction != nil &&
               pipeline != nil && command != nil && encoder != nil && encoded);
        prepared = containerURL != nil && fileURL != nil && identityPassed &&
            sharedWords != NULL && device != nil && graphPassed &&
            observedControl == controlMarker;
        if (!releaseConnection) {
            prepared = prepared && queue != nil && sharedBuffer != nil &&
                command.error == nil &&
                command.status == MTLCommandBufferStatusScheduled;
        }
        if (releaseDevice) {
            prepared = prepared && acceleratorFound &&
                privateDeviceClassPassed && privateDeviceFactoryFinalized &&
                privateDeviceCleanupLayoutPassed &&
                privateDeviceArrayChecked &&
                [NSStringFromClass([device class]) isEqualToString:
                    @"AGXG17PDevice"];
        }
        if (releaseConnection) {
            prepared = prepared && queue != nil &&
                connectionQueueClassPassed && acceleratorFound &&
                connectionDeviceClassPassed && connectionDeviceRefPassed &&
                [NSStringFromClass([device class]) isEqualToString:
                    @"CNDE5IOGPUConnectionDevice"];
        }
        controlStatus = releaseConnection ? 0U :
            (uint32_t)MTLCommandBufferStatusCompleted;

        weakDevice = device;
        weakQueue = queue;
        weakSharedBuffer = sharedBuffer;
        weakLibrary = library;
        weakFunction = markFunction;
        weakPipeline = pipeline;
        weakCommand = command;
        weakEncoder = encoder;

        CNDE2Message ready = {
            .magic = CNDE2Magic,
            .version = CNDE2Version,
            .type = CNDE2Ready,
            .result = prepared ? 0 : 1,
            .pid = (uint32_t)getpid(),
            .metalStatus = controlStatus,
            .fillVerified = prepared ? 1U : 0U,
            .mode = expectedMode,
            .gpuAddress = config.fileDevice,
            .secondaryGPUAddress = config.fileInode,
            .primaryPatternBytes = privateDeviceArrayChecked ?
                (privateDeviceInGlobalArray ? 3U : 1U) : 0U,
            .secondaryPatternBytes = globalDeviceArrayCount,
            .surfaceID = 0,
            .workloadRounds = releaseConnection
                ? 0U : CNDE4WorkloadRounds,
            .markerValue = observedControl,
            .reserved = (privateDeviceFactoryFinalized ||
                         connectionDeviceRefPassed) ? 1U : 0U,
        };
        memcpy(ready.token, gToken, sizeof(ready.token));
        readyAnnounced = CNDE2WriteAll(fd, &ready, sizeof(ready));
        fprintf(stderr,
                "[E5_HELPER] ready pid=%d mode=%s file=%s control=0x%08x status=%u workStatus=%u controlPhase=%d rounds=%u prepared=%d announced=%d accelerator=%d privateClass=%d factoryFinalized=%d cleanupLayout=%d globalArrayChecked=%d globalArrayContainsPrivate=%d globalArrayCount=%u connectionClass=%d deviceRef=%d connectionQueueClass=%d libError=%s pipelineError=%s\n",
                getpid(), modeName,
                fileName.UTF8String, observedControl,
                controlStatus,
                command != nil ? (uint32_t)command.status : 0U,
                controlPhasePassed,
                releaseConnection ? 0U : CNDE4WorkloadRounds,
                prepared, readyAnnounced,
                acceleratorFound, privateDeviceClassPassed,
                privateDeviceFactoryFinalized,
                privateDeviceCleanupLayoutPassed,
                privateDeviceArrayChecked,
                privateDeviceInGlobalArray,
                globalDeviceArrayCount,
                connectionDeviceClassPassed, connectionDeviceRefPassed,
                connectionQueueClassPassed,
                libraryError.localizedDescription.UTF8String ?: "none",
                pipelineError.localizedDescription.UTF8String ?: "none");
        fflush(stderr);
        if (!prepared || !readyAnnounced ||
            !CNDE2ReadControlByte(
                fd, CNDE2SubmitByte,
                modeName)) {
            if (sharedMapping != MAP_FAILED) {
                (void)munmap(sharedMapping, CNDE2PageSize);
            }
            if (sharedFD >= 0) close(sharedFD);
            close(fd);
            _exit(80);
        }

        if (!releaseConnection) {
            [command waitUntilCompleted];
            workCompletionPassed =
                command.status == MTLCommandBufferStatusCompleted &&
                command.error == nil;
        }

        // ARC strong locals have imprecise lifetime by default: the compiler
        // may legally keep them alive past the lexical pool edge. Make the
        // named action exact by releasing every graph owner in reverse order,
        // with the measured device released last. The bootstrap singleton is
        // then released only as our local reference; its separate weak witness
        // must remain alive through Metal's process-global ownership.
        encoder = nil;
        command = nil;
        pipeline = nil;
        markFunction = nil;
        library = nil;
        sharedBuffer = nil;
        connectionQueueDescriptor = nil;
        queue = nil;
        // Keep only the private device alive across the pool drain. Command
        // and queue destruction calls kickCleanupQueue, so the cleanup source
        // must remain active until every deferred autorelease has completed.
        if (releaseDevice) deviceReleaseOwner = device;
        device = nil;
        bootstrapDevice = nil;
    }

    if (releaseDevice && privateDeviceCleanupLayoutPassed &&
        deviceReleaseOwner != nil) {
        uint8_t *deviceBytes = (__bridge void *)deviceReleaseOwner;
        os_unfair_lock *cleanupLock = (os_unfair_lock *)(
            deviceBytes + CNDE5CleanupLockOffset);
        __unsafe_unretained dispatch_source_t cleanupSource =
            (__bridge dispatch_source_t)(*(void **)(
                deviceBytes + CNDE5CleanupSourceOffset));
        bool *cleanupScheduled = (bool *)(
            deviceBytes + CNDE5CleanupScheduledOffset);
        bool *cleanupRequested = (bool *)(
            deviceBytes + CNDE5CleanupRequestedOffset);
        for (privateDeviceCleanupCancelPolls = 0;
             privateDeviceCleanupCancelPolls < CNDE5WeakReleasePollLimit;
             privateDeviceCleanupCancelPolls++) {
            os_unfair_lock_lock(cleanupLock);
            privateDeviceCleanupRequested = *cleanupRequested;
            if (!privateDeviceCleanupRequested) {
                if (cleanupSource != nil) {
                    // The source's original handler captures this device
                    // through a strong __block cell. Replace that one
                    // statically proven ownership edge before cancellation;
                    // otherwise the device can never enter its dealloc, which
                    // is where IOGPU normally disposes the source itself.
                    dispatch_source_set_event_handler(cleanupSource, ^{});
                    privateDeviceCleanupHandlerReplaced = true;
                    dispatch_source_cancel(cleanupSource);
                    privateDeviceCleanupCancelled = true;
                }
                *cleanupScheduled = false;
            }
            os_unfair_lock_unlock(cleanupLock);
            if (privateDeviceCleanupCancelled || cleanupSource == nil) break;
            usleep(CNDE5WeakReleasePollIntervalUS);
        }
        cleanupSource = nil;
    }
    deviceReleaseOwner = nil;

    // The explicit reverse-order strong releases above are the named action.
    // Only weak witnesses remain for the helper-owned Metal graph. In the
    // owner-only branch the system MTLDevice is recorded separately because
    // Metal may retain it process-globally. In the private-device branch its
    // weak release is required as bit 7.
    // Completion and Objective-C destruction can hand the final device retain
    // to an internal driver queue.  Give that already-triggered teardown a
    // bounded three-second window to drain before classifying the device as a
    // persistent owner.  This loop has no Metal calls and touches only weak
    // userland witnesses; it cannot create or close a kernel connection.
    uint32_t deviceReleasePolls = 0;
    if (releasePrivateOwner) {
        while (deviceReleasePolls < CNDE5WeakReleasePollLimit) {
            bool released = false;
            @autoreleasepool {
                released = weakDevice == nil;
            }
            if (released) break;
            deviceReleasePolls++;
            usleep(CNDE5WeakReleasePollIntervalUS);
        }
    }

    uint32_t releasedMask = 0;
    if (weakQueue == nil) releasedMask |= CNDE5OwnerQueue;
    if (!releaseConnection && weakSharedBuffer == nil) {
        releasedMask |= CNDE5OwnerSharedBuffer;
    }
    if (!releaseConnection && weakLibrary == nil) releasedMask |= CNDE5OwnerLibrary;
    if (!releaseConnection && weakFunction == nil) releasedMask |= CNDE5OwnerFunction;
    if (!releaseConnection && weakPipeline == nil) releasedMask |= CNDE5OwnerPipeline;
    if (!releaseConnection && weakCommand == nil) {
        releasedMask |= CNDE5OwnerCommand;
    }
    if (!releaseConnection && weakEncoder == nil) {
        releasedMask |= CNDE5OwnerEncoder;
    }
    bool deviceStillAlive = weakDevice != nil;
    if (!deviceStillAlive) releasedMask |= CNDE5OwnerDevice;
    bool systemDeviceStillAlive = releasePrivateOwner
        ? weakBootstrapDevice != nil : deviceStillAlive;
    bool ownersReleased =
        releasedMask == requiredOwnerMask && workCompletionPassed;
    if (sharedWords != NULL) {
        __atomic_store_n(sharedWords, releaseMarker, __ATOMIC_SEQ_CST);
        (void)msync(sharedMapping, CNDE2PageSize, MS_SYNC);
    }

    CNDE2Message drained = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Exiting,
        .result = ownersReleased ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = controlStatus,
        .fillVerified = ownersReleased ? 1U : 0U,
        .mode = expectedMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .primaryPatternBytes = releasedMask,
        .secondaryPatternBytes = requiredOwnerMask,
        .surfaceID = deviceStillAlive ? 1U : 0U,
        .workloadRounds = releaseConnection
            ? 0U : CNDE4WorkloadRounds,
        .markerValue = releaseMarker,
        .reserved = systemDeviceStillAlive ? 1U : 0U,
    };
    memcpy(drained.token, gToken, sizeof(drained.token));
    bool drainAnnounced = CNDE2WriteAll(fd, &drained, sizeof(drained));
    fprintf(stderr,
            "[E5_HELPER] owners-drained pid=%d mode=%s releasedMask=0x%08x requiredMask=0x%08x workCompletion=%d deviceStillAlive=%d systemDeviceStillAlive=%d cleanupHandlerReplaced=%d cleanupCancelled=%d cleanupRequested=%d cleanupCancelPolls=%u deviceReleasePolls=%u marker=0x%08x announced=%d\n",
            getpid(), modeName,
            releasedMask, requiredOwnerMask, workCompletionPassed,
            deviceStillAlive, systemDeviceStillAlive,
            privateDeviceCleanupHandlerReplaced,
            privateDeviceCleanupCancelled, privateDeviceCleanupRequested,
            privateDeviceCleanupCancelPolls, deviceReleasePolls,
            releaseMarker, drainAnnounced);
    fflush(stderr);
    if (!ownersReleased || !systemDeviceStillAlive || !drainAnnounced ||
        !CNDE2ReadControlByte(fd, CNDE2ReleaseByte, "cleanup-release")) {
        close(fd);
        _exit(81);
    }

    CNDE2Message completed = drained;
    completed.type = CNDE2Completed;
    bool completedAnnounced = CNDE2WriteAll(fd, &completed, sizeof(completed));
    fprintf(stderr,
            "[E5_HELPER] cleanup-exit pid=%d completedAnnounced=%d\n",
            getpid(), completedAnnounced);
    fflush(stderr);
    if (sharedMapping != MAP_FAILED) (void)munmap(sharedMapping, CNDE2PageSize);
    if (sharedFD >= 0) close(sharedFD);
    close(fd);
    _exit(completedAnnounced ? 0 : 82);
}

static void CNDE5RunRawQueueBindReleaseAction(int fd)
{
    CNDE4Config config = {0};
    bool configRead = CNDE2ReadAll(fd, &config, sizeof(config));
    bool configPassed = configRead &&
        config.magic == CNDE4ConfigMagic &&
        config.version == CNDE4ConfigVersion &&
        config.controlMarker == CNDE5RawQueueBindControlMarker &&
        config.terminalMarker == CNDE5RawQueueBindReleaseMarker &&
        config.workloadRounds == 0 && config.reserved == 0 &&
        config.fileDevice != 0 && config.fileInode != 0 &&
        memcmp(config.token, gToken, sizeof(gToken)) == 0;
    if (!configPassed) {
        fprintf(stderr,
                "[E5_HELPER] raw-queue-bind config failed pid=%d read=%d magic=0x%08x version=%u\n",
                getpid(), configRead, config.magic, config.version);
        fflush(stderr);
        close(fd);
        _exit(87);
    }

    char tokenHex[CNDE2TokenBytes * 2 + 1] = {0};
    CNDE4TokenHex(tokenHex);
    NSString *fileName = [NSString stringWithFormat:
        @"e5b-%s.bin", tokenHex];
    NSURL *containerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDE4AppGroupIdentifier];
    NSURL *fileURL = containerURL != nil
        ? [containerURL URLByAppendingPathComponent:fileName isDirectory:NO]
        : nil;
    int sharedFD = fileURL != nil
        ? open(fileURL.fileSystemRepresentation, O_RDWR | O_CLOEXEC) : -1;
    struct stat sharedStat = {0};
    bool identityPassed = sharedFD >= 0 && fstat(sharedFD, &sharedStat) == 0 &&
        S_ISREG(sharedStat.st_mode) && sharedStat.st_size == CNDE2PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev == config.fileDevice &&
        (uint64_t)sharedStat.st_ino == config.fileInode;
    void *sharedMapping = identityPassed
        ? mmap(NULL, CNDE2PageSize, PROT_READ | PROT_WRITE,
               MAP_SHARED, sharedFD, 0)
        : MAP_FAILED;
    volatile uint32_t *sharedWords = sharedMapping != MAP_FAILED
        ? (volatile uint32_t *)sharedMapping : NULL;

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AGXAcceleratorG17P"));
    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t openKR = service != IO_OBJECT_NULL
        ? IOServiceOpen(service, mach_task_self(), 1, &connection)
        : KERN_FAILURE;
    if (service != IO_OBJECT_NULL) IOObjectRelease(service);

    uint64_t createScalars[2] = {0, 0};
    uint64_t createOutput[2] = {0, 0};
    uint32_t createOutputCount = 2;
    kern_return_t createKR = connection != IO_OBJECT_NULL &&
        sharedWords != NULL && openKR == KERN_SUCCESS
        ? IOConnectCallMethod(connection, 42,
            createScalars, 2, NULL, 0,
            createOutput, &createOutputCount, NULL, NULL)
        : KERN_FAILURE;
    uint32_t queueID = createKR == KERN_SUCCESS && createOutputCount == 2
        ? (uint32_t)createOutput[0] : 0;

    // IOGPUNotificationQueueCreate is pinned to selector 14 with the exact
    // scalar pair used by IOGPUCommandQueueCreate: 0x100 entries of size 0x28.
    // Its second 64-bit structure-output word is the ID returned by
    // IOGPUNotificationQueueGetID and used as both the notification-port
    // reference and selector-44's table key.
    uint64_t notificationScalars[2] = {0x100, 0x28};
    uint64_t notificationOutput[2] = {0, 0};
    size_t notificationOutputSize = sizeof(notificationOutput);
    kern_return_t notificationCreateKR = queueID != 0
        ? IOConnectCallMethod(connection, 14,
            notificationScalars, 2, NULL, 0,
            NULL, NULL, notificationOutput, &notificationOutputSize)
        : KERN_FAILURE;
    uint32_t notificationID = notificationCreateKR == KERN_SUCCESS &&
        notificationOutputSize == sizeof(notificationOutput)
        ? (uint32_t)notificationOutput[1] : 0;
    mach_port_t notificationPort = notificationID != 0
        ? IODataQueueAllocateNotificationPort() : MACH_PORT_NULL;
    kern_return_t notificationPortKR = notificationPort != MACH_PORT_NULL
        ? IOConnectSetNotificationPort(
            connection, 0, notificationPort, notificationID)
        : KERN_FAILURE;

    uint64_t bindScalars[2] = {queueID, notificationID};
    kern_return_t bindKR = notificationPortKR == KERN_SUCCESS
        ? IOConnectCallMethod(connection, 44,
            bindScalars, 2, NULL, 0, NULL, NULL, NULL, NULL)
        : KERN_FAILURE;

    // Selector 45's count-zero shape is a pinned binding oracle: the handler
    // returns success only after queue+0x78 and queue+0x28 are non-NULL. The
    // structure buffer is calloc-backed per the physical transport rule.
    uint8_t *zeroSubmit = bindKR == KERN_SUCCESS
        ? calloc(1, 8) : NULL;
    uint64_t submitScalar = queueID;
    kern_return_t zeroSubmitKR = zeroSubmit != NULL
        ? IOConnectCallMethod(connection, 45,
            &submitScalar, 1, zeroSubmit, 8,
            NULL, NULL, NULL, NULL)
        : KERN_FAILURE;
    free(zeroSubmit);

    bool prepared = identityPassed && sharedWords != NULL &&
        openKR == KERN_SUCCESS && connection != IO_OBJECT_NULL &&
        createKR == KERN_SUCCESS && createOutputCount == 2 && queueID != 0 &&
        notificationCreateKR == KERN_SUCCESS &&
        notificationOutputSize == sizeof(notificationOutput) &&
        notificationID != 0 &&
        notificationPort != MACH_PORT_NULL &&
        notificationPortKR == KERN_SUCCESS && bindKR == KERN_SUCCESS &&
        zeroSubmitKR == KERN_SUCCESS;
    if (prepared) {
        __atomic_store_n(sharedWords, CNDE5RawQueueBindControlMarker,
                         __ATOMIC_SEQ_CST);
        prepared = msync(sharedMapping, CNDE2PageSize, MS_SYNC) == 0;
    }

    CNDE2Message ready = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Ready,
        .result = prepared ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)zeroSubmitKR,
        .fillVerified = prepared ? 1U : 0U,
        .mode = CNDE5RawQueueBindReleaseMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .primaryPatternBytes = queueID,
        .secondaryPatternBytes = notificationID,
        .surfaceID = queueID,
        .workloadRounds = 0,
        .markerValue = prepared ? CNDE5RawQueueBindControlMarker : 0,
        .reserved = connection != IO_OBJECT_NULL ? 1U : 0U,
    };
    memcpy(ready.token, gToken, sizeof(ready.token));
    bool readyAnnounced = CNDE2WriteAll(fd, &ready, sizeof(ready));
    fprintf(stderr,
            "[E5_HELPER] raw-queue-bind ready pid=%d qid=%u notificationID=%u notificationToken=%llu openKR=0x%x createKR=0x%x notificationCreateKR=0x%x setPortKR=0x%x bindKR=0x%x zeroSubmitKR=0x%x prepared=%d announced=%d\n",
            getpid(), queueID, notificationID,
            (unsigned long long)notificationOutput[0], openKR, createKR,
            notificationCreateKR, notificationPortKR, bindKR, zeroSubmitKR,
            prepared, readyAnnounced);
    fflush(stderr);
    if (!prepared || !readyAnnounced ||
        !CNDE2ReadControlByte(fd, CNDE2SubmitByte,
                             "raw-queue-bind-release")) {
        if (queueID != 0 && connection != IO_OBJECT_NULL) {
            uint64_t destroyScalar = queueID;
            (void)IOConnectCallMethod(connection, 43,
                &destroyScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        }
        if (notificationID != 0 && connection != IO_OBJECT_NULL) {
            uint64_t destroyNotification = notificationID;
            (void)IOConnectCallMethod(connection, 15,
                &destroyNotification, 1, NULL, 0,
                NULL, NULL, NULL, NULL);
        }
        if (notificationPort != MACH_PORT_NULL) {
            (void)mach_port_deallocate(mach_task_self(), notificationPort);
        }
        if (connection != IO_OBJECT_NULL) IOServiceClose(connection);
        if (sharedMapping != MAP_FAILED) {
            (void)munmap(sharedMapping, CNDE2PageSize);
        }
        if (sharedFD >= 0) close(sharedFD);
        close(fd);
        _exit(88);
    }

    uint64_t destroyScalar = queueID;
    kern_return_t destroyKR = IOConnectCallMethod(connection, 43,
        &destroyScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
    bool queueDestroyed = destroyKR == KERN_SUCCESS;
    if (sharedWords != NULL) {
        __atomic_store_n(sharedWords, CNDE5RawQueueBindReleaseMarker,
                         __ATOMIC_SEQ_CST);
        (void)msync(sharedMapping, CNDE2PageSize, MS_SYNC);
    }
    uint32_t releasedMask = queueDestroyed ? CNDE5OwnerQueue : 0;
    CNDE2Message drained = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Exiting,
        .result = queueDestroyed ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)destroyKR,
        .fillVerified = queueDestroyed ? 1U : 0U,
        .mode = CNDE5RawQueueBindReleaseMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .primaryPatternBytes = releasedMask,
        .secondaryPatternBytes = CNDE5OwnerQueue,
        .surfaceID = 0,
        .workloadRounds = 0,
        .markerValue = CNDE5RawQueueBindReleaseMarker,
        .reserved = connection != IO_OBJECT_NULL ? 1U : 0U,
    };
    memcpy(drained.token, gToken, sizeof(drained.token));
    bool drainAnnounced = CNDE2WriteAll(fd, &drained, sizeof(drained));
    fprintf(stderr,
            "[E5_HELPER] raw-queue-bind destroyed pid=%d qid=%u destroyKR=0x%x connectionAlive=%d notificationAlive=%d announced=%d\n",
            getpid(), queueID, destroyKR,
            connection != IO_OBJECT_NULL, notificationID != 0,
            drainAnnounced);
    fflush(stderr);
    if (!queueDestroyed || !drainAnnounced ||
        !CNDE2ReadControlByte(fd, CNDE2ReleaseByte,
                             "raw-queue-bind-cleanup-release")) {
        if (connection != IO_OBJECT_NULL) IOServiceClose(connection);
        close(fd);
        _exit(89);
    }

    kern_return_t notificationDestroyKR = KERN_SUCCESS;
    if (notificationID != 0 && connection != IO_OBJECT_NULL) {
        uint64_t destroyNotification = notificationID;
        notificationDestroyKR = IOConnectCallMethod(connection, 15,
            &destroyNotification, 1, NULL, 0,
            NULL, NULL, NULL, NULL);
    }
    if (notificationPort != MACH_PORT_NULL) {
        (void)mach_port_deallocate(mach_task_self(), notificationPort);
        notificationPort = MACH_PORT_NULL;
    }
    if (connection != IO_OBJECT_NULL) {
        IOServiceClose(connection);
        connection = IO_OBJECT_NULL;
    }
    CNDE2Message completed = drained;
    completed.type = CNDE2Completed;
    completed.result = notificationDestroyKR == KERN_SUCCESS ? 0 : 1;
    completed.reserved = 0;
    bool completedAnnounced = CNDE2WriteAll(fd, &completed, sizeof(completed));
    fprintf(stderr,
            "[E5_HELPER] raw-queue-bind cleanup-exit pid=%d notificationDestroyKR=0x%x connectionClosed=1 completedAnnounced=%d\n",
            getpid(), notificationDestroyKR, completedAnnounced);
    fflush(stderr);
    if (sharedMapping != MAP_FAILED) (void)munmap(sharedMapping, CNDE2PageSize);
    if (sharedFD >= 0) close(sharedFD);
    close(fd);
    _exit(completedAnnounced && notificationDestroyKR == KERN_SUCCESS ? 0 : 90);
}

static void CNDE5RunRawQueueReleaseAction(int fd)
{
    CNDE4Config config = {0};
    bool configRead = CNDE2ReadAll(fd, &config, sizeof(config));
    bool configPassed = configRead &&
        config.magic == CNDE4ConfigMagic &&
        config.version == CNDE4ConfigVersion &&
        config.controlMarker == CNDE5RawQueueControlMarker &&
        config.terminalMarker == CNDE5RawQueueReleaseMarker &&
        config.workloadRounds == 0 && config.reserved == 0 &&
        config.fileDevice != 0 && config.fileInode != 0 &&
        memcmp(config.token, gToken, sizeof(gToken)) == 0;
    if (!configPassed) {
        fprintf(stderr,
                "[E5_HELPER] raw-queue config failed pid=%d read=%d magic=0x%08x version=%u\n",
                getpid(), configRead, config.magic, config.version);
        fflush(stderr);
        close(fd);
        _exit(83);
    }

    char tokenHex[CNDE2TokenBytes * 2 + 1] = {0};
    CNDE4TokenHex(tokenHex);
    NSString *fileName = [NSString stringWithFormat:
        @"e5q-%s.bin", tokenHex];
    NSURL *containerURL = [[NSFileManager defaultManager]
        containerURLForSecurityApplicationGroupIdentifier:
            CNDE4AppGroupIdentifier];
    NSURL *fileURL = containerURL != nil
        ? [containerURL URLByAppendingPathComponent:fileName isDirectory:NO]
        : nil;
    int sharedFD = fileURL != nil
        ? open(fileURL.fileSystemRepresentation, O_RDWR | O_CLOEXEC) : -1;
    struct stat sharedStat = {0};
    bool identityPassed = sharedFD >= 0 && fstat(sharedFD, &sharedStat) == 0 &&
        S_ISREG(sharedStat.st_mode) && sharedStat.st_size == CNDE2PageSize &&
        sharedStat.st_uid == getuid() && sharedStat.st_nlink == 1 &&
        (uint64_t)sharedStat.st_dev == config.fileDevice &&
        (uint64_t)sharedStat.st_ino == config.fileInode;
    void *sharedMapping = identityPassed
        ? mmap(NULL, CNDE2PageSize, PROT_READ | PROT_WRITE,
               MAP_SHARED, sharedFD, 0)
        : MAP_FAILED;
    volatile uint32_t *sharedWords = sharedMapping != MAP_FAILED
        ? (volatile uint32_t *)sharedMapping : NULL;

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("AGXAcceleratorG17P"));
    io_connect_t connection = IO_OBJECT_NULL;
    kern_return_t openKR = service != IO_OBJECT_NULL
        ? IOServiceOpen(service, mach_task_self(), 1, &connection)
        : KERN_FAILURE;
    if (service != IO_OBJECT_NULL) IOObjectRelease(service);

    uint64_t createScalars[2] = {0, 0};
    uint64_t createOutput[2] = {0, 0};
    uint32_t createOutputCount = 2;
    kern_return_t createKR = connection != IO_OBJECT_NULL &&
        sharedWords != NULL && openKR == KERN_SUCCESS
        ? IOConnectCallMethod(connection, 42,
            createScalars, 2, NULL, 0,
            createOutput, &createOutputCount, NULL, NULL)
        : KERN_FAILURE;
    uint32_t queueID = createKR == KERN_SUCCESS && createOutputCount == 2
        ? (uint32_t)createOutput[0] : 0;
    bool prepared = identityPassed && sharedWords != NULL &&
        openKR == KERN_SUCCESS && connection != IO_OBJECT_NULL &&
        createKR == KERN_SUCCESS && createOutputCount == 2 && queueID != 0;
    if (prepared) {
        __atomic_store_n(sharedWords, CNDE5RawQueueControlMarker,
                         __ATOMIC_SEQ_CST);
        prepared = msync(sharedMapping, CNDE2PageSize, MS_SYNC) == 0;
    }

    CNDE2Message ready = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Ready,
        .result = prepared ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)createKR,
        .fillVerified = prepared ? 1U : 0U,
        .mode = CNDE5RawQueueReleaseMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .primaryPatternBytes = queueID,
        .secondaryPatternBytes = (uint32_t)createOutput[1],
        .surfaceID = queueID,
        .workloadRounds = 0,
        .markerValue = prepared ? CNDE5RawQueueControlMarker : 0,
        .reserved = connection != IO_OBJECT_NULL ? 1U : 0U,
    };
    memcpy(ready.token, gToken, sizeof(ready.token));
    bool readyAnnounced = CNDE2WriteAll(fd, &ready, sizeof(ready));
    fprintf(stderr,
            "[E5_HELPER] raw-queue ready pid=%d qid=%u token=%llu openKR=0x%x createKR=0x%x prepared=%d announced=%d\n",
            getpid(), queueID,
            (unsigned long long)createOutput[1], openKR, createKR,
            prepared, readyAnnounced);
    fflush(stderr);
    if (!prepared || !readyAnnounced ||
        !CNDE2ReadControlByte(fd, CNDE2SubmitByte,
                             "raw-queue-release")) {
        if (queueID != 0 && connection != IO_OBJECT_NULL) {
            uint64_t destroyScalar = queueID;
            (void)IOConnectCallMethod(connection, 43,
                &destroyScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        }
        if (connection != IO_OBJECT_NULL) IOServiceClose(connection);
        if (sharedMapping != MAP_FAILED) {
            (void)munmap(sharedMapping, CNDE2PageSize);
        }
        if (sharedFD >= 0) close(sharedFD);
        close(fd);
        _exit(84);
    }

    uint64_t destroyScalar = queueID;
    kern_return_t destroyKR = IOConnectCallMethod(connection, 43,
        &destroyScalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
    bool queueDestroyed = destroyKR == KERN_SUCCESS;
    if (sharedWords != NULL) {
        __atomic_store_n(sharedWords, CNDE5RawQueueReleaseMarker,
                         __ATOMIC_SEQ_CST);
        (void)msync(sharedMapping, CNDE2PageSize, MS_SYNC);
    }
    uint32_t releasedMask = queueDestroyed ? CNDE5OwnerQueue : 0;
    CNDE2Message drained = {
        .magic = CNDE2Magic,
        .version = CNDE2Version,
        .type = CNDE2Exiting,
        .result = queueDestroyed ? 0 : 1,
        .pid = (uint32_t)getpid(),
        .metalStatus = (uint32_t)destroyKR,
        .fillVerified = queueDestroyed ? 1U : 0U,
        .mode = CNDE5RawQueueReleaseMode,
        .gpuAddress = config.fileDevice,
        .secondaryGPUAddress = config.fileInode,
        .primaryPatternBytes = releasedMask,
        .secondaryPatternBytes = CNDE5OwnerQueue,
        .surfaceID = 0,
        .workloadRounds = 0,
        .markerValue = CNDE5RawQueueReleaseMarker,
        .reserved = connection != IO_OBJECT_NULL ? 1U : 0U,
    };
    memcpy(drained.token, gToken, sizeof(drained.token));
    bool drainAnnounced = CNDE2WriteAll(fd, &drained, sizeof(drained));
    fprintf(stderr,
            "[E5_HELPER] raw-queue destroyed pid=%d qid=%u destroyKR=0x%x connectionAlive=%d announced=%d\n",
            getpid(), queueID, destroyKR,
            connection != IO_OBJECT_NULL, drainAnnounced);
    fflush(stderr);
    if (!queueDestroyed || !drainAnnounced ||
        !CNDE2ReadControlByte(fd, CNDE2ReleaseByte,
                             "raw-queue-cleanup-release")) {
        if (connection != IO_OBJECT_NULL) IOServiceClose(connection);
        close(fd);
        _exit(85);
    }

    if (connection != IO_OBJECT_NULL) {
        IOServiceClose(connection);
        connection = IO_OBJECT_NULL;
    }
    CNDE2Message completed = drained;
    completed.type = CNDE2Completed;
    completed.reserved = 0;
    bool completedAnnounced = CNDE2WriteAll(fd, &completed, sizeof(completed));
    fprintf(stderr,
            "[E5_HELPER] raw-queue cleanup-exit pid=%d connectionClosed=1 completedAnnounced=%d\n",
            getpid(), completedAnnounced);
    fflush(stderr);
    if (sharedMapping != MAP_FAILED) (void)munmap(sharedMapping, CNDE2PageSize);
    if (sharedFD >= 0) close(sharedFD);
    close(fd);
    _exit(completedAnnounced ? 0 : 86);
}

static void CNDE2RunAction(void)
{
    @autoreleasepool {
        int fd = CNDE2Connect();
        if (fd < 0) {
            fprintf(stderr, "[E2_HELPER] connect failed errno=%d pid=%d\n",
                    errno, getpid());
            fflush(stderr);
            _exit(68);
        }

        if (gMode == CNDE4InflightMode) {
            CNDE4RunInflightAction(fd);
        }
        if (gMode == CNDE5OwnerReleaseMode) {
            CNDE5RunOwnerReleaseAction(fd);
        }
        if (gMode == CNDE5DeviceReleaseMode) {
            CNDE5RunOwnerReleaseAction(fd);
        }
        if (gMode == CNDE5ConnectionReleaseMode) {
            CNDE5RunOwnerReleaseAction(fd);
        }
        if (gMode == CNDE5RawQueueBindReleaseMode) {
            CNDE5RunRawQueueBindReleaseAction(fd);
        }
        if (gMode == CNDE5RawQueueReleaseMode) {
            CNDE5RunRawQueueReleaseAction(fd);
        }

        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        id<MTLCommandQueue> queue = [device newCommandQueue];
        NSMutableArray<id<MTLBuffer>> *candidateBuffers =
            [NSMutableArray arrayWithCapacity:CNDE2LatchCandidateLimit];
        id<MTLBuffer> buffer = nil;
        id<MTLBuffer> secondaryBuffer = nil;
        NSUInteger candidateLimit = gMode == CNDE2LatchMode
            ? CNDE2LatchCandidateLimit : 1;
        for (NSUInteger candidate = 0; candidate < candidateLimit; candidate++) {
            id<MTLBuffer> next = [device newBufferWithLength:CNDE2PageSize
                                                    options:MTLResourceStorageModeShared];
            if (next == nil) break;
            [candidateBuffers addObject:next];
            uint64_t address = next.gpuAddress;
            bool usable = address != 0 &&
                (address & (CNDE2PageSize - 1)) == 0;
            if (gMode == CNDE2LatchMode) {
                usable = usable &&
                    (gAvoidGPUAddress == 0 || address != gAvoidGPUAddress) &&
                    ((address >> 42) & 1) == gRequiredRootIndex;
            }
            if (usable && buffer == nil) {
                buffer = next;
                if (gMode != CNDE2LatchMode) break;
                continue;
            }
            if (usable && gMode == CNDE2LatchMode && buffer != nil &&
                address != buffer.gpuAddress &&
                ((address >> 36) & UINT64_C(0x3f)) ==
                    ((buffer.gpuAddress >> 36) & UINT64_C(0x3f)) &&
                ((address >> 25) & UINT64_C(0x7ff)) ==
                    ((buffer.gpuAddress >> 25) & UINT64_C(0x7ff))) {
                secondaryBuffer = next;
                break;
            }
        }
        void *contents = buffer.contents;
        void *secondaryContents = secondaryBuffer.contents;
        uint64_t gpuAddress = buffer.gpuAddress;
        uint64_t secondaryGPUAddress = secondaryBuffer.gpuAddress;
        id<MTLCommandBuffer> command = [queue commandBuffer];
        id<MTLBlitCommandEncoder> encoder = [command blitCommandEncoder];
        if (gMode == CNDE2LatchMode) {
            if (contents != NULL) {
                memset(contents, CNDE2LatchPrimaryInitial, CNDE2PageSize);
            }
            if (secondaryContents != NULL) {
                memset(secondaryContents, CNDE2LatchSecondaryInitial,
                       CNDE2PageSize);
            }
        } else if (contents != NULL) {
            memset(contents, 0, CNDE2PageSize);
        }
        uint8_t pattern = gMode == CNDE2LatchMode
            ? CNDE2LatchPattern : CNDE2RetirePattern;
        if (encoder != nil && buffer != nil) {
            [encoder fillBuffer:buffer
                          range:NSMakeRange(0, CNDE2PageSize)
                          value:pattern];
            [encoder endEncoding];
            encoder = nil;
        }
        bool prepared = device != nil && queue != nil && buffer != nil &&
            contents != NULL && command != nil && gpuAddress != 0 &&
            (gpuAddress & (CNDE2PageSize - 1)) == 0;
        if (gMode == CNDE2LatchMode) {
            prepared = prepared && secondaryBuffer != nil &&
                secondaryContents != NULL && secondaryGPUAddress != 0 &&
                (secondaryGPUAddress & (CNDE2PageSize - 1)) == 0 &&
                secondaryGPUAddress != gpuAddress;
        }
        if (gMode == CNDE2RetireMode && prepared) {
            [command commit];
            [command waitUntilCompleted];
        }
        id<MTLCommandBuffer> warmupCommand = nil;
        bool latchWarmupVerified = false;
        if (gMode == CNDE2LatchMode && prepared) {
            warmupCommand = [queue commandBuffer];
            id<MTLBlitCommandEncoder> warmupEncoder =
                [warmupCommand blitCommandEncoder];
            if (warmupEncoder != nil) {
                [warmupEncoder fillBuffer:buffer
                                    range:NSMakeRange(0, CNDE2PageSize)
                                    value:CNDE2LatchPrimaryInitial];
                [warmupEncoder fillBuffer:secondaryBuffer
                                    range:NSMakeRange(0, CNDE2PageSize)
                                    value:CNDE2LatchSecondaryInitial];
                [warmupEncoder endEncoding];
            }
            [warmupCommand commit];
            [warmupCommand waitUntilCompleted];
            latchWarmupVerified = warmupCommand != nil &&
                warmupEncoder != nil &&
                warmupCommand.status == MTLCommandBufferStatusCompleted &&
                warmupCommand.error == nil &&
                CNDE2CountPatternBytes(
                    contents, CNDE2LatchPrimaryInitial) == CNDE2PageSize &&
                CNDE2CountPatternBytes(
                    secondaryContents, CNDE2LatchSecondaryInitial) ==
                    CNDE2PageSize;
        }

        uint32_t primaryPatternBytes = gMode == CNDE2RetireMode
            ? CNDE2CountPatternBytes(contents, pattern) : 0;
        uint32_t secondaryPatternBytes = 0;
        bool latchInitialVerified = gMode == CNDE2LatchMode && prepared &&
            latchWarmupVerified &&
            CNDE2CountPatternBytes(
                contents, CNDE2LatchPrimaryInitial) == CNDE2PageSize &&
            CNDE2CountPatternBytes(
                secondaryContents, CNDE2LatchSecondaryInitial) ==
                    CNDE2PageSize;
        bool verified = gMode == CNDE2RetireMode && prepared &&
            command.status == MTLCommandBufferStatusCompleted &&
            command.error == nil &&
            primaryPatternBytes == CNDE2PageSize;

        CNDE2Message ready = {
            .magic = CNDE2Magic,
            .version = CNDE2Version,
            .type = CNDE2Ready,
            .result = (gMode == CNDE2RetireMode
                ? verified : latchInitialVerified) ? 0 : 1,
            .pid = (uint32_t)getpid(),
            .metalStatus = (uint32_t)(gMode == CNDE2LatchMode
                ? warmupCommand.status : command.status),
            .fillVerified = (verified || latchInitialVerified) ? 1U : 0U,
            .mode = gMode,
            .gpuAddress = gpuAddress,
            .secondaryGPUAddress = secondaryGPUAddress,
            .primaryPatternBytes = primaryPatternBytes,
            .secondaryPatternBytes = secondaryPatternBytes,
        };
        memcpy(ready.token, gToken, sizeof(ready.token));
        bool announced = CNDE2WriteAll(fd, &ready, sizeof(ready));
        fprintf(stderr,
                "[E2_HELPER] ready pid=%d port=%u mode=%u gpuAddress=0x%016llx secondaryGPUAddress=0x%016llx metalStatus=%u verified=%d announced=%d candidates=%lu\n",
                getpid(), gPort, gMode, (unsigned long long)gpuAddress,
                (unsigned long long)secondaryGPUAddress,
                ready.metalStatus, verified || latchInitialVerified, announced,
                (unsigned long)candidateBuffers.count);
        fflush(stderr);
        if (ready.result != 0 || !announced) {
            close(fd);
            _exit(70);
        }

        if (gMode == CNDE2LatchMode) {
            if (!CNDE2ReadControlByte(fd, CNDE2SubmitByte, "submit")) {
                close(fd);
                _exit(71);
            }
            [command commit];
            [command waitUntilCompleted];
            primaryPatternBytes =
                CNDE2CountPatternBytes(contents, pattern);
            secondaryPatternBytes =
                CNDE2CountPatternBytes(secondaryContents, pattern);
            bool exclusiveResult =
                (primaryPatternBytes == CNDE2PageSize &&
                 secondaryPatternBytes == 0) ||
                (primaryPatternBytes == 0 &&
                 secondaryPatternBytes == CNDE2PageSize);
            verified = command.status == MTLCommandBufferStatusCompleted &&
                command.error == nil && exclusiveResult;
            CNDE2Message completed = {
                .magic = CNDE2Magic,
                .version = CNDE2Version,
                .type = CNDE2Completed,
                .result = 0,
                .pid = (uint32_t)getpid(),
                .metalStatus = (uint32_t)command.status,
                .fillVerified = verified ? 1U : 0U,
                .mode = gMode,
                .gpuAddress = gpuAddress,
                .secondaryGPUAddress = secondaryGPUAddress,
                .primaryPatternBytes = primaryPatternBytes,
                .secondaryPatternBytes = secondaryPatternBytes,
            };
            memcpy(completed.token, gToken, sizeof(completed.token));
            if (!CNDE2WriteAll(fd, &completed, sizeof(completed))) {
                close(fd);
                _exit(72);
            }
            fprintf(stderr,
                    "[E2_HELPER] completed pid=%d gpuAddress=0x%016llx secondaryGPUAddress=0x%016llx metalStatus=%u verified=%d primaryPatternBytes=%u secondaryPatternBytes=%u\n",
                    getpid(), (unsigned long long)gpuAddress,
                    (unsigned long long)secondaryGPUAddress,
                    completed.metalStatus, verified,
                    primaryPatternBytes, secondaryPatternBytes);
            fflush(stderr);
        }

        if (!CNDE2ReadControlByte(fd, CNDE2ReleaseByte, "release")) {
            close(fd);
            _exit(73);
        }

        CNDE2Message exiting = {
            .magic = CNDE2Magic,
            .version = CNDE2Version,
            .type = CNDE2Exiting,
            .result = 0,
            .pid = (uint32_t)getpid(),
            .metalStatus = (uint32_t)command.status,
            .fillVerified = verified ? 1U : 0U,
            .mode = gMode,
            .gpuAddress = gpuAddress,
            .secondaryGPUAddress = secondaryGPUAddress,
            .primaryPatternBytes = primaryPatternBytes,
            .secondaryPatternBytes = secondaryPatternBytes,
        };
        memcpy(exiting.token, gToken, sizeof(exiting.token));
        if (!CNDE2WriteAll(fd, &exiting, sizeof(exiting))) {
            fprintf(stderr, "[E2_HELPER] exit announcement failed pid=%d\n",
                    getpid());
            fflush(stderr);
            close(fd);
            _exit(74);
        }
        fprintf(stderr, "[E2_HELPER] exiting pid=%d with Metal owners live\n",
                getpid());
        fflush(stderr);

        // The socket closes as part of task exit.  The observer sees EOF only
        // after the OS tears down this process's descriptors; no ARC or Metal
        // owner release is used as the lifetime boundary.
        _exit(0);
    }
}

@interface CNDE2AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation CNDE2AppDelegate
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    (void)application;
    (void)launchOptions;
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.blackColor;
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        CNDE2RunAction();
    });
    return YES;
}
@end

int main(int argc, char *argv[])
{
    if (!CNDE2ParseArguments(argc, argv)) return 64;
    @autoreleasepool {
        return UIApplicationMain(
            argc, argv, nil, NSStringFromClass([CNDE2AppDelegate class]));
    }
}
