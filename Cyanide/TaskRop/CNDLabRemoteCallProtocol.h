#ifndef CNDLabRemoteCallProtocol_h
#define CNDLabRemoteCallProtocol_h

#include <stdint.h>

#define CND_LAB_REMOTECALL_MARKER_PATH "/var/tmp/cyanide-enable-remotecall-lab"
#define CND_LAB_REMOTECALL_TOKEN_PATH "/var/tmp/cyanide-remotecall-lab.token"
#define CND_LAB_REMOTECALL_BUNDLE_MARKER_LEAF "CNDLabRemoteCall.marker"
#define CND_LAB_REMOTECALL_BUNDLE_TOKEN_LEAF "CNDLabRemoteCall.token"
#define CND_LAB_REMOTECALL_SOCKET_PREFIX "/var/tmp/cyanide-remotecall-"
#define CND_LAB_REMOTECALL_SOCKET_SUFFIX ".sock"
#define CND_LAB_REMOTECALL_INSTALLD_SOCKET_LEAF ".cyanide-remotecall-installd.sock"

#define CND_LAB_REMOTECALL_MAGIC 0x434e4452U
#define CND_LAB_REMOTECALL_VERSION 1U
#define CND_LAB_REMOTECALL_TOKEN_LENGTH 32U
#define CND_LAB_REMOTECALL_MAX_TRANSFER 0x4000U
#define CND_LAB_REMOTECALL_SYMBOL_LENGTH 128U
#define CND_LAB_REMOTECALL_PROCESS_LENGTH 64U
#define CND_LAB_REMOTECALL_EXECUTABLE_LENGTH 256U

enum {
    CNDLabRemoteCallOperationHandshake = 1,
    CNDLabRemoteCallOperationCallSymbol = 2,
    CNDLabRemoteCallOperationCallAddress = 3,
    CNDLabRemoteCallOperationRead = 4,
    CNDLabRemoteCallOperationWrite = 5,
    CNDLabRemoteCallOperationClose = 6,
};

enum {
    CNDLabRemoteCallFlagOneWay = 1U << 0,
};

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    uint32_t flags;
    uint32_t length;
    uint32_t timeoutMS;
    int32_t expectedPID;
    uint32_t reserved;
    uint64_t address;
    uint64_t arguments[8];
    uint8_t token[CND_LAB_REMOTECALL_TOKEN_LENGTH];
    char symbol[CND_LAB_REMOTECALL_SYMBOL_LENGTH];
    char process[CND_LAB_REMOTECALL_PROCESS_LENGTH];
} CNDLabRemoteCallRequest;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t operation;
    int32_t status;
    int32_t pid;
    uint32_t length;
    uint64_t value;
    uint64_t scratchAddress;
    char process[CND_LAB_REMOTECALL_PROCESS_LENGTH];
    char executable[CND_LAB_REMOTECALL_EXECUTABLE_LENGTH];
} CNDLabRemoteCallResponse;

typedef struct {
    uint64_t requestSequence;
    uint64_t responseSequence;
    CNDLabRemoteCallRequest request;
    CNDLabRemoteCallResponse response;
    uint8_t payload[CND_LAB_REMOTECALL_MAX_TRANSFER];
} CNDLabRemoteCallMailbox;

#endif /* CNDLabRemoteCallProtocol_h */
