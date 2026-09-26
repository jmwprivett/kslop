#ifndef CNDLabRemoteCallClient_h
#define CNDLabRemoteCallClient_h

#include "CNDLabRemoteCallProtocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int socketFD;
    int responseFD;
    CNDLabRemoteCallMailbox *mailbox;
    size_t mailboxSize;
    int pid;
    uint64_t scratchAddress;
    uint8_t token[CND_LAB_REMOTECALL_TOKEN_LENGTH];
    char process[CND_LAB_REMOTECALL_PROCESS_LENGTH];
} CNDLabRemoteCallClient;

bool cnd_lab_remotecall_opted_in(void);
bool cnd_lab_remotecall_consume_root_file_token(void);
bool cnd_lab_remotecall_consume_bundle_file_token(void);
bool cnd_lab_remotecall_copy_target_bundle_path(char *path, size_t pathSize);
int cnd_lab_remotecall_connect(const char *process,
                               CNDLabRemoteCallClient *client,
                               char *error, size_t errorSize);
int cnd_lab_remotecall_call_symbol(CNDLabRemoteCallClient *client,
                                   int timeoutMS, const char *symbol,
                                   const uint64_t arguments[8],
                                   uint64_t *value);
int cnd_lab_remotecall_call_address(CNDLabRemoteCallClient *client,
                                    int timeoutMS, uint64_t address,
                                    const uint64_t arguments[8],
                                    uint64_t *value);
int cnd_lab_remotecall_read(CNDLabRemoteCallClient *client, uint64_t address,
                            void *buffer, size_t size);
int cnd_lab_remotecall_write(CNDLabRemoteCallClient *client, uint64_t address,
                             const void *buffer, size_t size);
int cnd_lab_remotecall_close(CNDLabRemoteCallClient *client);
void cnd_lab_remotecall_abandon(CNDLabRemoteCallClient *client);
bool cnd_lab_remotecall_has_state(const CNDLabRemoteCallClient *client);

#endif /* CNDLabRemoteCallClient_h */
