#include <stdint.h>

/*
 * A constructor-free dylib used only to establish the physical SpringBoard
 * library-loading boundary. Loading it has no side effects; the exported
 * challenge/response function proves that dyld admitted executable code and
 * that RemoteCall could invoke the resulting arm64e symbol.
 */

#define CND_SPRINGBOARD_DYLIB_COOKIE UINT64_C(0x434e4453594c4942)

__attribute__((visibility("default"), used))
uint64_t cnd_springboard_dylib_probe(uint64_t challenge)
{
    return challenge ^ CND_SPRINGBOARD_DYLIB_COOKIE;
}
