#import "CyanideLabProbe.h"
#import "TaskRop/RemoteCall.h"

#import <errno.h>
#import <stdlib.h>
#import <string.h>

static const NSUInteger kLabProbeListCap = 256;
static const NSUInteger kLabProbeReadCap = 4096;

static NSDictionary *probe_error(NSString *code, NSString *message)
{
    return @{ @"ok": @NO,
              @"error": code ?: @"probe-error",
              @"message": message ?: @"Unknown probe error.",
              @"readOnly": @YES,
              @"targetStateWrites": @0,
              @"protocolVersion": @1 };
}

static NSString *probe_hex(uint64_t value)
{
    return [NSString stringWithFormat:@"0x%llx",(unsigned long long)value];
}

static BOOL probe_u64(id value, uint64_t *outValue)
{
    if (outValue) *outValue = 0;
    uint64_t parsed = 0;
    if ([value isKindOfClass:NSNumber.class]) {
        parsed = [value unsignedLongLongValue];
    } else if ([value isKindOfClass:NSString.class]) {
        const char *text = [value UTF8String];
        if (!text || !text[0]) return NO;
        errno = 0;
        char *end = NULL;
        parsed = strtoull(text,&end,0);
        if (errno || !end || *end) return NO;
    } else {
        return NO;
    }
    if (outValue) *outValue = parsed;
    return YES;
}

static BOOL probe_object_header_plausible(RemoteCallSession *session,
                                          uint64_t object, uint64_t *isaOut)
{
    if (isaOut) *isaOut = 0;
    if (object < 0x100000000ULL || object >= 0x0000800000000000ULL ||
        (object & 0x7) != 0) return NO;
    uint64_t isa = 0;
    if (![session remoteRead:object to:&isa size:sizeof(isa)]) return NO;
    BOOL plausible = (isa & 1) ||
        (isa >= 0x100000000ULL && isa < 0x0000800000000000ULL &&
         (isa & 0x7) == 0);
    if (plausible && isaOut) *isaOut = isa;
    return plausible;
}

static uint64_t probe_call(RemoteCallSession *session, const char *name,
                           uint64_t x0, uint64_t x1, uint64_t x2,
                           uint64_t x3)
{
    return [session doRemoteCallStableWithTimeout:10000 functionName:name
        x0:x0 x1:x1 x2:x2 x3:x3 x4:0 x5:0 x6:0 x7:0];
}

static NSString *probe_remote_cstring(RemoteCallSession *session,
                                      uint64_t address, NSUInteger cap)
{
    if (!address || cap == 0 || cap > 4096) return nil;
    NSMutableData *data = [NSMutableData data];
    uint8_t chunk[128];
    while (data.length < cap) {
        NSUInteger wanted = MIN(sizeof(chunk),cap - data.length);
        if (![session remoteRead:address + data.length to:chunk size:wanted]) {
            return nil;
        }
        const uint8_t *zero = memchr(chunk,0,wanted);
        NSUInteger count = zero ? (NSUInteger)(zero - chunk) : wanted;
        [data appendBytes:chunk length:count];
        if (zero) {
            return [[NSString alloc] initWithData:data
                                         encoding:NSUTF8StringEncoding];
        }
    }
    return nil;
}

static uint64_t probe_remote_string(RemoteCallSession *session,
                                    NSString *string,
                                    NSUInteger *scratchMutations)
{
    NSData *bytes = [string dataUsingEncoding:NSUTF8StringEncoding];
    if (!bytes || bytes.length > 1024) return 0;
    uint64_t remote = probe_call(session,"malloc",bytes.length + 1,0,0,0);
    if (!remote) return 0;
    NSMutableData *terminated = [bytes mutableCopy];
    uint8_t zero = 0;
    [terminated appendBytes:&zero length:1];
    if (![session remoteWrite:remote from:terminated.bytes size:terminated.length]) {
        (void)probe_call(session,"free",remote,0,0,0);
        return 0;
    }
    if (scratchMutations) (*scratchMutations)++;
    return remote;
}

static void probe_remote_free(RemoteCallSession *session, uint64_t remote,
                              NSUInteger *scratchMutations)
{
    if (!remote) return;
    (void)probe_call(session,"free",remote,0,0,0);
    if (scratchMutations) (*scratchMutations)++;
}

static NSString *probe_class_name(RemoteCallSession *session, uint64_t cls)
{
    uint64_t name = cls ? probe_call(session,"class_getName",cls,0,0,0) : 0;
    return name ? probe_remote_cstring(session,name,512) : nil;
}

static BOOL probe_validate_class(RemoteCallSession *session, uint64_t cls,
                                 uint64_t *metaOut)
{
    if (metaOut) *metaOut = 0;
    if (!probe_object_header_plausible(session,cls,NULL)) return NO;
    uint64_t meta = probe_call(session,"object_getClass",cls,0,0,0);
    uint64_t isMeta = meta
        ? probe_call(session,"class_isMetaClass",meta,0,0,0) : 0;
    if (!meta || !isMeta) return NO;
    if (metaOut) *metaOut = meta;
    return YES;
}

typedef struct {
    uint64_t list;
    uint32_t count;
    NSUInteger scratchMutations;
} ProbeRemoteList;

static ProbeRemoteList probe_copy_list(RemoteCallSession *session,
                                       const char *function, uint64_t owner)
{
    ProbeRemoteList result = {0};
    uint64_t countPointer = probe_call(session,"malloc",sizeof(uint32_t),0,0,0);
    if (!countPointer) return result;
    uint32_t zero = 0;
    if (![session remoteWrite:countPointer from:&zero size:sizeof(zero)]) {
        probe_remote_free(session,countPointer,&result.scratchMutations);
        return result;
    }
    result.scratchMutations++;
    result.list = probe_call(session,function,owner,countPointer,0,0);
    (void)[session remoteRead:countPointer to:&result.count size:sizeof(result.count)];
    probe_remote_free(session,countPointer,&result.scratchMutations);
    return result;
}

static void probe_finish_list(RemoteCallSession *session,
                              ProbeRemoteList *list)
{
    if (!list) return;
    probe_remote_free(session,list->list,&list->scratchMutations);
    list->list = 0;
}

static NSArray *probe_methods(RemoteCallSession *session, uint64_t cls,
                              NSString *filter, NSUInteger *scratchOut)
{
    ProbeRemoteList list = probe_copy_list(session,"class_copyMethodList",cls);
    uint32_t bounded = MIN(list.count,(uint32_t)kLabProbeListCap);
    uint64_t *methods = bounded ? calloc(bounded,sizeof(uint64_t)) : NULL;
    BOOL read = !bounded || (list.list && methods &&
        [session remoteRead:list.list to:methods
                       size:(uint64_t)bounded * sizeof(uint64_t)]);
    NSMutableArray *result = [NSMutableArray array];
    if (read) {
        for (uint32_t i = 0; i < bounded; i++) {
            uint64_t method = methods[i];
            uint64_t selector = method
                ? probe_call(session,"method_getName",method,0,0,0) : 0;
            uint64_t namePointer = selector
                ? probe_call(session,"sel_getName",selector,0,0,0) : 0;
            uint64_t encodingPointer = method
                ? probe_call(session,"method_getTypeEncoding",method,0,0,0) : 0;
            NSString *name = probe_remote_cstring(session,namePointer,512);
            NSString *encoding = probe_remote_cstring(session,encodingPointer,512);
            if (!name.length || (filter.length &&
                [name rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound)) {
                continue;
            }
            uint64_t imp = probe_call(session,"method_getImplementation",method,0,0,0);
            [result addObject:@{ @"name": name,
                                 @"encoding": encoding ?: @"",
                                 @"method": probe_hex(method),
                                 @"selector": probe_hex(selector),
                                 @"implementation": probe_hex(imp) }];
        }
    }
    free(methods);
    probe_finish_list(session,&list);
    if (scratchOut) *scratchOut += list.scratchMutations;
    return result;
}

static BOOL probe_find_method(RemoteCallSession *session, uint64_t cls,
                              NSString *wanted, uint64_t *methodOut,
                              uint64_t *selectorOut, NSString **encodingOut,
                              NSUInteger *scratchOut)
{
    if (methodOut) *methodOut = 0;
    if (selectorOut) *selectorOut = 0;
    if (encodingOut) *encodingOut = nil;
    for (unsigned depth = 0; cls && depth < 20; depth++) {
        ProbeRemoteList list = probe_copy_list(session,"class_copyMethodList",cls);
        uint32_t bounded = MIN(list.count,(uint32_t)kLabProbeListCap);
        uint64_t *methods = bounded ? calloc(bounded,sizeof(uint64_t)) : NULL;
        BOOL read = !bounded || (list.list && methods &&
            [session remoteRead:list.list to:methods
                           size:(uint64_t)bounded * sizeof(uint64_t)]);
        BOOL found = NO;
        if (read) {
            for (uint32_t i = 0; i < bounded; i++) {
                uint64_t selector = probe_call(
                    session,"method_getName",methods[i],0,0,0);
                uint64_t namePointer = selector ? probe_call(
                    session,"sel_getName",selector,0,0,0) : 0;
                NSString *name = probe_remote_cstring(session,namePointer,512);
                if (![name isEqualToString:wanted]) continue;
                uint64_t encodingPointer = probe_call(
                    session,"method_getTypeEncoding",methods[i],0,0,0);
                NSString *encoding = probe_remote_cstring(
                    session,encodingPointer,512);
                if (methodOut) *methodOut = methods[i];
                if (selectorOut) *selectorOut = selector;
                if (encodingOut) *encodingOut = encoding;
                found = YES;
                break;
            }
        }
        free(methods);
        probe_finish_list(session,&list);
        if (scratchOut) *scratchOut += list.scratchMutations;
        if (found) return YES;
        cls = probe_call(session,"class_getSuperclass",cls,0,0,0);
    }
    return NO;
}

static NSArray *probe_ivars(RemoteCallSession *session, uint64_t cls,
                            NSString *filter, NSUInteger *scratchOut)
{
    ProbeRemoteList list = probe_copy_list(session,"class_copyIvarList",cls);
    uint32_t bounded = MIN(list.count,(uint32_t)kLabProbeListCap);
    uint64_t *ivars = bounded ? calloc(bounded,sizeof(uint64_t)) : NULL;
    BOOL read = !bounded || (list.list && ivars &&
        [session remoteRead:list.list to:ivars
                       size:(uint64_t)bounded * sizeof(uint64_t)]);
    NSMutableArray *result = [NSMutableArray array];
    if (read) {
        for (uint32_t i = 0; i < bounded; i++) {
            uint64_t namePointer = probe_call(session,"ivar_getName",ivars[i],0,0,0);
            uint64_t typePointer = probe_call(session,"ivar_getTypeEncoding",ivars[i],0,0,0);
            NSString *name = probe_remote_cstring(session,namePointer,512);
            NSString *type = probe_remote_cstring(session,typePointer,512);
            if (!name.length || (filter.length &&
                [name rangeOfString:filter options:NSCaseInsensitiveSearch].location == NSNotFound)) {
                continue;
            }
            uint64_t offset = probe_call(session,"ivar_getOffset",ivars[i],0,0,0);
            [result addObject:@{ @"name": name,
                                 @"type": type ?: @"",
                                 @"ivar": probe_hex(ivars[i]),
                                 @"offset": @(offset) }];
        }
    }
    free(ivars);
    probe_finish_list(session,&list);
    if (scratchOut) *scratchOut += list.scratchMutations;
    return result;
}

static BOOL probe_selector_is_forbidden(NSString *selector)
{
    if ([selector containsString:@":"]) return YES;
    static NSSet<NSString *> *forbidden;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        forbidden = [NSSet setWithArray:@[
            @"clear", @"invalidate", @"removeAll", @"start", @"resume",
            @"suspend", @"purge", @"writeStoreUnit", @"addUnitWithData",
            @"removeUnitForUUID", @"retain", @"autorelease", @"copy",
            @"mutableCopy", @"alloc", @"new", @"init", @"initialize",
            @"load",
            @"findStoreUnitForIcon:descriptor:UUID:validationToken:"
        ]];
    });
    return [forbidden containsObject:selector];
}

static BOOL probe_getter_encoding_allowed(NSString *encoding)
{
    static NSSet<NSString *> *allowed;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        allowed = [NSSet setWithArray:@[
            @"@16@0:8", @"#16@0:8", @"B16@0:8", @"Q16@0:8",
            @"q16@0:8", @"I16@0:8", @"i16@0:8", @"^v16@0:8",
            @"r^v16@0:8", @"*16@0:8", @"r*16@0:8"
        ]];
    });
    return [allowed containsObject:encoding];
}

NSDictionary *cyanide_lab_probe_handle_request(
    RemoteCallSession *session, NSDictionary<NSString *, id> *request)
{
    if (!session || ![session hasLocalState]) {
        return probe_error(@"session-required",@"Open a target session first.");
    }
    NSString *command = [request[@"command"] isKindOfClass:NSString.class]
        ? request[@"command"] : @"";
    NSUInteger scratch = 0;

    if ([command isEqualToString:@"probe.capabilities"]) {
        return @{ @"ok": @YES,
                  @"commands": @[@"runtime.class",@"runtime.methods",
                      @"runtime.ivars",@"runtime.ivar",@"runtime.getter",
                      @"runtime.objectClass",@"memory.read",@"thread.states"],
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"runtime.class"]) {
        NSString *name = [request[@"name"] isKindOfClass:NSString.class]
            ? request[@"name"] : nil;
        if (!name.length || name.length > 255) {
            return probe_error(@"invalid-class",@"Provide a class name up to 255 bytes.");
        }
        uint64_t remoteName = probe_remote_string(session,name,&scratch);
        uint64_t cls = remoteName ? probe_call(
            session,"objc_lookUpClass",remoteName,0,0,0) : 0;
        probe_remote_free(session,remoteName,&scratch);
        return @{ @"ok": @(cls != 0), @"class": probe_hex(cls),
                  @"name": cls ? (probe_class_name(session,cls) ?: name) : name,
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"scratchMutations": @(scratch), @"protocolVersion": @1 };
    }

    uint64_t address = 0;
    if ([command isEqualToString:@"runtime.methods"] ||
        [command isEqualToString:@"runtime.ivars"]) {
        if (!probe_u64(request[@"class"],&address) || !address) {
            return probe_error(@"invalid-class-address",@"Provide a nonzero class address.");
        }
        NSString *filter = [request[@"filter"] isKindOfClass:NSString.class]
            ? request[@"filter"] : nil;
        BOOL meta = [request[@"meta"] boolValue];
        uint64_t metaClass = 0;
        if (!probe_validate_class(session,address,&metaClass)) {
            return probe_error(@"invalid-class-address",
                               @"The address is not an exact Objective-C class object.");
        }
        uint64_t owner = meta ? metaClass : address;
        NSArray *items = [command hasSuffix:@"methods"]
            ? probe_methods(session,owner,filter,&scratch)
            : probe_ivars(session,owner,filter,&scratch);
        return @{ @"ok": @YES, @"class": probe_hex(address),
                  @"owner": probe_hex(owner), @"meta": @(meta),
                  @"items": items, @"count": @(items.count),
                  @"truncatedAt": @(kLabProbeListCap), @"readOnly": @YES,
                  @"targetStateWrites": @0, @"scratchMutations": @(scratch),
                  @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"runtime.objectClass"]) {
        if (!probe_u64(request[@"object"],&address) || !address) {
            return probe_error(@"invalid-object-address",@"Provide a nonzero object address.");
        }
        uint64_t isa = 0;
        if (!probe_object_header_plausible(session,address,&isa)) {
            return probe_error(@"object-unreadable",@"The object header or ISA was not plausible.");
        }
        uint64_t cls = probe_call(session,"object_getClass",address,0,0,0);
        return @{ @"ok": @(cls != 0), @"object": probe_hex(address),
                  @"rawISA": probe_hex(isa), @"class": probe_hex(cls),
                  @"className": cls ? (probe_class_name(session,cls) ?: @"") : @"",
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"runtime.getter"]) {
        uint64_t receiver = 0;
        NSString *selector = [request[@"selector"] isKindOfClass:NSString.class]
            ? request[@"selector"] : nil;
        NSString *expected = [request[@"encoding"] isKindOfClass:NSString.class]
            ? request[@"encoding"] : nil;
        if (!probe_u64(request[@"receiver"],&receiver) || !receiver ||
            !selector.length || !expected.length) {
            return probe_error(@"invalid-getter",@"receiver, selector, and exact encoding are required.");
        }
        if (probe_selector_is_forbidden(selector) ||
            !probe_getter_encoding_allowed(expected)) {
            return probe_error(@"getter-prohibited",@"Only allowlisted zero-argument getter encodings are accepted.");
        }
        if (!probe_object_header_plausible(session,receiver,NULL)) {
            return probe_error(@"receiver-unreadable",@"The receiver header or ISA was not plausible.");
        }
        uint64_t cls = probe_call(session,"object_getClass",receiver,0,0,0);
        uint64_t method = 0;
        uint64_t sel = 0;
        NSString *observed = nil;
        BOOL found = cls && probe_find_method(session,cls,selector,&method,
                                               &sel,&observed,&scratch);
        if (!found) return probe_error(@"method-not-found",@"The selector was not found without registering it.");
        if (![observed isEqualToString:expected]) {
            return @{ @"ok": @NO, @"error": @"abi-mismatch",
                      @"selector": selector, @"expected": expected,
                      @"observed": observed ?: @"", @"invoked": @NO,
                      @"readOnly": @YES, @"targetStateWrites": @0,
                      @"scratchMutations": @(scratch), @"protocolVersion": @1 };
        }
        uint64_t value = probe_call(session,"objc_msgSend",receiver,sel,0,0);
        return @{ @"ok": @YES, @"selector": selector,
                  @"encoding": observed, @"method": probe_hex(method),
                  @"selectorAddress": probe_hex(sel), @"invoked": @YES,
                  @"value": probe_hex(value), @"valueUnsigned": @(value),
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"scratchMutations": @(scratch), @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"runtime.ivar"]) {
        uint64_t object = 0;
        NSString *wanted = [request[@"name"] isKindOfClass:NSString.class]
            ? request[@"name"] : nil;
        if (!probe_u64(request[@"object"],&object) || !object || !wanted.length) {
            return probe_error(@"invalid-ivar",@"object and ivar name are required.");
        }
        if (!probe_object_header_plausible(session,object,NULL)) {
            return probe_error(@"object-unreadable",@"The object header or ISA was not plausible.");
        }
        uint64_t cls = probe_call(session,"object_getClass",object,0,0,0);
        BOOL found = NO;
        uint64_t value = 0;
        uint64_t offset = 0;
        NSString *type = nil;
        for (unsigned depth = 0; cls && depth < 20 && !found; depth++) {
            NSArray *ivars = probe_ivars(session,cls,nil,&scratch);
            for (NSDictionary *ivar in ivars) {
                if (![ivar[@"name"] isEqualToString:wanted]) continue;
                offset = [ivar[@"offset"] unsignedLongLongValue];
                type = ivar[@"type"];
                found = [session remoteRead:object + offset to:&value size:sizeof(value)];
                break;
            }
            cls = found ? 0 : probe_call(session,"class_getSuperclass",cls,0,0,0);
        }
        if (!found) return probe_error(@"ivar-not-found",@"The ivar was not found or could not be read.");
        return @{ @"ok": @YES, @"object": probe_hex(object),
                  @"name": wanted, @"type": type ?: @"",
                  @"offset": @(offset), @"value": probe_hex(value),
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"scratchMutations": @(scratch), @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"memory.read"]) {
        uint64_t length = 0;
        if (!probe_u64(request[@"address"],&address) || !address ||
            !probe_u64(request[@"length"],&length) || !length ||
            length > kLabProbeReadCap) {
            return probe_error(@"invalid-read",@"Provide an address and a length from 1 through 4096.");
        }
        NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)length];
        if (![session remoteRead:address to:data.mutableBytes size:length]) {
            return probe_error(@"read-failed",@"The requested memory range could not be read.");
        }
        return @{ @"ok": @YES, @"address": probe_hex(address),
                  @"length": @(length),
                  @"base64": [data base64EncodedStringWithOptions:0],
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"protocolVersion": @1 };
    }

    if ([command isEqualToString:@"thread.states"]) {
        arm_thread_state64_internal states[5] = {0};
        size_t count = remote_call_copy_original_thread_states(states,5);
        NSMutableArray *items = [NSMutableArray array];
        for (size_t i = 0; i < count; i++) {
            NSMutableArray *registers = [NSMutableArray arrayWithCapacity:29];
            for (unsigned r = 0; r < 29; r++) {
                [registers addObject:probe_hex(states[i].__x[r])];
            }
            [items addObject:@{ @"index": @(i), @"x": registers,
                                @"fp": probe_hex(states[i].__fp),
                                @"lr": probe_hex(states[i].__lr),
                                @"sp": probe_hex(states[i].__sp),
                                @"pc": probe_hex(states[i].__pc),
                                @"cpsr": @(states[i].__cpsr) }];
        }
        return @{ @"ok": @YES, @"states": items, @"count": @(count),
                  @"readOnly": @YES, @"targetStateWrites": @0,
                  @"protocolVersion": @1 };
    }

    return probe_error(@"unknown-command",@"The requested probe command is not supported.");
}
