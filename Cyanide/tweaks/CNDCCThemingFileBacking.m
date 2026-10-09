#import "CNDCCThemingFileBacking.h"

#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if !defined(CND_CC_FILE_BACKING_TESTING)
#import "../utils/file.h"
#endif

static NSString *const CNDCCFileBuild = @"23A341";
static const NSUInteger CNDCCMaximumResourceLength = 256U << 20;
typedef BOOL (^CNDCCFileWriter)(NSString *, NSString *);

// This small XML model is for resource files only. It never follows a UIKit
// hierarchy or touches a SpringBoard receiver. External entities are disabled.
@interface CNDCCFileXMLNode : NSObject
@property(nonatomic, copy) NSString *name;
@property(nonatomic, strong) NSMutableDictionary<NSString *, NSString *> *attributes;
@property(nonatomic, strong) NSMutableArray<CNDCCFileXMLNode *> *children;
@property(nonatomic, strong) NSMutableString *text;
@end
@implementation CNDCCFileXMLNode
- (instancetype)init
{
    if ((self = [super init])) {
        _attributes = [NSMutableDictionary dictionary];
        _children = [NSMutableArray array];
        _text = [NSMutableString string];
    }
    return self;
}
@end

@interface CNDCCFileXMLReader : NSObject <NSXMLParserDelegate>
@property(nonatomic, strong) CNDCCFileXMLNode *root;
@property(nonatomic, strong) NSMutableArray<CNDCCFileXMLNode *> *stack;
@property(nonatomic) NSUInteger nodeCount;
@end
@implementation CNDCCFileXMLReader
- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)name
    namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qualifiedName
    attributes:(NSDictionary<NSString *, NSString *> *)attributes
{
    (void)namespaceURI;
    (void)qualifiedName;
    if (++self.nodeCount > 10000 || self.stack.count > 64) {
        [parser abortParsing];
        return;
    }
    CNDCCFileXMLNode *node = [CNDCCFileXMLNode new];
    node.name = name;
    [node.attributes addEntriesFromDictionary:attributes];
    if (self.stack.count) [self.stack.lastObject.children addObject:node];
    else self.root = node;
    [self.stack addObject:node];
}
- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)name
    namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qualifiedName
{
    (void)parser; (void)name; (void)namespaceURI; (void)qualifiedName;
    [self.stack removeLastObject];
}
- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)text
{
    (void)parser;
    [self.stack.lastObject.text appendString:text];
}
@end

static NSError *CNDCCFileError(NSString *reason)
{
    return [NSError errorWithDomain:@"CNDCCFileBacking" code:1
        userInfo:@{NSLocalizedDescriptionKey: reason}];
}

static NSString *CNDCCFileSHA(NSData *data)
{
    if (!data) return nil;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    const uint8_t *bytes = data.bytes;
    NSUInteger offset = 0;
    while (offset < data.length) {
        NSUInteger length = MIN(data.length - offset, (NSUInteger)(1U << 20));
        CC_SHA256_Update(&context, bytes + offset, (CC_LONG)length);
        offset += length;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    NSMutableString *string = [NSMutableString string];
    for (NSUInteger i = 0; i < sizeof(digest); i++) [string appendFormat:@"%02x", digest[i]];
    return string;
}

static BOOL CNDCCFileDigestValid(id value)
{
    if (![value isKindOfClass:NSString.class] || [value length] != 64) return NO;
    NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
    return [(NSString *)value rangeOfCharacterFromSet:hex.invertedSet].location == NSNotFound;
}

static NSData *CNDCCFileRead(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return nil;
    struct stat st = {0};
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > CNDCCMaximumResourceLength) {
        close(fd);
        return nil;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t amount = read(fd, (uint8_t *)data.mutableBytes + offset, data.length - offset);
        if (amount > 0) offset += (NSUInteger)amount;
        else if (amount < 0 && errno == EINTR) continue;
        else { close(fd); return nil; }
    }
    close(fd);
    return data;
}

static BOOL CNDCCFileSave(NSData *data, NSURL *url)
{
    if (!data.length || !url.isFileURL) return NO;
    if (![data writeToURL:url options:NSDataWritingAtomic error:NULL]) return NO;
    chmod(url.fileSystemRepresentation, 0644);
    int fd = open(url.fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    BOOL okay = fd >= 0 && fsync(fd) == 0;
    if (fd >= 0) close(fd);
    int directory = open(url.URLByDeletingLastPathComponent.fileSystemRepresentation,
                         O_RDONLY | O_CLOEXEC);
    if (directory >= 0) { (void)fsync(directory); close(directory); }
    return okay && [CNDCCFileRead(url.path) isEqualToData:data];
}

static NSDictionary *CNDCCFileLoadJSON(NSURL *url)
{
    NSData *data = CNDCCFileRead(url.path);
    id object = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL] : nil;
    return [object isKindOfClass:NSDictionary.class] ? object : nil;
}

static BOOL CNDCCFileSaveJSON(NSDictionary *object, NSURL *url)
{
    NSData *data = [NSJSONSerialization dataWithJSONObject:object
        options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:NULL];
    return data && CNDCCFileSave(data, url);
}

static CNDCCFileXMLNode *CNDCCFileXML(NSData *data)
{
    if (!data.length || data.length > (4U << 20)) return nil;
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!string || [string containsString:@"<!DOCTYPE"] || [string containsString:@"<!ENTITY"])
        return nil;
    CNDCCFileXMLReader *reader = [CNDCCFileXMLReader new];
    reader.stack = [NSMutableArray array];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];
    parser.shouldResolveExternalEntities = NO;
    parser.delegate = reader;
    if (![parser parse] || reader.stack.count || ![reader.root.name isEqualToString:@"caml"] ||
        ![reader.root.attributes[@"xmlns"] isEqualToString:@"http://www.apple.com/CoreAnimation/1.0"] ||
        reader.root.children.count != 1 ||
        ![reader.root.children.firstObject.name isEqualToString:@"CALayer"]) return nil;
    return reader.root;
}

static NSString *CNDCCFileEscape(NSString *text)
{
    NSString *escaped = [text stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
    escaped = [escaped stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
    escaped = [escaped stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
    escaped = [escaped stringByReplacingOccurrencesOfString:@"\"" withString:@"&quot;"];
    return escaped;
}

static void CNDCCFileSerialize(CNDCCFileXMLNode *node, NSMutableString *text)
{
    [text appendFormat:@"<%@", node.name];
    for (NSString *key in [node.attributes.allKeys sortedArrayUsingSelector:@selector(compare:)])
        [text appendFormat:@" %@=\"%@\"", key, CNDCCFileEscape(node.attributes[key])];
    NSString *content = [node.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    if (!node.children.count && !content.length) { [text appendString:@"/>"]; return; }
    [text appendString:@">"];
    if (content.length) [text appendString:CNDCCFileEscape(content)];
    for (CNDCCFileXMLNode *child in node.children) CNDCCFileSerialize(child, text);
    [text appendFormat:@"</%@>", node.name];
}

static CNDCCFileXMLNode *CNDCCFileChild(CNDCCFileXMLNode *node, NSString *name)
{
    for (CNDCCFileXMLNode *child in node.children) if ([child.name isEqualToString:name]) return child;
    return nil;
}

static BOOL CNDCCFileNumbers(NSString *text, double *values, NSUInteger count)
{
    if (![text isKindOfClass:NSString.class]) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:text];
    for (NSUInteger i = 0; i < count; i++) {
        if (![scanner scanDouble:&values[i]] || !isfinite(values[i])) return NO;
    }
    return scanner.isAtEnd;
}

static BOOL CNDCCFileNumberArray(id array, double *values, NSUInteger count)
{
    if (![array isKindOfClass:NSArray.class] || [array count] != count) return NO;
    for (NSUInteger i = 0; i < count; i++) {
        if (![array[i] isKindOfClass:NSNumber.class]) return NO;
        values[i] = [array[i] doubleValue];
        if (!isfinite(values[i]) || fabs(values[i]) > 512) return NO;
    }
    return YES;
}

static NSDictionary<NSString *, NSString *> *CNDCCFileAllowedPackages(void)
{
    static NSDictionary *routes;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        routes = @{
            @"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Brightness.ca": @"display",
            @"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/StyleMode.ca": @"appearance",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/Volume.ca": @"sound",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/VolumeRTL.ca": @"sound",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/VolumeSemibold.ca": @"sound",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/VolumeSemiboldRTL.ca": @"sound",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/VolumeBold.ca": @"sound",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/PlayPauseStop.ca": @"mediaPlayPause",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/ForwardBackward.ca": @"mediaNext",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/Mirroring.ca": @"screenMirroring",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/Mirroring_IC.ca": @"screenMirroring",
            @"/System/Library/PrivateFrameworks/MediaControls.framework/MirroringLeading.ca": @"screenMirroring",
            @"/System/Library/ControlCenter/Bundles/TimerModule.bundle/Timer.ca": @"timer",
            @"/System/Library/ControlCenter/Bundles/TimerModule.bundle/Timer_IC.ca": @"timer",
            @"/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower.ca": @"lowPower",
            @"/System/Library/ControlCenter/Bundles/LowPowerModule.bundle/LowPower_IC.ca": @"lowPower",
            @"/System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute.ca": @"mute",
            @"/System/Library/ControlCenter/Bundles/MuteModule.bundle/Mute_IC.ca": @"mute",
            @"/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock.ca": @"orientationLock",
            @"/System/Library/ControlCenter/Bundles/OrientationLockModule.bundle/OrientationLock_IC.ca": @"orientationLock",
            @"/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit.ca": @"screenRecording",
            @"/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit_IC.ca": @"screenRecording",
            @"/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit-v2.ca": @"screenRecording",
            @"/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit-v2_IC.ca": @"screenRecording",
            @"/System/Library/ControlCenter/Bundles/ShazamModule.bundle/Shazam.ca": @"musicRecognition",
            @"/System/Library/PrivateFrameworks/FocusUI.framework/dnd_cg_02.ca": @"focus",
            @"/System/Library/PrivateFrameworks/FocusUI.framework/sleep_cg_02.ca": @"focusSleep",
            @"/System/Library/PrivateFrameworks/FocusUI.framework/personal_cg_02.ca": @"focusPersonal",
            @"/System/Library/PrivateFrameworks/FocusUI.framework/work_cg_02.ca": @"focusWork",
        };
    });
    return routes;
}

static NSArray<NSString *> *CNDCCFileStateNames(CNDCCFileXMLNode *root)
{
    NSMutableArray *names = [NSMutableArray array];
    for (CNDCCFileXMLNode *state in CNDCCFileChild(root, @"states").children) {
        NSString *name = state.attributes[@"name"];
        if (![state.name isEqualToString:@"LKState"] || !name.length || [names containsObject:name]) return nil;
        [names addObject:name];
    }
    return names;
}

static BOOL CNDCCFileReplaceImageURLs(CNDCCFileXMLNode *node, NSURL *directory)
{
    if ([node.name isEqualToString:@"contents"] && [node.attributes[@"type"] isEqualToString:@"CGImage"]) {
        NSString *source = node.attributes[@"src"];
        if (!source.length || ![source.lastPathComponent isEqualToString:source] ||
            ![source.pathExtension isEqualToString:@"png"]) return NO;
        node.attributes[@"src"] = [directory URLByAppendingPathComponent:source].absoluteString;
    }
    for (CNDCCFileXMLNode *child in node.children) if (!CNDCCFileReplaceImageURLs(child, directory)) return NO;
    return YES;
}

static NSString *CNDCCFileAlias(NSString *kind, NSString *nativeState, NSArray *sourceStates)
{
    if ([sourceStates containsObject:nativeState]) return nativeState;
    NSDictionary *aliases = @{
        @"timer": @{@"timing": @"on", @"idle": @"off", @"base": @"off"},
        @"lowPower": @{@"on": @"enabled", @"off": @"disabled"},
        @"mute": @{@"on": @"silent", @"off": @"ringer"},
        @"orientationLock": @{@"on": @"locked", @"off": @"unlocked"},
        // iOS 26 adds a recording-static state to the upstream package.
        // Aliased recording states also receive the authored transitions below.
        @"screenRecording": @{@"off": @"disabled", @"on": @"recording",
                              @"recording-static": @"recording"},
        @"screenMirroring": @{@"breathe": @"on", @"zoom": @"on"},
    };
    NSString *alias = aliases[kind][nativeState];
    return [sourceStates containsObject:alias] ? alias : nil;
}

static void CNDCCFileAdaptReplayKitTransitions(CNDCCFileXMLNode *transitions,
    NSArray<NSString *> *nativeStates, NSArray<NSString *> *sourceStates)
{
    // This rewrites a CAML document during preflight. Native receivers still
    // own state selection and execute the package's existing CA animations.
    NSArray<CNDCCFileXMLNode *> *authored = [transitions.children copy];
    for (NSString *nativeState in nativeStates) {
        if ([sourceStates containsObject:nativeState]) continue;
        NSString *sourceState = CNDCCFileAlias(@"screenRecording", nativeState, sourceStates);
        if (![sourceState isEqualToString:@"recording"]) continue;
        for (CNDCCFileXMLNode *transition in authored) {
            NSString *from = transition.attributes[@"fromState"], *to = transition.attributes[@"toState"];
            if (![from isEqualToString:sourceState] && ![to isEqualToString:sourceState]) continue;
            CNDCCFileXMLNode *adapted = [CNDCCFileXMLNode new];
            adapted.name = transition.name;
            [adapted.attributes addEntriesFromDictionary:transition.attributes];
            if ([from isEqualToString:sourceState]) adapted.attributes[@"fromState"] = nativeState;
            if ([to isEqualToString:sourceState]) adapted.attributes[@"toState"] = nativeState;
            [adapted.children addObjectsFromArray:transition.children];
            [adapted.text appendString:transition.text];
            [transitions.children addObject:adapted];
        }
    }
}

// This walks a parsed resource document during preflight, never a live view or
// layer. Native Brightness/Volume packages author their visible drawing white;
// the consumer owns tint/colorization in both light slider and dark subpages.
static void CNDCCFileNormalizeTemplateColors(CNDCCFileXMLNode *node)
{
    for (NSString *key in @[@"fillColor", @"strokeColor", @"backgroundColor"])
        if (node.attributes[key]) node.attributes[key] = @"1 1 1";
    for (CNDCCFileXMLNode *child in node.children) CNDCCFileNormalizeTemplateColors(child);
}

static NSData *CNDCCFilePrepareCAML(NSData *nativeData, NSData *sourceData,
    NSString *kind, NSURL *imageDirectory, NSDictionary *geometry, NSError **error)
{
    CNDCCFileXMLNode *native = CNDCCFileXML(nativeData);
    CNDCCFileXMLNode *source = CNDCCFileXML(sourceData);
    CNDCCFileXMLNode *nativeLayer = native.children.firstObject;
    CNDCCFileXMLNode *sourceLayer = source.children.firstObject;
    double bounds[4];
    if (!native || !source || !CNDCCFileNumbers(nativeLayer.attributes[@"bounds"], bounds, 4) ||
        bounds[2] <= 0 || bounds[3] <= 0 || bounds[2] > 512 || bounds[3] > 512 ||
        !CNDCCFileReplaceImageURLs(sourceLayer, imageDirectory)) {
        if (error) *error = CNDCCFileError(@"The native/source CAML or its document geometry/images are invalid.");
        return nil;
    }
    NSArray *nativeStates = CNDCCFileStateNames(nativeLayer);
    NSArray *sourceStates = CNDCCFileStateNames(sourceLayer);
    if (!nativeStates || !sourceStates) {
        if (error) *error = CNDCCFileError(@"The package has an invalid or duplicate state contract.");
        return nil;
    }
    CNDCCFileXMLNode *states = CNDCCFileChild(sourceLayer, @"states");
    if (!states) { states = [CNDCCFileXMLNode new]; states.name = @"states"; }
    NSMutableSet<NSString *> *requiredStates = [NSMutableSet setWithArray:nativeStates];
    BOOL staticStates = [@[@"sound", @"display", @"mediaNext"] containsObject:kind] && !sourceStates.count;
    BOOL staticTemplate = [@[@"sound", @"display"] containsObject:kind] && staticStates;
    if (staticTemplate) {
        CNDCCFileNormalizeTemplateColors(sourceLayer);
        sourceLayer.attributes[@"id"] = @"#9001";
    }
    for (NSString *name in nativeStates) {
        if ([sourceStates containsObject:name]) continue;
        NSString *alias = CNDCCFileAlias(kind, name, sourceStates);
        if (!alias && !staticStates) {
            if (error) *error = CNDCCFileError([NSString stringWithFormat:@"No Pulsar state maps to native %@/%@.", kind, name]);
            return nil;
        }
        CNDCCFileXMLNode *state = [CNDCCFileXMLNode new];
        state.name = @"LKState";
        state.attributes[@"name"] = name;
        if (alias) {
            state.attributes[@"basedOn"] = alias;
            [requiredStates addObject:alias];
        }
        if (staticTemplate) {
            // Each native volume/brightness level explicitly selects the same
            // authored Pulsar drawing. State reconstruction cannot inherit a
            // stale hidden/opacity value from a preceding level.
            CNDCCFileXMLNode *elements = [CNDCCFileXMLNode new]; elements.name = @"elements";
            for (NSString *key in @[@"hidden", @"opacity"]) {
                CNDCCFileXMLNode *setter = [CNDCCFileXMLNode new]; setter.name = @"LKStateSetValue";
                setter.attributes[@"targetId"] = @"#9001"; setter.attributes[@"keyPath"] = key;
                CNDCCFileXMLNode *value = [CNDCCFileXMLNode new]; value.name = @"value";
                value.attributes[@"type"] = @"integer";
                value.attributes[@"value"] = [key isEqualToString:@"hidden"] ? @"0" : @"1";
                [setter.children addObject:value]; [elements.children addObject:setter];
            }
            [state.children addObject:elements];
        }
        [states.children addObject:state];
    }
    // Supplemental wrappers deliberately include many generic state aliases.
    // Keep only the native contract and its inherited Pulsar states so the
    // smaller native Focus packages still fit their original file capacities.
    BOOL inheritedAdded;
    do {
        inheritedAdded = NO;
        for (CNDCCFileXMLNode *state in states.children) {
            NSString *name = state.attributes[@"name"], *base = state.attributes[@"basedOn"];
            if ([requiredStates containsObject:name] && base.length && ![requiredStates containsObject:base]) {
                [requiredStates addObject:base];
                inheritedAdded = YES;
            }
        }
    } while (inheritedAdded);
    NSMutableArray *retainedStates = [NSMutableArray array];
    for (CNDCCFileXMLNode *state in states.children)
        if ([requiredStates containsObject:state.attributes[@"name"]]) [retainedStates addObject:state];
    states.children = retainedStates;

    // Keep the native document root so e.g. Timer uses its native 48-point
    // canvas/24-point center. Per-view coordinate workarounds cannot be copied
    // unchanged into a resource that has to work for every new native receiver.
    CNDCCFileXMLNode *root = [CNDCCFileXMLNode new];
    root.name = @"CALayer";
    [root.attributes addEntriesFromDictionary:nativeLayer.attributes];
    [root.attributes removeObjectForKey:@"id"];
    double sourceBounds[4] = {0};
    BOOL hasSourceBounds = CNDCCFileNumbers(sourceLayer.attributes[@"bounds"], sourceBounds, 4) &&
        sourceBounds[2] > 0 && sourceBounds[3] > 0;
    if (geometry) {
        double content[4], destination[4], document[4];
        BOOL valid = [geometry isKindOfClass:NSDictionary.class] &&
            [geometry[@"kind"] isEqualToString:kind] &&
            [geometry[@"sourceMainSHA256"] isEqualToString:CNDCCFileSHA(sourceData)] &&
            [geometry[@"nativeMainSHA256"] isEqualToString:CNDCCFileSHA(nativeData)] &&
            CNDCCFileNumberArray(geometry[@"sourceContentBounds"], content, 4) &&
            CNDCCFileNumberArray(geometry[@"nativeContentBounds"], destination, 4) &&
            CNDCCFileNumberArray(geometry[@"nativeDocumentBounds"], document, 4) &&
            content[2] > 0 && content[3] > 0 && destination[2] > 0 && destination[3] > 0;
        for (NSUInteger i = 0; valid && i < 4; i++) valid = fabs(document[i] - bounds[i]) < 0.0001;
        valid = valid && destination[0] >= bounds[0] && destination[1] >= bounds[1] &&
            destination[0] + destination[2] <= bounds[0] + bounds[2] &&
            destination[1] + destination[3] <= bounds[1] + bounds[3];
        if (!valid) {
            if (error) *error = CNDCCFileError(@"The pinned offline artwork geometry does not match these native/Pulsar resources.");
            return nil;
        }
        double scale = fmin(destination[2] / content[2], destination[3] / content[3]);
        if (scale < 0.01 || scale > 32) {
            if (error) *error = CNDCCFileError(@"The offline artwork geometry requires an invalid scale.");
            return nil;
        }
        // The source rectangle already includes its original root transform,
        // bounds anchor, vector paths, and PNG alpha padding. Scale uniformly
        // and place that rectangle at the native artwork center, rather than
        // centering/resizing its unrelated legacy 40-point document canvas.
        sourceLayer.attributes[@"position"] = [NSString stringWithFormat:@"%.12g %.12g",
            destination[0] + destination[2] / 2 - scale * (content[0] + content[2] / 2),
            destination[1] + destination[3] / 2 - scale * (content[1] + content[3] / 2)];
        sourceLayer.attributes[@"transform"] = [NSString stringWithFormat:@"scale(%.12g, %.12g, 1) %@",
            scale, scale, sourceLayer.attributes[@"transform"] ?: @""];
    } else if (!hasSourceBounds) {
        sourceLayer.attributes[@"position"] = [NSString stringWithFormat:@"%.8g %.8g",
            bounds[0] + bounds[2] / 2, bounds[1] + bounds[3] / 2];
        sourceLayer.attributes[@"bounds"] = @"0 0 0 0";
        sourceLayer.attributes[@"anchorPoint"] = @"0.5 0.5";
    } else {
        sourceLayer.attributes[@"position"] = [NSString stringWithFormat:@"%.8g %.8g",
            bounds[0] + bounds[2] / 2, bounds[1] + bounds[3] / 2];
        if (fabs(sourceBounds[2] - bounds[2]) > 0.01 || fabs(sourceBounds[3] - bounds[3]) > 0.01) {
            NSString *transform = sourceLayer.attributes[@"transform"] ?: @"";
            sourceLayer.attributes[@"transform"] = [NSString stringWithFormat:@"scale(%.8g, %.8g, 1) %@",
                bounds[2] / sourceBounds[2], bounds[3] / sourceBounds[3], transform];
        }
    }
    CNDCCFileXMLNode *transitions = CNDCCFileChild(sourceLayer, @"stateTransitions");
    if ([kind isEqualToString:@"screenRecording"] && transitions)
        CNDCCFileAdaptReplayKitTransitions(transitions, nativeStates, sourceStates);
    [sourceLayer.children removeObject:states];
    if (transitions) [sourceLayer.children removeObject:transitions];
    CNDCCFileXMLNode *sublayers = [CNDCCFileXMLNode new];
    sublayers.name = @"sublayers";
    [sublayers.children addObject:sourceLayer];
    [root.children addObject:sublayers];
    [root.children addObject:states];
    if (transitions) [root.children addObject:transitions];
    [native.children removeAllObjects];
    [native.children addObject:root];
    NSMutableString *xml = [NSMutableString stringWithString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"];
    CNDCCFileSerialize(native, xml);
    NSData *data = [xml dataUsingEncoding:NSUTF8StringEncoding];
    if (data.length > nativeData.length) {
        if (error) *error = CNDCCFileError(@"The valid Pulsar CAML exceeds the existing native file's capacity.");
        return nil;
    }
    // In-place overwrite cannot truncate. XML whitespace is valid padding and
    // avoids the NUL tail produced by a shorter source vnode overwrite.
    NSMutableData *padded = [data mutableCopy];
    NSUInteger length = padded.length;
    [padded setLength:nativeData.length];
    memset((uint8_t *)padded.mutableBytes + length, ' ', padded.length - length);
    if (!CNDCCFileXML(padded)) {
        if (error) *error = CNDCCFileError(@"The final padded resource did not parse as CAML.");
        return nil;
    }
    return padded;
}

static NSURL *CNDCCFileDataDirectory(void)
{
    NSURL *support = [[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory
        inDomains:NSUserDomainMask].firstObject;
    return [support URLByAppendingPathComponent:@"CCThemingFileBacking" isDirectory:YES];
}

#if !defined(CND_CC_FILE_BACKING_TESTING)
static NSString *CNDCCFileCurrentBuild(void)
{
    char value[64] = {0};
    size_t length = sizeof(value);
    return sysctlbyname("kern.osversion", value, &length, NULL, 0) == 0 ? @(value) : @"";
}
#endif

static NSString *CNDCCFileTarget(NSURL *root, NSString *path)
{
    return [root URLByAppendingPathComponent:[path substringFromIndex:1]].path;
}

static NSDictionary *CNDCCFileFailure(NSString *path, NSString *reason)
{
    return @{@"path": path ?: @"", @"reason": reason ?: @"Resource validation failed."};
}

static NSDictionary *CNDCCFileCatalogPending(NSDictionary *route, NSString *reason)
{
    NSString *path = [route[@"targetPath"] isKindOfClass:NSString.class]
        ? route[@"targetPath"] : @"";
    NSArray *kinds = @[];
    if ([path hasSuffix:@"/ConnectivityModule.bundle/Assets.car"])
        kinds = @[@"airplaneMode", @"cellular-preview", @"hotspot-preview"];
    else if ([path hasSuffix:@"/DisplayModule.bundle/Assets.car"])
        kinds = @[@"nightShift", @"trueTone"];
    else if ([path hasSuffix:@"/CoreGlyphs.bundle/Assets.car"])
        kinds = @[@"wifi", @"cellular", @"hotspot", @"flashlight", @"qrCode", @"airPlay", @"sound"];
    else if ([path hasSuffix:@"/CoreGlyphsPrivate.bundle/Assets.car"])
        kinds = @[@"bluetooth", @"airDrop", @"vpn", @"satellite"];
    else if ([path containsString:@"/SFSymbols.framework/"])
        kinds = @[@"wifi", @"bluetooth", @"cellular", @"hotspot", @"airDrop", @"vpn",
                  @"satellite", @"flashlight", @"qrCode", @"airPlay", @"sound"];
    return @{@"path": path, @"kinds": kinds, @"reason": reason,
        @"payloadCoreUIVersion": route[@"payloadCoreUIVersion"] ?: @0,
        @"targetCoreUIVersion": route[@"targetCoreUIVersion"] ?: @0,
        @"deviceConsumptionVerified": @NO};
}

static NSString *CNDCCFileCatalogPendingReason(NSDictionary *route)
{
    if ([route[@"targetPath"] isEqualToString:
            @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"])
        return @"The traced Control Center symbols resolve from base CoreGlyphs; a priority catalog replacement does not establish coverage of that provider.";
    // The payload is admitted for a build-locked physical trial only when its
    // authoring runtime and storage schema exactly match the native iOS 26.0
    // catalog. This does not claim that device consumption has already happened.
    NSNumber *payloadVersion = [route[@"payloadCoreUIVersion"] isKindOfClass:NSNumber.class]
        ? route[@"payloadCoreUIVersion"] : nil;
    NSNumber *targetVersion = [route[@"targetCoreUIVersion"] isKindOfClass:NSNumber.class]
        ? route[@"targetCoreUIVersion"] : nil;
    NSNumber *payloadStorage = [route[@"payloadStorageVersion"] isKindOfClass:NSNumber.class]
        ? route[@"payloadStorageVersion"] : nil;
    NSNumber *targetStorage = [route[@"targetStorageVersion"] isKindOfClass:NSNumber.class]
        ? route[@"targetStorageVersion"] : nil;
    if (!payloadVersion || !targetVersion || payloadVersion.unsignedIntegerValue != 970 ||
        targetVersion.unsignedIntegerValue != 970 || !payloadStorage || !targetStorage ||
        payloadStorage.unsignedIntegerValue != 17 || targetStorage.unsignedIntegerValue != 17)
        return @"The catalog has no compatible CoreUI 970 authoring contract for build 23A341; host validation does not establish device consumption.";
    if (![route[@"nativeAuthoringRuntimeVerified"] isKindOfClass:NSNumber.class] ||
        ![route[@"nativeAuthoringRuntimeVerified"] boolValue] ||
        ![route[@"nativeAuthoringRuntimeBuild"] isEqualToString:@"23A343"])
        return @"The catalog was not authored by the pinned iOS 26.0 CoreUI 970 runtime.";
    return nil;
}

static BOOL CNDCCFileRelativeResourceValid(NSString *resource, NSString *extension)
{
    return [resource isKindOfClass:NSString.class] && resource.length &&
        ![resource hasPrefix:@"/"] && ![[resource pathComponents] containsObject:@".."] &&
        [resource.pathExtension isEqualToString:extension];
}

static BOOL CNDCCFileCatalogProofValid(NSDictionary *route, NSURL *artworkDirectory)
{
    NSString *resource = [route[@"preservationProofResource"] isKindOfClass:NSString.class]
        ? route[@"preservationProofResource"] : nil;
    NSString *digest = route[@"preservationProofSHA256"];
    if (!CNDCCFileRelativeResourceValid(resource, @"json") || !CNDCCFileDigestValid(digest)) return NO;
    NSURL *proofURL = [artworkDirectory URLByAppendingPathComponent:resource];
    NSData *data = CNDCCFileRead(proofURL.path);
    if (!data || ![CNDCCFileSHA(data) isEqualToString:digest]) return NO;
    NSDictionary *proof = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if (![proof isKindOfClass:NSDictionary.class] ||
        ![proof[@"targetPath"] isEqualToString:route[@"targetPath"]] ||
        ![proof[@"stockSHA256"] isEqualToString:route[@"stockSHA256"]] ||
        ![proof[@"payloadSHA256"] isEqualToString:route[@"payloadSHA256"]]) return NO;
    for (NSString *key in @[@"allUnrelatedBlocksByteIdentical", @"nativeHeaderPreserved",
                            @"lookupKeysAndTreesPreserved",
                            @"allTargetVectorAndCachedImageVariantsReplaced"])
        if (![proof[key] isKindOfClass:NSNumber.class] || ![proof[key] boolValue] ||
            ![route[key] isKindOfClass:NSNumber.class] || ![route[key] boolValue]) return NO;
    return YES;
}

static NSDictionary *CNDCCFileReport(BOOL apply, NSString *build,
    NSArray *applied, NSArray *failed, NSArray *pending, NSArray *absent,
    NSUInteger writes, BOOL success, BOOL rollbackComplete)
{
    NSMutableArray *catalogPreservation = [NSMutableArray array];
    NSMutableArray *catalogCaveats = [NSMutableArray array];
    for (NSDictionary *row in applied) {
        NSDictionary *preservation = row[@"catalogPreservation"];
        if (![preservation isKindOfClass:NSDictionary.class]) continue;
        [catalogPreservation addObject:preservation];
        if (apply && [preservation[@"priorityOverride"] boolValue] &&
            ![preservation[@"stockPriorityVariantFidelityVerified"] boolValue])
            [catalogCaveats addObject:@"The priority override retains all stock priority symbol names, but exact original weight/variant fidelity is unverified. The base CoreGlyphs catalog is untouched; overrides apply globally."];
    }
    return @{
        @"schemaVersion": @3, @"mode": apply ? @"physical-pulsar-file-backing-apply" : @"physical-pulsar-file-backing-restore",
        @"success": @(success), @"complete": @(success && !pending.count),
        @"productBuildVersion": build ?: @"", @"installationScope": @"native-resource-files",
        @"applied": applied, @"failed": failed, @"pendingFileBackedRoutes": pending,
        @"absentOptionalVariants": absent, @"targetFileWrites": @(writes),
        @"catalogPreservation": catalogPreservation, @"catalogCaveats": catalogCaveats,
        @"retiredCatalogFiles": @[], @"retiredCatalogFileCount": @0,
        @"appliedFileCount": @(apply ? applied.count : 0),
        @"restoredFileCount": @(apply ? 0 : applied.count),
        @"rollbackComplete": @(rollbackComplete), @"requiresSpringBoardRefresh": @(writes > 0),
        @"nativeResourceWritesVerified": @(apply && success && applied.count > 0),
        @"nativeProviderLoadsModifiedFiles": @NO,
        @"nativeProviderConsumptionVerified": @NO,
        @"samePIDPersistenceVerified": @NO, @"rebootPersistenceVerified": @NO,
        @"residentAdaptersInstalled": @NO, @"providerFactoryActive": @NO,
        @"controlCenterPresentationRequired": @NO, @"recursiveViewWalkUsedForApply": @NO,
        @"glyphPresentationWrites": @0, @"controlActions": @0, @"radioWrites": @0,
        @"excludedKinds": @[@"focusReduceInterruptions", @"focusCustom", @"hearing"],
        @"failureReason": failed.count ? failed.firstObject[@"reason"] : @"",
    };
}

static NSDictionary *CNDCCFileReportWithCatalogRetirements(NSDictionary *report, NSArray *retired)
{
    NSMutableDictionary *result = [report mutableCopy];
    result[@"retiredCatalogFiles"] = retired;
    result[@"retiredCatalogFileCount"] = @(retired.count);
    return result;
}

static BOOL CNDCCFileMkdir(NSURL *url)
{
    if (![[NSFileManager defaultManager] createDirectoryAtURL:url
        withIntermediateDirectories:YES attributes:nil error:NULL]) return NO;
    return chmod(url.fileSystemRepresentation, 0755) == 0;
}

static NSDictionary *CNDCCFileExportCatalogDiagnostic(NSData *current, NSURL *journalDirectory)
{
    if (!current.length || current.length > CNDCCMaximumResourceLength)
        return @{@"saved": @NO, @"reason": @"The target is unavailable or exceeds the resource size limit."};
    NSURL *directory;
#if defined(CND_CC_FILE_BACKING_TESTING)
    directory = [journalDirectory URLByAppendingPathComponent:@"CatalogDiagnostics" isDirectory:YES];
#else
    (void)journalDirectory;
    NSURL *documents = [[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory
        inDomains:NSUserDomainMask].firstObject;
    directory = [[documents URLByAppendingPathComponent:@"CCTheming" isDirectory:YES]
        URLByAppendingPathComponent:@"CatalogDiagnostics" isDirectory:YES];
#endif
    NSString *digest = CNDCCFileSHA(current);
    NSURL *url = [directory URLByAppendingPathComponent:[digest stringByAppendingPathExtension:@"car"]];
    BOOL saved = CNDCCFileMkdir(directory) && CNDCCFileSave(current, url);
    return @{@"saved": @(saved), @"path": url.path ?: @"", @"sha256": digest,
        @"length": @(current.length), @"reason": saved ? @"" : @"Saving the local diagnostic catalog did not verify."};
}

static BOOL CNDCCFileBackupValid(NSDictionary *entry, NSURL *directory)
{
    if (![entry isKindOfClass:NSDictionary.class] ||
        ![entry[@"path"] isKindOfClass:NSString.class] ||
        ![entry[@"kind"] isKindOfClass:NSString.class] ||
        ![entry[@"length"] isKindOfClass:NSNumber.class] ||
        [entry[@"length"] unsignedIntegerValue] == 0 ||
        [entry[@"length"] unsignedIntegerValue] > CNDCCMaximumResourceLength ||
        !CNDCCFileDigestValid(entry[@"originalSHA256"]) ||
        !CNDCCFileDigestValid(entry[@"payloadSHA256"]) ||
        ![@[@"prepared", @"writing", @"applied", @"restored", @"catalog-retiring"] containsObject:entry[@"state"]]) return NO;
    NSString *name = entry[@"backupName"];
    NSString *payloadName = entry[@"payloadName"];
    if (![name isKindOfClass:NSString.class] || ![name.lastPathComponent isEqualToString:name] ||
        ![name.pathExtension isEqualToString:@"original"] ||
        ![payloadName isKindOfClass:NSString.class] || ![payloadName.lastPathComponent isEqualToString:payloadName] ||
        ![payloadName.pathExtension isEqualToString:@"payload"]) return NO;
    NSData *original = CNDCCFileRead([directory URLByAppendingPathComponent:name].path);
    return original.length == [entry[@"length"] unsignedIntegerValue] &&
        [CNDCCFileSHA(original) isEqualToString:entry[@"originalSHA256"]];
}

static BOOL CNDCCFilePartialWriteMatches(NSData *current, NSDictionary *entry, NSURL *directory)
{
    if (current.length != [entry[@"length"] unsignedIntegerValue] ||
        ![@[@"writing", @"catalog-retiring"] containsObject:entry[@"state"]]) return NO;
    NSData *original = CNDCCFileRead([directory URLByAppendingPathComponent:entry[@"backupName"]].path);
    NSData *payload = CNDCCFileRead([directory URLByAppendingPathComponent:entry[@"payloadName"]].path);
    if (original.length != current.length || payload.length != current.length ||
        ![CNDCCFileSHA(payload) isEqualToString:entry[@"payloadSHA256"]]) return NO;
    const uint8_t *actual = current.bytes, *before = original.bytes, *after = payload.bytes;
    // A stopped memcpy/msync may leave either old or staged bytes in a page.
    // A journal's "writing" marker is not authority to overwrite arbitrary
    // externally changed content after an app restart.
    for (NSUInteger i = 0; i < current.length; i++)
        if (actual[i] != before[i] && actual[i] != after[i]) return NO;
    return YES;
}

static BOOL CNDCCFileRestoreEntries(NSMutableArray *entries, NSURL *root,
    NSURL *directory, NSURL *journalURL, NSMutableDictionary *journal,
    CNDCCFileWriter writer, NSMutableArray *restored, NSMutableArray *failed,
    NSUInteger *writes)
{
    BOOL success = YES;
    for (NSInteger i = (NSInteger)entries.count - 1; i >= 0; i--) {
        NSMutableDictionary *entry = [entries[(NSUInteger)i] mutableCopy];
        NSString *path = entry[@"path"];
        NSString *package = path.stringByDeletingLastPathComponent;
        BOOL allowed = CNDCCFileAllowedPackages()[package] && [path.lastPathComponent isEqualToString:@"main.caml"];
        allowed |= [path isEqualToString:@"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car"];
        allowed |= [path isEqualToString:@"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car"];
        allowed |= [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"];
        allowed |= [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"];
        allowed |= [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"];
        if (!allowed || !CNDCCFileBackupValid(entry, directory)) {
            [failed addObject:CNDCCFileFailure(path, @"The durable backup or journal target is invalid; restoration was refused.")];
            success = NO;
            continue;
        }
        NSString *target = CNDCCFileTarget(root, path);
        NSData *current = CNDCCFileRead(target);
        NSString *sha = CNDCCFileSHA(current);
        if ([sha isEqualToString:entry[@"originalSHA256"]]) {
            entry[@"state"] = @"restored";
        } else {
            BOOL expected = current.length == [entry[@"length"] unsignedIntegerValue] &&
                ([sha isEqualToString:entry[@"payloadSHA256"]] ||
                 CNDCCFilePartialWriteMatches(current, entry, directory));
            if (!expected) {
                [failed addObject:CNDCCFileFailure(path, @"The target changed outside this transaction; its bytes were preserved.")];
                success = NO;
                continue;
            }
            NSString *backup = [directory URLByAppendingPathComponent:entry[@"backupName"]].path;
            (*writes)++;
            BOOL wrote = writer(target, backup);
            NSData *readback = CNDCCFileRead(target);
            if (!wrote || ![CNDCCFileSHA(readback) isEqualToString:entry[@"originalSHA256"]]) {
                [failed addObject:CNDCCFileFailure(path, @"Restoring the backed-up native resource did not verify.")];
                success = NO;
                continue;
            }
            entry[@"state"] = @"restored";
        }
        entries[(NSUInteger)i] = entry;
        journal[@"entries"] = entries;
        if (!CNDCCFileSaveJSON(journal, journalURL)) {
            [failed addObject:CNDCCFileFailure(path, @"The verified restoration could not be committed to the durable journal.")];
            success = NO;
        }
        [restored addObject:@{@"path": path, @"kind": entry[@"kind"] ?: @"", @"verified": @YES}];
    }
    return success;
}

static NSDictionary *CNDCCFileRun(BOOL apply, NSDictionary *manifest, NSURL *artworkDirectory,
    NSURL *targetRoot, NSURL *directory, NSString *build, CNDCCFileWriter writer)
{
    NSMutableArray *applied = [NSMutableArray array], *failed = [NSMutableArray array];
    NSMutableArray *pending = [NSMutableArray array], *absent = [NSMutableArray array];
    NSMutableArray *retiredCatalogs = [NSMutableArray array];
    NSUInteger writes = 0;
    if (![build isEqualToString:CNDCCFileBuild] ||
        (apply && (![manifest[@"productBuildVersion"] isEqualToString:build] ||
        [manifest[@"schemaVersion"] integerValue] != 1))) {
        [failed addObject:CNDCCFileFailure(nil, @"The file-backed resources support only the verified iOS build 23A341.")];
        return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
    }
    if (!directory.isFileURL || !targetRoot.isFileURL || !writer || !CNDCCFileMkdir(directory)) {
        [failed addObject:CNDCCFileFailure(nil, @"The durable resource/backup directory is unavailable.")];
        return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
    }
    NSURL *lockURL = [directory URLByAppendingPathComponent:@"transaction.lock"];
    int lock = open(lockURL.fileSystemRepresentation, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) {
        if (lock >= 0) close(lock);
        [failed addObject:CNDCCFileFailure(nil, @"Another Control Center file transaction owns the journal.")];
        return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
    }
    @try {
        NSURL *journalURL = [directory URLByAppendingPathComponent:@"journal.json"];
        BOOL journalExists = [[NSFileManager defaultManager] fileExistsAtPath:journalURL.path];
        NSDictionary *saved = CNDCCFileLoadJSON(journalURL);
        if (journalExists && (![saved[@"productBuildVersion"] isEqualToString:build] ||
            [saved[@"schemaVersion"] integerValue] != 1 || ![saved[@"entries"] isKindOfClass:NSArray.class])) {
            [failed addObject:CNDCCFileFailure(nil, @"The existing backup journal is unreadable or belongs to another build.")];
            return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
        }
        NSMutableDictionary *journal = saved ? [saved mutableCopy] : [@{
            @"schemaVersion": @1, @"productBuildVersion": build, @"entries": @[],
            @"state": @"prepared",
        } mutableCopy];
        NSMutableArray *entries = [journal[@"entries"] mutableCopy];
        NSMutableDictionary *priorByPath = [NSMutableDictionary dictionary];
        if (entries.count > 32) {
            [failed addObject:CNDCCFileFailure(nil, @"The resource journal exceeds the proven route limit.")];
            return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
        }
        for (NSDictionary *entry in entries) {
            if (!CNDCCFileBackupValid(entry, directory) || priorByPath[entry[@"path"]]) {
                [failed addObject:CNDCCFileFailure(nil, @"An existing journal entry/backup is invalid or duplicated.")];
                return CNDCCFileReport(apply, build, applied, failed, pending, absent, writes, NO, YES);
            }
            priorByPath[entry[@"path"]] = entry;
        }
        if (!apply) {
            BOOL restored = CNDCCFileRestoreEntries(entries, targetRoot, directory, journalURL,
                journal, writer, applied, failed, &writes);
            journal[@"state"] = restored ? @"restored" : @"restore-incomplete";
            if (!CNDCCFileSaveJSON(journal, journalURL)) {
                [failed addObject:CNDCCFileFailure(nil, @"The restoration journal could not be saved.")];
                restored = NO;
            }
            return CNDCCFileReport(NO, build, applied, failed, pending, absent, writes, restored, restored);
        }
        // Recover an interrupted in-place write before constructing a new plan.
        if ([@[@"writing", @"rollback-incomplete", @"restore-incomplete"] containsObject:journal[@"state"]]) {
            BOOL recovered = CNDCCFileRestoreEntries(entries, targetRoot, directory, journalURL,
                journal, writer, [NSMutableArray array], failed, &writes);
            if (!recovered) return CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, NO);
        }
        NSMutableArray *plans = [NSMutableArray array];
        NSArray *routes = [manifest[@"packageRoutes"] isKindOfClass:NSArray.class] ? manifest[@"packageRoutes"] : @[];
        NSMutableSet *seen = [NSMutableSet set];
        for (NSDictionary *route in routes) {
            if (![route isKindOfClass:NSDictionary.class]) {
                [failed addObject:CNDCCFileFailure(nil, @"The package route record is malformed.")];
                continue;
            }
            NSString *package = route[@"packagePath"], *kind = route[@"kind"], *sourceName = route[@"sourcePackage"];
            if (![package isKindOfClass:NSString.class] || ![CNDCCFileAllowedPackages()[package] isEqualToString:kind] ||
                [seen containsObject:package] || ![sourceName isKindOfClass:NSString.class] ||
                ![sourceName.lastPathComponent isEqualToString:sourceName] || ![sourceName.pathExtension isEqualToString:@"ca"]) {
                [failed addObject:CNDCCFileFailure(package, @"The manifest contains an unapproved/duplicate package route.")];
                continue;
            }
            [seen addObject:package];
            NSString *path = [package stringByAppendingPathComponent:@"main.caml"];
            NSString *target = CNDCCFileTarget(targetRoot, path);
            NSData *current = CNDCCFileRead(target);
            if (!current) {
                if (![[NSFileManager defaultManager] fileExistsAtPath:target]) [absent addObject:path];
                else [failed addObject:CNDCCFileFailure(path, @"The target is not a readable nonempty regular resource file.")];
                continue;
            }
            NSDictionary *prior = priorByPath[path];
            NSData *native = current;
            if (prior) {
                NSString *currentSHA = CNDCCFileSHA(current);
                if (![currentSHA isEqualToString:prior[@"originalSHA256"]] &&
                    ![currentSHA isEqualToString:prior[@"payloadSHA256"]]) {
                    [failed addObject:CNDCCFileFailure(path, @"An existing target differs from both the original and this theme; it was preserved.")];
                    continue;
                }
                native = CNDCCFileRead([directory URLByAppendingPathComponent:prior[@"backupName"]].path);
            }
            NSData *index = CNDCCFileRead(CNDCCFileTarget(targetRoot, [package stringByAppendingPathComponent:@"index.xml"]));
            id indexObject = index ? [NSPropertyListSerialization propertyListWithData:index options:0 format:NULL error:NULL] : nil;
            BOOL baseline = !route[@"stockMainSHA256"] ||
                ([CNDCCFileSHA(native) isEqualToString:route[@"stockMainSHA256"]] &&
                 native.length == [route[@"stockMainLength"] unsignedIntegerValue] &&
                 [CNDCCFileSHA(index) isEqualToString:route[@"stockIndexSHA256"]]);
            if (![indexObject isKindOfClass:NSDictionary.class] || ![indexObject[@"rootDocument"] isEqualToString:@"main.caml"] || !baseline) {
                [failed addObject:CNDCCFileFailure(path, @"The native package index or available IPSW baseline does not match.")];
                continue;
            }
            NSURL *sourceURL = [artworkDirectory URLByAppendingPathComponent:sourceName isDirectory:YES];
            NSData *source = CNDCCFileRead([sourceURL URLByAppendingPathComponent:@"main.caml"].path);
            NSData *sourceIndex = CNDCCFileRead([sourceURL URLByAppendingPathComponent:@"index.xml"].path);
            if (![CNDCCFileSHA(source) isEqualToString:route[@"sourceMainSHA256"]] ||
                ![CNDCCFileSHA(sourceIndex) isEqualToString:route[@"sourceIndexSHA256"]]) {
                [failed addObject:CNDCCFileFailure(path, @"The bundled Pulsar package differs from its artwork manifest.")];
                continue;
            }
            BOOL geometryRequired = [@[@"display", @"sound", @"focusSleep", @"focusPersonal", @"focusWork"] containsObject:kind];
            NSDictionary *geometry = route[@"artworkGeometry"];
            NSMutableDictionary *geometryImages = [NSMutableDictionary dictionary];
            NSDictionary *routeImages = [route[@"images"] isKindOfClass:NSDictionary.class] ? route[@"images"] : nil;
            for (NSString *name in routeImages) {
                NSDictionary *spec = [routeImages[name] isKindOfClass:NSDictionary.class] ? routeImages[name] : nil;
                if ([spec[@"sha256"] isKindOfClass:NSString.class]) geometryImages[name] = spec[@"sha256"];
            }
            if (geometryRequired && (![geometry isKindOfClass:NSDictionary.class] ||
                ![geometry[@"sourceImageSHA256"] isEqual:geometryImages])) {
                [failed addObject:CNDCCFileFailure(path, @"The required pinned artwork geometry or its image identities are missing/incompatible.")];
                continue;
            }
            NSString *assetIdentity = [NSString stringWithFormat:@"%@-%@", sourceName.stringByDeletingPathExtension, route[@"sourceMainSHA256"]];
            NSURL *images = [[directory URLByAppendingPathComponent:@"Assets" isDirectory:YES] URLByAppendingPathComponent:assetIdentity isDirectory:YES];
            BOOL imagesReady = CNDCCFileMkdir(images);
            NSDictionary *imageSpecs = [route[@"images"] isKindOfClass:NSDictionary.class] ? route[@"images"] : nil;
            if (!imageSpecs) imagesReady = NO;
            for (NSString *name in imageSpecs) {
                NSDictionary *spec = imageSpecs[name];
                if (![spec isKindOfClass:NSDictionary.class] || ![name.lastPathComponent isEqualToString:name] ||
                    ![name.pathExtension isEqualToString:@"png"] || !CNDCCFileDigestValid(spec[@"sha256"]) ||
                    ![spec[@"length"] isKindOfClass:NSNumber.class]) { imagesReady = NO; break; }
                NSData *png = CNDCCFileRead([sourceURL URLByAppendingPathComponent:name].path);
                const unsigned char signature[] = {137,80,78,71,13,10,26,10};
                if (png.length < 24 || memcmp(png.bytes, signature, sizeof(signature)) ||
                    png.length != [spec[@"length"] unsignedIntegerValue] ||
                    ![CNDCCFileSHA(png) isEqualToString:spec[@"sha256"]] ||
                    !CNDCCFileSave(png, [images URLByAppendingPathComponent:name])) { imagesReady = NO; break; }
            }
            NSError *prepareError = nil;
            NSData *payload = imagesReady ? CNDCCFilePrepareCAML(native, source, kind, images,
                geometry, &prepareError) : nil;
            if (!payload) {
                [failed addObject:CNDCCFileFailure(path, prepareError.localizedDescription ?: @"Pulsar image staging did not verify.")];
                continue;
            }
            NSString *identifier = CNDCCFileSHA([path dataUsingEncoding:NSUTF8StringEncoding]);
            NSString *backupName = [identifier stringByAppendingString:@".original"];
            NSString *payloadName = [identifier stringByAppendingString:@".payload"];
            if ((!prior && !CNDCCFileSave(native, [directory URLByAppendingPathComponent:backupName])) ||
                !CNDCCFileSave(payload, [directory URLByAppendingPathComponent:payloadName])) {
                [failed addObject:CNDCCFileFailure(path, @"The original backup or prepared payload could not be saved/read back.")];
                continue;
            }
            [plans addObject:[@{@"path": path, @"kind": kind, @"backupName": backupName,
                @"payloadName": payloadName, @"originalSHA256": CNDCCFileSHA(native),
                @"payloadSHA256": CNDCCFileSHA(payload), @"indexSHA256": CNDCCFileSHA(index),
                @"beforeSHA256": CNDCCFileSHA(current), @"length": @(native.length),
                @"state": @"prepared", @"baseline": route[@"baseline"] ?: @"device-package-preflight",
                @"nativeGeometryAndStateContractPreserved": @YES} mutableCopy]];
        }
        NSDictionary *catalogManifest = CNDCCFileLoadJSON([artworkDirectory URLByAppendingPathComponent:@"CatalogFileBacking.json"]);
        NSArray *catalogRoutes = [catalogManifest[@"routes"] isKindOfClass:NSArray.class] ? catalogManifest[@"routes"] : @[];
        NSMutableSet<NSString *> *unconsumedCatalogPaths = [NSMutableSet set];
        if (catalogRoutes.count) {
            for (NSDictionary *route in catalogRoutes) {
                if (![route isKindOfClass:NSDictionary.class]) {
                    [failed addObject:CNDCCFileFailure(nil, @"The catalog route record is malformed.")];
                    continue;
                }
                NSString *path = route[@"targetPath"], *resource = route[@"payloadResource"];
                BOOL priorityOverride = [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"];
                BOOL directCoreGlyphs = [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"] ||
                    [path isEqualToString:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"];
                BOOL preservationOkay;
                if (priorityOverride) {
                    preservationOkay = [route[@"baseCoreGlyphsUntouched"] isKindOfClass:NSNumber.class] &&
                        [route[@"baseCoreGlyphsUntouched"] boolValue] &&
                        [route[@"allStockPriorityNamesPresent"] isKindOfClass:NSNumber.class] &&
                        [route[@"allStockPriorityNamesPresent"] boolValue] &&
                        [route[@"stockPriorityVariantFidelityVerified"] isKindOfClass:NSNumber.class] &&
                        [route[@"globalOverrideAccepted"] isKindOfClass:NSNumber.class] &&
                        [route[@"globalOverrideAccepted"] boolValue];
                } else if (directCoreGlyphs) {
                    preservationOkay = [route[@"unrelatedRenditionsPreserved"] isKindOfClass:NSNumber.class] &&
                        [route[@"unrelatedRenditionsPreserved"] boolValue] &&
                        CNDCCFileCatalogProofValid(route, artworkDirectory);
                } else preservationOkay = [route[@"unrelatedRenditionsPreserved"] isKindOfClass:NSNumber.class] &&
                    [route[@"unrelatedRenditionsPreserved"] boolValue];
                NSSet *allowed = [NSSet setWithArray:@[
                    @"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car",
                    @"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car",
                    @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car",
                    @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car",
                    @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"]];
                if (![allowed containsObject:path] || !CNDCCFileRelativeResourceValid(resource, @"car") ||
                    [seen containsObject:path] ||
                    ![catalogManifest[@"productBuildVersion"] isEqualToString:build] ||
                    !CNDCCFileDigestValid(route[@"stockSHA256"]) || !CNDCCFileDigestValid(route[@"payloadSHA256"]) ||
                    ![route[@"payloadLength"] isKindOfClass:NSNumber.class] ||
                    ![route[@"assetutilValidated"] isKindOfClass:NSNumber.class] ||
                    !preservationOkay || ![route[@"assetutilValidated"] boolValue]) {
                    [failed addObject:CNDCCFileFailure(path, @"The catalog payload has no validated preservation/build contract.")];
                    continue;
                }
                NSString *pendingReason = CNDCCFileCatalogPendingReason(route);
                if (pendingReason) {
                    [pending addObject:CNDCCFileCatalogPending(route, pendingReason)];
                    [unconsumedCatalogPaths addObject:path];
                    continue;
                }
                [seen addObject:path];
                NSData *payload = CNDCCFileRead([artworkDirectory URLByAppendingPathComponent:resource].path);
                NSData *current = CNDCCFileRead(CNDCCFileTarget(targetRoot, path));
                NSDictionary *prior = priorByPath[path];
                NSData *native = prior ? CNDCCFileRead([directory URLByAppendingPathComponent:prior[@"backupName"]].path) : current;
                BOOL currentOkay = !prior || [CNDCCFileSHA(current) isEqualToString:prior[@"originalSHA256"]] ||
                    [CNDCCFileSHA(current) isEqualToString:prior[@"payloadSHA256"]];
                NSString *currentSHA = CNDCCFileSHA(current);
                NSString *nativeSHA = CNDCCFileSHA(native);
                NSString *payloadSHA = CNDCCFileSHA(payload);
                NSMutableArray *mismatches = [NSMutableArray array];
                if (!current) [mismatches addObject:@"target-unreadable"];
                if (!currentOkay) [mismatches addObject:@"target-journal-digest"];
                if (payload.length < 8 || memcmp(payload.bytes, "BOMStore", 8))
                    [mismatches addObject:@"payload-format"];
                if (payload.length != native.length) [mismatches addObject:@"native-payload-length"];
                if (payload.length != [route[@"payloadLength"] unsignedIntegerValue])
                    [mismatches addObject:@"manifest-payload-length"];
                if (![nativeSHA isEqualToString:route[@"stockSHA256"]]) [mismatches addObject:@"stock-digest"];
                if (![payloadSHA isEqualToString:route[@"payloadSHA256"]]) [mismatches addObject:@"payload-digest"];
                if (mismatches.count) {
                    NSMutableDictionary *failure = [CNDCCFileFailure(path,
                        [NSString stringWithFormat:@"Catalog validation failed: %@.",
                            [mismatches componentsJoinedByString:@", "]]) mutableCopy];
                    failure[@"catalogValidation"] = @{
                        @"mismatches": mismatches, @"hasJournaledOriginal": @(prior != nil),
                        @"currentReadable": @(current != nil), @"nativeReadable": @(native != nil),
                        @"payloadReadable": @(payload != nil),
                        @"currentLength": @(current.length), @"nativeLength": @(native.length),
                        @"payloadLength": @(payload.length), @"expectedLength": route[@"payloadLength"],
                        @"currentSHA256": currentSHA ?: @"", @"nativeSHA256": nativeSHA ?: @"",
                        @"payloadSHA256": payloadSHA ?: @"", @"expectedStockSHA256": route[@"stockSHA256"],
                        @"expectedPayloadSHA256": route[@"payloadSHA256"],
                    };
                    // Export the readable snapshot to the app's Documents
                    // directory for stock provenance review. This is evidence
                    // only; it never authorizes or performs a target overwrite.
                    failure[@"catalogDiagnosticExport"] = CNDCCFileExportCatalogDiagnostic(current, directory);
                    [failed addObject:failure];
                    continue;
                }
                NSString *identifier = CNDCCFileSHA([path dataUsingEncoding:NSUTF8StringEncoding]);
                NSString *backupName = [identifier stringByAppendingString:@".original"];
                NSString *payloadName = [identifier stringByAppendingString:@".payload"];
                if ((!prior && !CNDCCFileSave(native, [directory URLByAppendingPathComponent:backupName])) ||
                    !CNDCCFileSave(payload, [directory URLByAppendingPathComponent:payloadName])) {
                    [failed addObject:CNDCCFileFailure(path, @"The catalog original/payload staging did not verify.")];
                    continue;
                }
                [plans addObject:[@{@"path": path, @"kind": route[@"kind"] ?: @"catalog",
                    @"backupName": backupName, @"payloadName": payloadName,
                    @"originalSHA256": CNDCCFileSHA(native), @"payloadSHA256": CNDCCFileSHA(payload),
                    @"beforeSHA256": CNDCCFileSHA(current), @"length": @(native.length),
                    @"catalogPreservation": @{
                        @"targetPath": path, @"priorityOverride": @(priorityOverride),
                        @"baseCoreGlyphsUntouched": @(priorityOverride || [route[@"baseCoreGlyphsUntouched"] boolValue]),
                        @"allStockPriorityNamesPresent": @([route[@"allStockPriorityNamesPresent"] boolValue]),
                        @"stockPriorityVariantFidelityVerified": @([route[@"stockPriorityVariantFidelityVerified"] boolValue]),
                        @"unrelatedRenditionsPreserved": @(!priorityOverride && [route[@"unrelatedRenditionsPreserved"] boolValue]),
                        @"globalOverrideAccepted": @([route[@"globalOverrideAccepted"] boolValue]),
                        @"nativeHeaderPreserved": @([route[@"nativeHeaderPreserved"] boolValue]),
                        @"lookupKeysAndTreesPreserved": @([route[@"lookupKeysAndTreesPreserved"] boolValue]),
                        @"allUnrelatedBlocksByteIdentical": @([route[@"allUnrelatedBlocksByteIdentical"] boolValue]),
                        @"allTargetVectorAndCachedImageVariantsReplaced": @([route[@"allTargetVectorAndCachedImageVariantsReplaced"] boolValue]),
                        @"nativeAuthoringRuntimeVerified": @([route[@"nativeAuthoringRuntimeVerified"] boolValue]),
                    },
                    @"state": @"prepared"} mutableCopy]];
            }
        }
        if (![seen containsObject:@"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car"] &&
            ![unconsumedCatalogPaths containsObject:@"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car"]) {
            [pending addObject:@{@"path": @"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car",
                @"kinds": @[@"airplaneMode", @"cellular-preview", @"hotspot-preview"],
                @"reason": @"No complete catalog payload with verified preservation of unrelated renditions is bundled."}];
        }
        if (![seen containsObject:@"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car"] &&
            ![unconsumedCatalogPaths containsObject:@"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car"]) {
            [pending addObject:@{@"path": @"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car",
                @"kinds": @[@"nightShift", @"trueTone"],
                @"reason": @"No complete DisplayModule catalog payload with native rendition preservation is bundled."}];
        }
        if (![seen containsObject:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"] &&
            ![unconsumedCatalogPaths containsObject:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car"]) {
            [pending addObject:@{@"path": @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car",
                @"kinds": @[@"wifi", @"cellular", @"hotspot", @"flashlight", @"qrCode", @"airPlay", @"sound"],
                @"reason": @"The traced public system symbols require a verified native CoreUI 970 base-CoreGlyphs route; a CoreGlyphsPriority replacement cannot satisfy this provider."}];
        }
        if (![seen containsObject:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"] &&
            ![unconsumedCatalogPaths containsObject:@"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car"]) {
            [pending addObject:@{@"path": @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car",
                @"kinds": @[@"bluetooth", @"airDrop", @"vpn", @"satellite"],
                @"reason": @"The traced private system symbols require a verified native CoreUI 970 CoreGlyphsPrivate route."}];
        }
        // Retire only the journaled catalogs that this Apply no longer admits.
        // Old payloads must not remain mounted merely because future writes are
        // skipped. Validate every target first and keep all CAML entries intact.
        NSSet *catalogPaths = [NSSet setWithArray:@[
            @"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car",
            @"/System/Library/ControlCenter/Bundles/DisplayModule.bundle/Assets.car",
            @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphs.bundle/Assets.car",
            @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPrivate.bundle/Assets.car",
            @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car"]];
        NSMutableArray *catalogRetirements = [NSMutableArray array];
        for (NSDictionary *entry in entries) {
            NSString *path = entry[@"path"];
            if (![catalogPaths containsObject:path] || [seen containsObject:path]) continue;
            NSString *sha = CNDCCFileSHA(CNDCCFileRead(CNDCCFileTarget(targetRoot, path)));
            if (![sha isEqualToString:entry[@"originalSHA256"]] &&
                ![sha isEqualToString:entry[@"payloadSHA256"]]) {
                [failed addObject:CNDCCFileFailure(path,
                    @"The obsolete catalog differs from both journaled original and payload; its bytes and recovery entry were preserved.")];
                continue;
            }
            NSMutableDictionary *retirement = [entry mutableCopy];
            retirement[@"retirementBeforeSHA256"] = sha;
            [catalogRetirements addObject:retirement];
        }
        // One malformed reachable package blocks the transaction before any
        // system write. Missing optional layout variants are reported separately.
        if (failed.count || (!plans.count && !catalogRetirements.count)) {
            if (!plans.count && !failed.count) [failed addObject:CNDCCFileFailure(nil, @"No proven native resource file is present on this device.")];
            return CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, YES);
        }
        for (NSMutableDictionary *retirement in catalogRetirements) {
            NSString *path = retirement[@"path"];
            NSString *target = CNDCCFileTarget(targetRoot, path);
            NSString *currentSHA = CNDCCFileSHA(CNDCCFileRead(target));
            if (![currentSHA isEqualToString:retirement[@"retirementBeforeSHA256"]]) {
                [failed addObject:CNDCCFileFailure(path,
                    @"The obsolete catalog changed after retirement preflight; its recovery entry was retained.")];
                return CNDCCFileReportWithCatalogRetirements(
                    CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, YES), retiredCatalogs);
            }
            BOOL alreadyStock = [currentSHA isEqualToString:retirement[@"originalSHA256"]];
            if (!alreadyStock) {
                retirement[@"state"] = @"catalog-retiring";
                NSUInteger index = [entries indexOfObjectPassingTest:^BOOL(NSDictionary *entry, NSUInteger i, BOOL *stop) {
                    (void)i; (void)stop; return [entry[@"path"] isEqualToString:path];
                }];
                if (index == NSNotFound) {
                    [failed addObject:CNDCCFileFailure(path, @"The catalog recovery entry disappeared before restoration.")];
                    return CNDCCFileReportWithCatalogRetirements(
                        CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, NO), retiredCatalogs);
                }
                entries[index] = retirement;
                journal[@"entries"] = entries;
                journal[@"state"] = @"catalog-retiring";
                if (!CNDCCFileSaveJSON(journal, journalURL)) {
                    [failed addObject:CNDCCFileFailure(path, @"Catalog retirement could not be journaled before restoration.")];
                    return CNDCCFileReportWithCatalogRetirements(
                        CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, NO), retiredCatalogs);
                }
                writes++;
                BOOL wrote = writer(target, [directory URLByAppendingPathComponent:retirement[@"backupName"]].path);
                if (!wrote || ![CNDCCFileSHA(CNDCCFileRead(target)) isEqualToString:retirement[@"originalSHA256"]]) {
                    [failed addObject:CNDCCFileFailure(path,
                        @"Restoring the obsolete catalog did not verify; its original backup and recovery entry were retained.")];
                    journal[@"state"] = @"catalog-retirement-incomplete";
                    (void)CNDCCFileSaveJSON(journal, journalURL);
                    return CNDCCFileReportWithCatalogRetirements(
                        CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, NO), retiredCatalogs);
                }
            }
            [entries filterUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSDictionary *entry, NSDictionary *bindings) {
                (void)bindings; return ![entry[@"path"] isEqualToString:path];
            }]];
            journal[@"entries"] = entries;
            journal[@"state"] = @"catalog-retiring";
            if (!CNDCCFileSaveJSON(journal, journalURL)) {
                [failed addObject:CNDCCFileFailure(path,
                    @"The native catalog is restored, but retirement could not be committed; its durable backup remains available.")];
                return CNDCCFileReportWithCatalogRetirements(
                    CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, NO), retiredCatalogs);
            }
            [retiredCatalogs addObject:@{@"path": path, @"kind": retirement[@"kind"] ?: @"catalog",
                @"verified": @YES, @"alreadyStock": @(alreadyStock), @"originalBackupRetained": @YES}];
        }
        NSMutableArray *newEntries = [NSMutableArray array];
        NSMutableSet *plannedPaths = [NSMutableSet set];
        for (NSDictionary *plan in plans) [plannedPaths addObject:plan[@"path"]];
        for (NSDictionary *old in entries) if (![plannedPaths containsObject:old[@"path"]]) [newEntries addObject:old];
        [newEntries addObjectsFromArray:plans];
        journal[@"entries"] = newEntries;
        journal[@"state"] = @"prepared";
        if (!CNDCCFileSaveJSON(journal, journalURL)) {
            [failed addObject:CNDCCFileFailure(nil, @"The complete backup plan could not be durably journaled before target writes.")];
            return CNDCCFileReportWithCatalogRetirements(
                CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, NO, YES), retiredCatalogs);
        }
        for (NSMutableDictionary *entry in plans) {
            NSString *target = CNDCCFileTarget(targetRoot, entry[@"path"]);
            NSString *currentSHA = CNDCCFileSHA(CNDCCFileRead(target));
            if (![currentSHA isEqualToString:entry[@"beforeSHA256"]]) {
                [failed addObject:CNDCCFileFailure(entry[@"path"], @"The target changed after preflight and before its write.")];
                break;
            }
            if ([currentSHA isEqualToString:entry[@"payloadSHA256"]]) {
                entry[@"state"] = @"applied";
                NSMutableDictionary *row = [@{@"path": entry[@"path"], @"kind": entry[@"kind"], @"verified": @YES, @"alreadyApplied": @YES} mutableCopy];
                if (entry[@"catalogPreservation"]) row[@"catalogPreservation"] = entry[@"catalogPreservation"];
                [applied addObject:row];
                continue;
            }
            entry[@"state"] = @"writing";
            journal[@"state"] = @"writing";
            if (!CNDCCFileSaveJSON(journal, journalURL)) {
                [failed addObject:CNDCCFileFailure(entry[@"path"], @"The before-write journal could not be saved.")];
                break;
            }
            writes++;
            BOOL wrote = writer(target, [directory URLByAppendingPathComponent:entry[@"payloadName"]].path);
            NSData *readback = CNDCCFileRead(target);
            if (!wrote || readback.length != [entry[@"length"] unsignedIntegerValue] ||
                ![CNDCCFileSHA(readback) isEqualToString:entry[@"payloadSHA256"]]) {
                [failed addObject:CNDCCFileFailure(entry[@"path"], @"The native resource overwrite did not verify; the transaction will roll back.")];
                break;
            }
            entry[@"state"] = @"applied";
            NSMutableDictionary *row = [@{@"path": entry[@"path"], @"kind": entry[@"kind"], @"verified": @YES} mutableCopy];
            if (entry[@"catalogPreservation"]) row[@"catalogPreservation"] = entry[@"catalogPreservation"];
            [applied addObject:row];
            if (!CNDCCFileSaveJSON(journal, journalURL)) {
                [failed addObject:CNDCCFileFailure(entry[@"path"], @"The verified write could not be committed to its journal.")];
                break;
            }
        }
        BOOL rolledBack = YES;
        if (failed.count) {
            NSMutableArray *rollbackFailures = [NSMutableArray array];
            rolledBack = CNDCCFileRestoreEntries(newEntries, targetRoot, directory, journalURL,
                journal, writer, [NSMutableArray array], rollbackFailures, &writes);
            [failed addObjectsFromArray:rollbackFailures];
            [applied removeAllObjects];
            journal[@"state"] = rolledBack ? @"rolled-back" : @"rollback-incomplete";
        } else journal[@"state"] = @"applied";
        if (!CNDCCFileSaveJSON(journal, journalURL)) {
            BOOL wasSuccessful = !failed.count;
            [failed addObject:CNDCCFileFailure(nil, @"The final resource transaction state could not be saved.")];
            if (wasSuccessful) {
                NSMutableArray *rollbackFailures = [NSMutableArray array];
                rolledBack = CNDCCFileRestoreEntries(newEntries, targetRoot, directory, journalURL,
                    journal, writer, [NSMutableArray array], rollbackFailures, &writes);
                [failed addObjectsFromArray:rollbackFailures];
                [applied removeAllObjects];
                journal[@"state"] = rolledBack ? @"rolled-back" : @"rollback-incomplete";
                (void)CNDCCFileSaveJSON(journal, journalURL);
            }
        }
        return CNDCCFileReportWithCatalogRetirements(
            CNDCCFileReport(YES, build, applied, failed, pending, absent, writes, !failed.count, rolledBack), retiredCatalogs);
    } @finally {
        (void)flock(lock, LOCK_UN);
        close(lock);
    }
}

#if !defined(CND_CC_FILE_BACKING_TESTING)
static NSURL *CNDCCFileArtworkDirectory(void)
{
    return [[NSBundle mainBundle] URLForResource:@"PulsarControlCenter" withExtension:@"bundle"];
}
#endif

NSDictionary<NSString *, id> *CNDCCThemingFileBackingApply(void)
{
#if defined(CND_CC_FILE_BACKING_TESTING)
    return @{};
#else
    NSURL *artwork = CNDCCFileArtworkDirectory();
    NSDictionary *manifest = CNDCCFileLoadJSON([artwork URLByAppendingPathComponent:@"FileBacking.json"]);
    return CNDCCFileRun(YES, manifest, artwork, [NSURL fileURLWithPath:@"/" isDirectory:YES],
        CNDCCFileDataDirectory(), CNDCCFileCurrentBuild(), ^BOOL(NSString *target, NSString *source) {
            return overwrite_system_file((char *)target.fileSystemRepresentation,
                                         (char *)source.fileSystemRepresentation) == 0;
        });
#endif
}

NSDictionary<NSString *, id> *CNDCCThemingFileBackingRestore(void)
{
#if defined(CND_CC_FILE_BACKING_TESTING)
    return @{};
#else
    return CNDCCFileRun(NO, nil, CNDCCFileArtworkDirectory(), [NSURL fileURLWithPath:@"/" isDirectory:YES],
        CNDCCFileDataDirectory(), CNDCCFileCurrentBuild(), ^BOOL(NSString *target, NSString *source) {
            return overwrite_system_file((char *)target.fileSystemRepresentation,
                                         (char *)source.fileSystemRepresentation) == 0;
        });
#endif
}

BOOL CNDCCThemingFileBackingHasJournaledState(void)
{
    NSDictionary *journal = CNDCCFileLoadJSON([CNDCCFileDataDirectory() URLByAppendingPathComponent:@"journal.json"]);
    if (![journal[@"entries"] isKindOfClass:NSArray.class]) return NO;
    for (NSDictionary *entry in journal[@"entries"]) {
        if (![entry isKindOfClass:NSDictionary.class]) return YES;
        if (![@[@"restored", @"prepared"] containsObject:entry[@"state"]]) return YES;
    }
    return NO;
}

#if defined(CND_CC_FILE_BACKING_TESTING)
NSDictionary *CNDCCThemingFileBackingRunFixture(BOOL apply, NSDictionary *manifest,
    NSURL *artworkDirectory, NSURL *targetRoot, NSURL *journalDirectory,
    NSString *productBuildVersion, CNDCCFileBackingTestWriter writer)
{
    return CNDCCFileRun(apply, manifest, artworkDirectory, targetRoot, journalDirectory,
        productBuildVersion, writer);
}
NSData *CNDCCThemingFileBackingPrepareFixture(NSData *nativeMain, NSData *sourceMain,
    NSString *kind, NSURL *imageDirectory, NSError **error)
{
    return CNDCCFilePrepareCAML(nativeMain, sourceMain, kind, imageDirectory, nil, error);
}
NSData *CNDCCThemingFileBackingPrepareGeometryFixture(NSData *nativeMain, NSData *sourceMain,
    NSString *kind, NSURL *imageDirectory, NSDictionary *geometry, NSError **error)
{
    return CNDCCFilePrepareCAML(nativeMain, sourceMain, kind, imageDirectory, geometry, error);
}
#endif
