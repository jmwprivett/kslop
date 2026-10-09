#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <QuartzCore/QuartzCore.h>
#import "../../Cyanide/tweaks/CNDCCThemingFileBacking.h"
#include <fcntl.h>
#include <unistd.h>

@interface CAPackage : NSObject
+ (instancetype)packageWithContentsOfURL:(NSURL *)url type:(NSString *)type
                                options:(NSDictionary *)options error:(NSError **)error;
- (CALayer *)rootLayer;
@end

static BOOL HasImage(CALayer *layer)
{
    if (layer.contents) return YES;
    for (CALayer *child in layer.sublayers) if (HasImage(child)) return YES;
    return NO;
}

static void Check(BOOL condition, NSString *message)
{
    if (!condition) { fprintf(stderr, "FAIL: %s\n", message.UTF8String); exit(1); }
}

static NSString *SHA(NSData *data)
{
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, result);
    NSMutableString *text = [NSMutableString string];
    for (NSUInteger i = 0; i < sizeof(result); i++) [text appendFormat:@"%02x", result[i]];
    return text;
}

static NSDictionary *JSON(NSURL *url)
{
    return [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:url] options:0 error:NULL];
}

static void Save(NSData *data, NSURL *url)
{
    [[NSFileManager defaultManager] createDirectoryAtURL:url.URLByDeletingLastPathComponent
        withIntermediateDirectories:YES attributes:nil error:NULL];
    Check([data writeToURL:url options:NSDataWritingAtomic error:NULL],
          [@"fixture file save: " stringByAppendingString:url.path ?: @"(nil)"]);
}

static NSURL *Target(NSURL *root, NSString *path)
{
    return [root URLByAppendingPathComponent:[path substringFromIndex:1]];
}

static BOOL Write(NSString *target, NSString *source)
{
    NSData *data = [NSData dataWithContentsOfFile:source];
    return [data writeToFile:target options:0 error:NULL];
}

static void CheckNativeRoot(NSData *native, NSData *payload)
{
    NSXMLDocument *original = [[NSXMLDocument alloc] initWithData:native options:0 error:NULL];
    NSXMLDocument *result = [[NSXMLDocument alloc] initWithData:payload options:0 error:NULL];
    NSXMLElement *originalLayer = (NSXMLElement *)[original.rootElement.children filteredArrayUsingPredicate:
        [NSPredicate predicateWithBlock:^BOOL(NSXMLNode *node, NSDictionary *bindings) {
            (void)bindings; return [node.name isEqualToString:@"CALayer"];
        }]].firstObject;
    NSXMLElement *resultLayer = (NSXMLElement *)[result.rootElement.children filteredArrayUsingPredicate:
        [NSPredicate predicateWithBlock:^BOOL(NSXMLNode *node, NSDictionary *bindings) {
            (void)bindings; return [node.name isEqualToString:@"CALayer"];
        }]].firstObject;
    for (NSString *key in @[@"bounds", @"position", @"transform"]) {
        NSString *before = [originalLayer attributeForName:key].stringValue;
        NSString *after = [resultLayer attributeForName:key].stringValue;
        Check((!before && !after) || [before isEqualToString:after], [@"native root preserved: " stringByAppendingString:key]);
    }
    NSArray *states = [original nodesForXPath:@"//*[local-name()='LKState']/@name" error:NULL];
    NSArray *newStates = [result nodesForXPath:@"//*[local-name()='LKState']/@name" error:NULL];
    NSMutableSet *names = [NSMutableSet set];
    for (NSXMLNode *state in newStates) [names addObject:state.stringValue];
    for (NSXMLNode *state in states) Check([names containsObject:state.stringValue], @"every native state retained");
}

// These device-preflight ReplayKit variants have no exported IPSW baseline.
// Exercise their state contract explicitly instead of silently skipping them.
static NSData *ReplayKitNative(NSArray<NSString *> *names)
{
    NSMutableString *xml = [NSMutableString stringWithString:
        @"<caml xmlns=\"http://www.apple.com/CoreAnimation/1.0\"><CALayer bounds=\"0 0 36 36\" position=\"18 18\"><states>"];
    for (NSString *name in names) [xml appendFormat:@"<LKState name=\"%@\"/>", name];
    [xml appendString:@"</states></CALayer></caml>"];
    NSData *data = [xml dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *padded = [data mutableCopy];
    [padded setLength:24576];
    memset((uint8_t *)padded.mutableBytes + data.length, ' ', padded.length - data.length);
    return padded;
}

static void CheckReplayKit(NSURL *artwork, NSURL *temporary)
{
    NSData *source = [NSData dataWithContentsOfURL:[artwork URLByAppendingPathComponent:@"ScreenRecording.ca/main.caml"]];
    NSData *native = ReplayKitNative(@[@"countdown", @"recording", @"recording-static", @"disabled", @"off", @"on"]);
    NSError *error = nil;
    NSData *payload = CNDCCThemingFileBackingPrepareFixture(native, source, @"screenRecording", temporary, &error);
    Check(payload != nil, [NSString stringWithFormat:@"ReplayKit native static recording state prepares: %@", error]);
    Check(payload.length == native.length, @"ReplayKit retains fixed native resource length");
    CheckNativeRoot(native, payload);
    NSXMLDocument *result = [[NSXMLDocument alloc] initWithData:payload options:0 error:NULL];
    Check([[result nodesForXPath:@"//*[local-name()='LKState'][@name='recording-static' and @basedOn='recording']" error:NULL] count] == 1,
          @"ReplayKit static presentation inherits Pulsar's recording artwork");
    Check([[result nodesForXPath:@"//*[local-name()='LKState'][@name='recording']/*[local-name()='elements']" error:NULL] count] == 1,
          @"ReplayKit retains inherited recording artwork values");
    for (NSString *state in @[@"recording", @"recording-static", @"on"]) {
        NSString *entry = [NSString stringWithFormat:@"//*[local-name()='LKStateTransition'][@toState='%@']//*[local-name()='animation'][@repeatCount='Inf']", state];
        Check([[result nodesForXPath:entry error:NULL] count] == 2,
              [@"Pulsar opacity/scale pulse reaches native recording state: " stringByAppendingString:state]);
        NSString *exit = [NSString stringWithFormat:@"//*[local-name()='LKStateTransition'][@fromState='%@' and @toState='*']", state];
        Check([[result nodesForXPath:exit error:NULL] count] == 1,
              [@"Pulsar pulse exit reaches native recording state: " stringByAppendingString:state]);
    }
    Check([[result nodesForXPath:@"//*[local-name()='LKStateTransition'][@toState='countdown']//*[local-name()='animation'][@beginTime]" error:NULL] count] == 12,
          @"Pulsar's original timed three-number countdown is retained");

    error = nil;
    NSData *unknown = CNDCCThemingFileBackingPrepareFixture(ReplayKitNative(@[@"unexpected-recording-state"]),
        source, @"screenRecording", temporary, &error);
    Check(unknown == nil && [error.localizedDescription containsString:@"screenRecording/unexpected-recording-state"],
          @"unknown ReplayKit state fails closed with the native state name");
    NSString *withoutRecording = [[[NSString alloc] initWithData:source encoding:NSUTF8StringEncoding]
        stringByReplacingOccurrencesOfString:@"name=\"recording\"" withString:@"name=\"other-recording\""];
    error = nil;
    NSData *missing = CNDCCThemingFileBackingPrepareFixture(ReplayKitNative(@[@"recording-static"]),
        [withoutRecording dataUsingEncoding:NSUTF8StringEncoding], @"screenRecording", temporary, &error);
    Check(missing == nil && [error.localizedDescription containsString:@"screenRecording/recording-static"],
          @"recording alias fails closed when its Pulsar source state is absent");
}

static void CheckArtworkGeometry(NSDictionary *manifest, NSURL *stock, NSURL *artwork, NSURL *temporary)
{
    NSUInteger checked = 0;
    for (NSDictionary *route in manifest[@"packageRoutes"]) {
        NSDictionary *geometry = route[@"artworkGeometry"];
        if (!geometry) continue;
        NSURL *nativePackage = Target(stock, route[@"packagePath"]);
        NSURL *sourcePackage = [artwork URLByAppendingPathComponent:route[@"sourcePackage"]];
        NSData *native = [NSData dataWithContentsOfURL:[nativePackage URLByAppendingPathComponent:@"main.caml"]];
        NSData *source = [NSData dataWithContentsOfURL:[sourcePackage URLByAppendingPathComponent:@"main.caml"]];
        NSURL *images = [temporary URLByAppendingPathComponent:[NSString stringWithFormat:@"geometry-images-%lu", (unsigned long)checked]];
        for (NSString *image in route[@"images"])
            Save([NSData dataWithContentsOfURL:[sourcePackage URLByAppendingPathComponent:image]],
                [images URLByAppendingPathComponent:image]);
        NSError *error = nil;
        NSData *payload = CNDCCThemingFileBackingPrepareGeometryFixture(native, source, route[@"kind"], images, geometry, &error);
        Check(payload != nil, [NSString stringWithFormat:@"pinned artwork layout %@: %@", route[@"packagePath"], error]);
        CheckNativeRoot(native, payload);
        NSURL *prepared = [temporary URLByAppendingPathComponent:[NSString stringWithFormat:@"geometry-%lu.ca", (unsigned long)checked]];
        Save(payload, [prepared URLByAppendingPathComponent:@"main.caml"]);
        Save([NSData dataWithContentsOfURL:[nativePackage URLByAppendingPathComponent:@"index.xml"]],
            [prepared URLByAppendingPathComponent:@"index.xml"]);
        CAPackage *original = [CAPackage packageWithContentsOfURL:sourcePackage
            type:@"com.apple.coreanimation-bundle" options:@{} error:&error];
        CAPackage *result = [CAPackage packageWithContentsOfURL:prepared
            type:@"com.apple.coreanimation-bundle" options:@{} error:&error];
        Check(original && result, @"original and adapted geometry load through native CAPackage");
        if ([@[@"sound", @"display"] containsObject:route[@"kind"]]) {
            NSXMLDocument *document = [[NSXMLDocument alloc] initWithData:payload options:0 error:NULL];
            NSArray *colors = [document nodesForXPath:@"//@fillColor | //@strokeColor | //@backgroundColor" error:NULL];
            Check(colors.count > 0, @"slider has native-template vector colors");
            for (NSXMLNode *color in colors)
                Check([color.stringValue isEqualToString:@"1 1 1"], @"slider vector follows native white/template color contract");
            NSString *backingOpacity = [route[@"kind"] isEqualToString:@"display"] ? @"0.3" : @"0.5";
            NSString *backingQuery = [NSString stringWithFormat:@"//*[local-name()='CAShapeLayer'][@opacity='%@']", backingOpacity];
            Check([[document nodesForXPath:backingQuery error:NULL] count] > 0,
                  @"Pulsar's authored lower-opacity offset backing is retained");
            CALayer *art = result.rootLayer.sublayers.firstObject;
            NSArray *levels = [result.rootLayer valueForKey:@"states"];
            Check(levels.count == [route[@"stockStates"] count], @"each native slider level has a Pulsar state");
            for (id state in levels) {
                art.hidden = YES; art.opacity = 0;
                NSArray *elements = [state valueForKey:@"elements"];
                Check(elements.count == 2, @"native level explicitly restores Pulsar artwork visibility");
                for (id element in elements) {
                    Check([element valueForKey:@"target"] == art, @"native LKState binds exact source artwork root");
                    [[element valueForKey:@"target"] setValue:[element valueForKey:@"value"]
                        forKeyPath:[element valueForKey:@"keyPath"]];
                }
                Check(!art.hidden && art.opacity == 1, @"Pulsar slider remains visible after every level reconstruction");
            }
        }
        CALayer *origin = [CALayer layer];
        original.rootLayer.position = CGPointZero;
        [origin addSublayer:original.rootLayer];
        NSArray *content = geometry[@"sourceContentBounds"], *destination = geometry[@"nativeContentBounds"];
        CGRect measured = CGRectMake([content[0] doubleValue], [content[1] doubleValue],
            [content[2] doubleValue], [content[3] doubleValue]);
        CGRect sourceCoordinates = [original.rootLayer convertRect:measured fromLayer:origin];
        CALayer *adapted = result.rootLayer.sublayers.firstObject;
        Check(adapted != nil, @"adapted resource retains the single source artwork root");
        CGRect actual = [adapted convertRect:sourceCoordinates toLayer:result.rootLayer];
        CGRect expected = CGRectMake([destination[0] doubleValue], [destination[1] doubleValue],
            [destination[2] doubleValue], [destination[3] doubleValue]);
        Check(fabs(CGRectGetMidX(actual) - CGRectGetMidX(expected)) < 0.0001 &&
              fabs(CGRectGetMidY(actual) - CGRectGetMidY(expected)) < 0.0001,
              [@"artwork center matches native content, including source anchor/transforms: " stringByAppendingString:route[@"kind"]]);
        Check(actual.size.width <= expected.size.width + 0.0001 &&
              actual.size.height <= expected.size.height + 0.0001 &&
              (fabs(actual.size.width - expected.size.width) < 0.0001 ||
               fabs(actual.size.height - expected.size.height) < 0.0001),
              @"artwork fits the native content footprint uniformly without canvas upscaling");
        Check(fabs(actual.size.width / actual.size.height - measured.size.width / measured.size.height) < 0.0001,
              @"source artwork aspect ratio preserved");
        NSMutableDictionary *stale = [geometry mutableCopy];
        stale[@"nativeMainSHA256"] = @"changed";
        error = nil;
        Check(!CNDCCThemingFileBackingPrepareGeometryFixture(native, source, route[@"kind"], images, stale, &error) &&
              [error.localizedDescription containsString:@"pinned offline artwork geometry"],
              @"stale native geometry contract fails closed");
        stale = [geometry mutableCopy];
        stale[@"sourceContentBounds"] = @[@0, @0, @0, @40];
        error = nil;
        Check(!CNDCCThemingFileBackingPrepareGeometryFixture(native, source, route[@"kind"], images, stale, &error),
              @"zero-sized artwork geometry fails closed");
        checked++;
    }
    Check(checked == 9, @"brightness, all five volume variants, and three supplemental Focus layouts checked");
}

static void CheckLegacyCatalogRetirement(NSDictionary *fixture, NSURL *productionArtwork,
    NSURL *sourceRoot, NSURL *sourceJournal, NSURL *temporary, NSDictionary *catalogs,
    NSUInteger camlCount)
{
    NSDictionary *priority = @{
        @"kind": @"core-glyphs-priority-catalog",
        @"targetPath": @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car",
        @"payloadResource": @"CoreGlyphsPriority-23A341.car",
    };
    NSString *priorityPath = priority[@"targetPath"];
    NSUInteger activeCatalogCount = [catalogs[@"routes"] count];
    for (NSString *mode in @[@"payload", @"stock", @"conflict", @"partial"])
    {
        NSURL *root = [temporary URLByAppendingPathComponent:[@"retirement-system-" stringByAppendingString:mode]];
        NSURL *journal = [temporary URLByAppendingPathComponent:[@"retirement-journal-" stringByAppendingString:mode]];
        Check([[NSFileManager defaultManager] copyItemAtURL:sourceRoot toURL:root error:NULL] &&
              [[NSFileManager defaultManager] copyItemAtURL:sourceJournal toURL:journal error:NULL],
              @"clone local resources and durable journal for retirement scenario");
        NSURL *journalURL = [journal URLByAppendingPathComponent:@"journal.json"];
        NSMutableDictionary *state = [JSON(journalURL) mutableCopy];
        NSMutableArray *entries = [state[@"entries"] mutableCopy];
        NSData *priorityOriginal = [NSData dataWithContentsOfURL:Target(root, priorityPath)];
        NSData *priorityPayload = [NSData dataWithContentsOfURL:
            [productionArtwork URLByAppendingPathComponent:priority[@"payloadResource"]]];
        NSString *identifier = SHA([priorityPath dataUsingEncoding:NSUTF8StringEncoding]);
        NSString *backup = [identifier stringByAppendingString:@".original"];
        NSString *payload = [identifier stringByAppendingString:@".payload"];
        Save(priorityOriginal, [journal URLByAppendingPathComponent:backup]);
        Save(priorityPayload, [journal URLByAppendingPathComponent:payload]);
        [entries addObject:@{@"path": priorityPath, @"kind": priority[@"kind"],
            @"backupName": backup, @"payloadName": payload,
            @"originalSHA256": SHA(priorityOriginal), @"payloadSHA256": SHA(priorityPayload),
            @"length": @(priorityOriginal.length), @"state": @"applied"}];
        Save(priorityPayload, Target(root, priorityPath));
        state[@"entries"] = entries;
        state[@"state"] = @"applied";
        Save([NSJSONSerialization dataWithJSONObject:state options:0 error:NULL], journalURL);
        NSMutableDictionary *camlBefore = [NSMutableDictionary dictionary];
        for (NSDictionary *entry in entries)
            if ([entry[@"path"] hasSuffix:@"main.caml"])
                camlBefore[entry[@"path"]] = [NSData dataWithContentsOfURL:Target(root, entry[@"path"])];
        if ([mode isEqualToString:@"stock"])
            for (NSDictionary *entry in entries)
                if ([entry[@"path"] hasSuffix:@".car"])
                    Save([NSData dataWithContentsOfURL:[journal URLByAppendingPathComponent:entry[@"backupName"]]],
                         Target(root, entry[@"path"]));
        if ([mode isEqualToString:@"conflict"]) {
            NSMutableData *external = [priorityPayload mutableCopy];
            ((uint8_t *)external.mutableBytes)[external.length - 1] ^= 1;
            Save(external, Target(root, priorityPath));
        }
        __block NSUInteger calls = 0, catalogCalls = 0;
        CNDCCFileBackingTestWriter writer = ^BOOL(NSString *target, NSString *source) {
            calls++;
            if ([target hasSuffix:@".car"]) {
                catalogCalls++;
                if ([mode isEqualToString:@"partial"]) {
                    NSData *native = [NSData dataWithContentsOfFile:source];
                    NSMutableData *mixed = [[NSData dataWithContentsOfFile:target] mutableCopy];
                    [mixed replaceBytesInRange:NSMakeRange(0, native.length / 2) withBytes:native.bytes];
                    [mixed writeToFile:target options:0 error:NULL];
                    return NO;
                }
            }
            return Write(target, source);
        };
        NSDictionary *report = CNDCCThemingFileBackingRunFixture(YES, fixture, productionArtwork,
            root, journal, @"23A341", writer);
        if ([@[@"payload", @"stock"] containsObject:mode]) {
            Check([report[@"success"] boolValue] && [report[@"retiredCatalogFileCount"] unsignedIntegerValue] == 1,
                  @"Apply retires the obsolete priority catalog independently of active CoreUI 970 routes");
            Check(catalogCalls == ([mode isEqualToString:@"stock"] ? activeCatalogCount : 1),
                  @"active native catalogs are applied while the obsolete priority catalog is restored exactly once");
            NSArray *remaining = JSON(journalURL)[@"entries"];
            Check(remaining.count == camlCount + activeCatalogCount,
                  @"CAML and active catalog recovery entries remain after priority retirement");
            for (NSDictionary *entry in entries) {
                Check([[NSFileManager defaultManager] fileExistsAtPath:
                    [journal URLByAppendingPathComponent:entry[@"backupName"]].path],
                    @"retirement retains every original backup");
                if ([entry[@"path"] isEqualToString:priorityPath])
                    Check([SHA([NSData dataWithContentsOfURL:Target(root, entry[@"path"])])
                           isEqualToString:entry[@"originalSHA256"]], @"retired catalog equals journaled native bytes");
                else if ([entry[@"path"] hasSuffix:@".car"])
                    Check([SHA([NSData dataWithContentsOfURL:Target(root, entry[@"path"])])
                           isEqualToString:entry[@"payloadSHA256"]], @"active catalog remains on its verified payload");
            }
        } else {
            Check(![report[@"success"] boolValue] && JSON(journalURL)[@"entries"] != nil &&
                  [JSON(journalURL)[@"entries"] count] == entries.count,
                  @"conflict and partial restore retain catalog and CAML recovery entries");
            Check(calls == ([mode isEqualToString:@"conflict"] ? 0 : 1),
                  @"conflict is rejected before any target writes; partial retirement stops before CAML writes");
            for (NSString *path in camlBefore)
                Check([camlBefore[path] isEqualToData:[NSData dataWithContentsOfURL:Target(root, path)]],
                      @"failed catalog retirement leaves CAML resources unchanged");
            if ([mode isEqualToString:@"partial"]) {
                NSUInteger beforeRetry = calls;
                NSDictionary *retry = CNDCCThemingFileBackingRunFixture(YES, fixture, productionArtwork,
                    root, journal, @"23A341", writer);
                Check(![retry[@"success"] boolValue] && calls == beforeRetry,
                      @"an interrupted retirement is not interpreted as an all-CAML write recovery");
                NSDictionary *restored = CNDCCThemingFileBackingRunFixture(NO, nil, productionArtwork,
                    root, journal, @"23A341", ^BOOL(NSString *target, NSString *source) { return Write(target, source); });
                Check([restored[@"success"] boolValue],
                      @"explicit Restore can recover verified original/payload mixtures after interrupted retirement");
            }
        }
    }
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        Check(argc == 3, @"repo and temp roots required");
        NSURL *repo = [NSURL fileURLWithPath:@(argv[1]) isDirectory:YES];
        NSURL *temporary = [NSURL fileURLWithPath:@(argv[2]) isDirectory:YES];
        NSURL *artwork = [repo URLByAppendingPathComponent:@"Cyanide/PulsarControlCenter.bundle" isDirectory:YES];
        NSURL *productionArtwork = artwork;
        NSURL *stock = [repo URLByAppendingPathComponent:@"build/iOS26-23A341-CC-assets/23A341__iPhone17,2" isDirectory:YES];
        NSDictionary *manifest = JSON([artwork URLByAppendingPathComponent:@"FileBacking.json"]);
        Check([manifest[@"packageRoutes"] count] == 29, @"all 29 known package variants inventoried");
        NSUInteger verified = 0;
        for (NSDictionary *route in manifest[@"packageRoutes"]) {
            NSURL *nativeURL = [Target(stock, route[@"packagePath"]) URLByAppendingPathComponent:@"main.caml"];
            NSData *native = [NSData dataWithContentsOfURL:nativeURL];
            if (!native) continue;
            NSData *source = [NSData dataWithContentsOfURL:[[artwork URLByAppendingPathComponent:route[@"sourcePackage"]]
                URLByAppendingPathComponent:@"main.caml"]];
            NSError *error = nil;
            NSData *payload = CNDCCThemingFileBackingPrepareFixture(native, source, route[@"kind"],
                [temporary URLByAppendingPathComponent:@"images"], &error);
            Check(payload != nil, [NSString stringWithFormat:@"real native package %@: %@", route[@"packagePath"], error]);
            Check(payload.length == native.length, @"payload exactly fits native vnode length");
            CheckNativeRoot(native, payload);
            verified++;
        }
        Check(verified >= 19, @"all exported native package baselines verified");
        CheckReplayKit(artwork, temporary);
        CheckArtworkGeometry(manifest, stock, artwork, temporary);

        NSMutableArray *routes = [NSMutableArray array];
        for (NSDictionary *route in manifest[@"packageRoutes"])
            if ([@[@"appearance", @"timer", @"focusWork"] containsObject:route[@"kind"]] &&
                route[@"stockMainSHA256"] && ![route[@"packagePath"] containsString:@"_IC.ca"])
                [routes addObject:route];
        Check(routes.count == 3, @"fixture has three stateful resource routes");
        for (NSDictionary *route in manifest[@"packageRoutes"]) {
            if (![route[@"kind"] isEqualToString:@"screenRecording"]) continue;
            NSMutableDictionary *deviceReplayKit = [route mutableCopy];
            [deviceReplayKit removeObjectsForKeys:@[@"stockMainSHA256", @"stockMainLength", @"stockIndexSHA256"]];
            [routes addObject:deviceReplayKit];
        }
        Check(routes.count == 7, @"fixture includes all four device-preflight ReplayKit variants");
        NSMutableDictionary *fixture = [manifest mutableCopy];
        fixture[@"packageRoutes"] = routes;
        NSURL *targetRoot = [temporary URLByAppendingPathComponent:@"system" isDirectory:YES];
        NSURL *journal = [temporary URLByAppendingPathComponent:@"backups" isDirectory:YES];
        NSMutableDictionary<NSString *, NSData *> *originals = [NSMutableDictionary dictionary];
        for (NSDictionary *route in routes) {
            // The physical report has three present ReplayKit packages and
            // one optional absent variant. Match that preflight arrangement.
            if ([route[@"packagePath"] hasSuffix:@"/replaykit_IC.ca"]) continue;
            for (NSString *file in @[@"main.caml", @"index.xml"]) {
                NSString *path = [route[@"packagePath"] stringByAppendingPathComponent:file];
                NSData *data = [route[@"kind"] isEqualToString:@"screenRecording"]
                    ? ([file isEqualToString:@"main.caml"]
                        ? ReplayKitNative(@[@"countdown", @"recording", @"recording-static", @"disabled"])
                        : [NSData dataWithContentsOfURL:[artwork URLByAppendingPathComponent:@"ScreenRecording.ca/index.xml"]])
                    : [NSData dataWithContentsOfURL:Target(stock, path)];
                Save(data, Target(targetRoot, path));
                if ([file isEqualToString:@"main.caml"]) originals[path] = data;
            }
        }
        NSDictionary *catalogs = JSON([artwork URLByAppendingPathComponent:@"CatalogFileBacking.json"]);
        for (NSDictionary *route in catalogs[@"routes"]) {
            NSURL *original = [route[@"kind"] isEqualToString:@"connectivity-catalog"]
                ? [repo URLByAppendingPathComponent:@"build/diagnostics/20261006-physical-connectivity-catalog/Connectivity-physical-23A341.car"]
                : Target(stock, route[@"targetPath"]);
            Save([NSData dataWithContentsOfURL:original], Target(targetRoot, route[@"targetPath"]));
        }
        NSString *legacyPriorityPath = @"/System/Library/PrivateFrameworks/SFSymbols.framework/CoreGlyphsPriority.bundle/Assets.car";
        Save([NSData dataWithContentsOfURL:Target(stock, legacyPriorityPath)],
             Target(targetRoot, legacyPriorityPath));
        NSUInteger resourceCount = originals.count + [catalogs[@"routes"] count];
        __block NSUInteger writeCalls = 0;
        CNDCCFileBackingTestWriter writer = ^BOOL(NSString *target, NSString *source) {
            writeCalls++; return Write(target, source);
        };
        NSMutableDictionary *catalogOnlyPolicy = [fixture mutableCopy];
        catalogOnlyPolicy[@"packageRoutes"] = @[];
        NSURL *policyRoot = [temporary URLByAppendingPathComponent:@"native970-policy-system" isDirectory:YES];
        Check([[NSFileManager defaultManager] copyItemAtURL:targetRoot toURL:policyRoot error:NULL],
              @"clone exact native catalogs for CoreUI 970 admission checks");
        __block NSUInteger policyWrites = 0;
        CNDCCFileBackingTestWriter policyWriter = ^BOOL(NSString *target, NSString *source) {
            policyWrites++; return Write(target, source);
        };
        NSURL *policyJournal = [temporary URLByAppendingPathComponent:@"native970-catalog-journal"];
        NSDictionary *admittedCatalogs = CNDCCThemingFileBackingRunFixture(YES,
            catalogOnlyPolicy, artwork, policyRoot, policyJournal, @"23A341", policyWriter);
        Check([admittedCatalogs[@"success"] boolValue] && [admittedCatalogs[@"complete"] boolValue] &&
              [admittedCatalogs[@"pendingFileBackedRoutes"] count] == 0 &&
              policyWrites == [catalogs[@"routes"] count],
              @"genuine native-authored CoreUI 970/storage17 catalogs are admitted and written");
        Check(![admittedCatalogs[@"nativeProviderLoadsModifiedFiles"] boolValue] &&
              ![admittedCatalogs[@"nativeProviderConsumptionVerified"] boolValue],
              @"admitting a build-locked device trial does not claim provider consumption before the test");
        NSDictionary *policyRestore = CNDCCThemingFileBackingRunFixture(NO, nil, artwork,
            policyRoot, policyJournal, @"23A341", policyWriter);
        Check([policyRestore[@"success"] boolValue] && policyWrites == [catalogs[@"routes"] count] * 2,
              @"native CoreUI 970 admission fixture restores every exact catalog baseline");

        NSURL *policyArtwork = [temporary URLByAppendingPathComponent:@"invalid-native970-artwork" isDirectory:YES];
        Check([[NSFileManager defaultManager] copyItemAtURL:artwork toURL:policyArtwork error:NULL],
              @"copy local artwork for invalid CoreUI contract checks");
        for (NSDictionary *invalidContract in @[
            @{@"payloadCoreUIVersion": @975},
            @{@"targetCoreUIVersion": @971},
            @{@"payloadStorageVersion": @18},
            @{@"targetStorageVersion": @18},
            @{@"nativeAuthoringRuntimeVerified": @NO},
            @{@"nativeAuthoringRuntimeBuild": @"23A999"},
        ]) {
            NSMutableDictionary *rejected = [catalogs mutableCopy];
            NSMutableArray *rejectedRoutes = [NSMutableArray array];
            for (NSDictionary *route in catalogs[@"routes"]) {
                NSMutableDictionary *invalid = [route mutableCopy];
                [invalid addEntriesFromDictionary:invalidContract];
                [rejectedRoutes addObject:invalid];
            }
            rejected[@"routes"] = rejectedRoutes;
            Save([NSJSONSerialization dataWithJSONObject:rejected options:0 error:NULL],
                 [policyArtwork URLByAppendingPathComponent:@"CatalogFileBacking.json"]);
            NSDictionary *denied = CNDCCThemingFileBackingRunFixture(YES,
                catalogOnlyPolicy, policyArtwork, targetRoot,
                [temporary URLByAppendingPathComponent:@"invalid-compatibility-journal"], @"23A341", writer);
            Check(writeCalls == 0 && [denied[@"pendingFileBackedRoutes"] count] == [catalogs[@"routes"] count],
                  @"wrong CoreUI, storage schema, or native authoring runtime prohibits every catalog write");
        }
        NSDictionary *wrongBuild = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A999", writer);
        Check(![wrongBuild[@"success"] boolValue] && writeCalls == 0, @"build mismatch fails before writing");

        // The production report must distinguish a different native catalog
        // from a corrupt payload or vnode-length mismatch before any write.
        NSString *connectivityPath = @"/System/Library/ControlCenter/Bundles/ConnectivityModule.bundle/Assets.car";
        NSURL *connectivityTarget = Target(targetRoot, connectivityPath);
        NSData *connectivityStock = [NSData dataWithContentsOfURL:connectivityTarget];
        NSData *vmCatalog = [NSData dataWithContentsOfURL:
            [repo URLByAppendingPathComponent:@"build/ios26-cc-disk-map/files/connectivity-assets.car"]];
        Check(vmCatalog.length == connectivityStock.length && ![SHA(vmCatalog) isEqualToString:SHA(connectivityStock)],
              @"VM and physical catalog baselines have equal lengths but distinct digests");
        Save(vmCatalog, connectivityTarget);
        NSDictionary *vmMismatch = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check(![vmMismatch[@"success"] boolValue] && writeCalls == 0 &&
              [vmMismatch[@"failed"][0][@"catalogValidation"][@"mismatches"] isEqual:@[@"stock-digest"]],
              @"production contract rejects the VM-thinned baseline before any target writes");
        NSMutableData *differentCatalog = [connectivityStock mutableCopy];
        ((uint8_t *)differentCatalog.mutableBytes)[differentCatalog.length - 1] ^= 1;
        Save(differentCatalog, connectivityTarget);
        NSDictionary *digestMismatch = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        NSDictionary *digestFailure = [digestMismatch[@"failed"] firstObject];
        NSDictionary *digestEvidence = digestFailure[@"catalogValidation"];
        Check(![digestMismatch[@"success"] boolValue] && writeCalls == 0 &&
              [digestMismatch[@"rollbackComplete"] boolValue], @"unknown catalog blocks every target write");
        Check([digestFailure[@"path"] isEqualToString:connectivityPath] &&
              [digestEvidence[@"mismatches"] isEqual:@[@"stock-digest"]], @"stock digest failure is specific");
        Check([digestEvidence[@"nativeSHA256"] isEqualToString:SHA(differentCatalog)] &&
              [digestEvidence[@"expectedStockSHA256"] isEqualToString:SHA(connectivityStock)] &&
              [digestEvidence[@"nativeLength"] unsignedIntegerValue] == connectivityStock.length,
              @"report preserves actual and expected native catalog evidence");
        Check([[NSData dataWithContentsOfURL:connectivityTarget] isEqualToData:differentCatalog],
              @"unknown catalog bytes remain unchanged");
        NSDictionary *export = digestFailure[@"catalogDiagnosticExport"];
        NSString *exportPath = export[@"path"];
        Check([export[@"saved"] boolValue] &&
              [exportPath.lastPathComponent isEqualToString:[SHA(differentCatalog) stringByAppendingPathExtension:@"car"]] &&
              [exportPath.stringByDeletingLastPathComponent isEqualToString:
                  [journal URLByAppendingPathComponent:@"CatalogDiagnostics" isDirectory:YES].path],
              @"catalog evidence export uses a SHA-named file in the local diagnostics directory");
        Check([[NSData dataWithContentsOfFile:exportPath] isEqualToData:differentCatalog] &&
              [export[@"sha256"] isEqualToString:SHA(differentCatalog)] &&
              [export[@"length"] unsignedIntegerValue] == differentCatalog.length && writeCalls == 0,
              @"catalog evidence export exactly matches the target snapshot before all target writes");

        Save([connectivityStock subdataWithRange:NSMakeRange(0, connectivityStock.length - 1)], connectivityTarget);
        NSDictionary *lengthMismatch = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check([lengthMismatch[@"failed"][0][@"catalogValidation"][@"mismatches"]
              isEqual:@[@"native-payload-length", @"stock-digest"]] && writeCalls == 0,
              @"native vnode length and digest mismatches are independently reported");
        Check([[NSFileManager defaultManager] removeItemAtURL:connectivityTarget error:NULL], @"remove local catalog fixture");
        NSDictionary *missingCatalog = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        NSDictionary *missingEvidence = missingCatalog[@"failed"][0][@"catalogValidation"];
        Check([missingEvidence[@"mismatches"] containsObject:@"target-unreadable"] &&
              ![missingEvidence[@"currentReadable"] boolValue] && writeCalls == 0,
              @"missing target is distinguished from digest mismatch without writes");
        Check(![missingCatalog[@"failed"][0][@"catalogDiagnosticExport"][@"saved"] boolValue],
              @"unreadable target does not produce a catalog evidence export");
        NSURL *diagnostics = [journal URLByAppendingPathComponent:@"CatalogDiagnostics" isDirectory:YES];
        NSUInteger exportsBeforeOversize = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:diagnostics
            includingPropertiesForKeys:nil options:0 error:NULL].count;
        int largeFile = open(connectivityTarget.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL, 0600);
        Check(largeFile >= 0 && ftruncate(largeFile, ((off_t)256 << 20) + 1) == 0, @"create sparse oversize local fixture");
        close(largeFile);
        NSDictionary *oversizeCatalog = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check(![oversizeCatalog[@"failed"][0][@"catalogDiagnosticExport"][@"saved"] boolValue] &&
              ![oversizeCatalog[@"failed"][0][@"catalogValidation"][@"currentReadable"] boolValue] &&
              [[NSFileManager defaultManager] contentsOfDirectoryAtURL:diagnostics
                  includingPropertiesForKeys:nil options:0 error:NULL].count == exportsBeforeOversize && writeCalls == 0,
              @"catalog exports respect the bounded resource reader and never export oversize targets");
        Save(connectivityStock, connectivityTarget);

        NSURL *badArtwork = [temporary URLByAppendingPathComponent:@"bad-catalog-artwork" isDirectory:YES];
        for (NSDictionary *route in catalogs[@"routes"]) {
            NSString *resource = route[@"payloadResource"];
            NSData *data = [NSData dataWithContentsOfURL:[artwork URLByAppendingPathComponent:resource]];
            if ([route[@"targetPath"] isEqualToString:connectivityPath]) {
                NSMutableData *corrupt = [data mutableCopy];
                ((uint8_t *)corrupt.mutableBytes)[corrupt.length - 1] ^= 1;
                data = corrupt;
            }
            Save(data, [badArtwork URLByAppendingPathComponent:resource]);
            NSString *proof = route[@"preservationProofResource"];
            if (proof.length)
                Save([NSData dataWithContentsOfURL:[artwork URLByAppendingPathComponent:proof]],
                     [badArtwork URLByAppendingPathComponent:proof]);
        }
        Save([NSData dataWithContentsOfURL:[artwork URLByAppendingPathComponent:@"CatalogFileBacking.json"]],
             [badArtwork URLByAppendingPathComponent:@"CatalogFileBacking.json"]);
        NSMutableDictionary *catalogOnly = [fixture mutableCopy];
        catalogOnly[@"packageRoutes"] = @[];
        NSDictionary *badPayload = CNDCCThemingFileBackingRunFixture(YES, catalogOnly, badArtwork,
            targetRoot, journal, @"23A341", writer);
        Check([badPayload[@"failed"][0][@"catalogValidation"][@"mismatches"] isEqual:@[@"payload-digest"]] &&
              writeCalls == 0, @"corrupt bundled payload is distinguished from a stock digest mismatch");

        NSDictionary *installed = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check([installed[@"success"] boolValue] && writeCalls == resourceCount,
              @"verified CAML and all four native CoreUI 970 catalog writes");
        Check([installed[@"complete"] boolValue] && [installed[@"pendingFileBackedRoutes"] count] == 0,
              @"public/private glyph and module catalogs satisfy every file-backed provider route");
        Check([installed[@"absentOptionalVariants"] count] == 1,
              @"absent optional ReplayKit variant is reported without blocking three present variants");
        Check([installed[@"catalogCaveats"] count] == 0, @"obsolete priority override is not reported as installed");
        NSDictionary *stored = JSON([journal URLByAppendingPathComponent:@"journal.json"]);
        Check([stored[@"entries"] count] == resourceCount, @"all originals retained in durable journal");
        CheckLegacyCatalogRetirement(fixture, productionArtwork, targetRoot, journal, temporary,
            catalogs, originals.count);
        for (NSDictionary *entry in stored[@"entries"]) {
            NSData *current = [NSData dataWithContentsOfURL:Target(targetRoot, entry[@"path"])];
            Check([SHA(current) isEqualToString:entry[@"payloadSHA256"]], @"written readback equals staged resource digest");
            if (![entry[@"path"] hasSuffix:@"main.caml"]) continue;
            NSString *xml = [[NSString alloc] initWithData:current encoding:NSUTF8StringEncoding];
            if ([entry[@"kind"] isEqualToString:@"timer"])
                Check([xml containsString:@"position=\"24 24\""] &&
                      [xml containsString:@"bounds=\"0 0 56 56\""],
                      @"timer glyph uses native center and 1.4x artwork bounds");
            Check([xml containsString:@"file://"], @"Pulsar PNGs resolve from a persistent file URL");
            NSError *loadError = nil;
            CAPackage *package = [NSClassFromString(@"CAPackage")
                packageWithContentsOfURL:Target(targetRoot, [entry[@"path"] stringByDeletingLastPathComponent])
                type:@"com.apple.coreanimation-bundle" options:@{} error:&loadError];
            Check(package != nil, [NSString stringWithFormat:@"native CAPackage loader accepts patched resource: %@", loadError]);
            Check(HasImage(package.rootLayer), @"native loader resolved the staged Pulsar PNG URL");
        }
        NSDictionary *again = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check([again[@"success"] boolValue] && writeCalls == resourceCount, @"repeated installation is idempotent");
        NSDictionary *restored = CNDCCThemingFileBackingRunFixture(NO, nil, artwork,
            targetRoot, journal, @"23A341", writer);
        Check([restored[@"success"] boolValue] && writeCalls == resourceCount * 2, @"restore requires only persisted journal");
        for (NSString *path in originals) {
            Check([originals[path] isEqualToData:
                   [NSData dataWithContentsOfURL:Target(targetRoot, path)]], @"exact stock bytes restored");
        }

        __block NSUInteger faultCalls = 0;
        CNDCCFileBackingTestWriter faultWriter = ^BOOL(NSString *target, NSString *source) {
            if (++faultCalls == 2) {
                NSData *payload = [NSData dataWithContentsOfFile:source];
                NSMutableData *partial = [[NSData dataWithContentsOfFile:target] mutableCopy];
                [partial replaceBytesInRange:NSMakeRange(0, payload.length / 2) withBytes:payload.bytes];
                [partial writeToFile:target options:0 error:NULL];
                return NO;
            }
            return Write(target, source);
        };
        NSDictionary *fault = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", faultWriter);
        Check(![fault[@"success"] boolValue] && [fault[@"rollbackComplete"] boolValue], @"partial write rolls back transaction");
        for (NSString *path in originals) {
            Check([originals[path] isEqualToData:
                   [NSData dataWithContentsOfURL:Target(targetRoot, path)]], @"rollback restores every original");
        }
        NSString *replayPath = @"/System/Library/ControlCenter/Bundles/ReplayKitModule.bundle/replaykit.ca/main.caml";
        NSData *unknownNative = ReplayKitNative(@[@"recording-static", @"unexpected-recording-state"]);
        Save(unknownNative, Target(targetRoot, replayPath));
        NSUInteger beforeUnknown = writeCalls;
        NSDictionary *unknownReport = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, [temporary URLByAppendingPathComponent:@"unknown-state-journal"], @"23A341", writer);
        Check(![unknownReport[@"success"] boolValue] && [unknownReport[@"targetFileWrites"] unsignedIntegerValue] == 0 &&
              writeCalls == beforeUnknown && [unknownReport[@"rollbackComplete"] boolValue],
              @"one unknown ReplayKit state blocks all catalog/package writes before mutation");
        Check([unknownReport[@"failed"] count] == 1 &&
              [unknownReport[@"failed"][0][@"path"] isEqualToString:replayPath],
              @"transaction reports the exact failing ReplayKit path");
        Check([[NSData dataWithContentsOfURL:Target(targetRoot, replayPath)] isEqualToData:unknownNative],
              @"unmapped ReplayKit resource is preserved");
        Save(originals[replayPath], Target(targetRoot, replayPath));
        // A first-run device baseline is supported for confirmed packages whose
        // IPSW files were not exported, while their XML/index remain mandatory.
        NSMutableDictionary *deviceRoute = [routes.firstObject mutableCopy];
        [deviceRoute removeObjectsForKeys:@[@"stockMainSHA256", @"stockMainLength", @"stockIndexSHA256"]];
        fixture[@"packageRoutes"] = @[deviceRoute];
        NSDictionary *deviceDerived = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, journal, @"23A341", writer);
        Check([deviceDerived[@"success"] boolValue], @"strict device package preflight works without a host baseline");
        NSDictionary *tamperedEntry = nil;
        for (NSDictionary *entry in JSON([journal URLByAppendingPathComponent:@"journal.json"])[@"entries"])
            if ([entry[@"kind"] isEqualToString:deviceRoute[@"kind"]]) tamperedEntry = entry;
        Check(tamperedEntry != nil, @"active fixture entry exists");
        NSURL *tamperedTarget = Target(targetRoot, tamperedEntry[@"path"]);
        NSMutableData *otherModification = [[NSData dataWithContentsOfURL:tamperedTarget] mutableCopy];
        ((uint8_t *)otherModification.mutableBytes)[0] ^= 0x40;
        Save(otherModification, tamperedTarget);
        NSDictionary *conflict = CNDCCThemingFileBackingRunFixture(NO, nil, artwork,
            targetRoot, journal, @"23A341", writer);
        Check(![conflict[@"success"] boolValue], @"external target modification blocks restore");
        Check([[NSData dataWithContentsOfURL:tamperedTarget] isEqualToData:otherModification], @"external modification preserved");
        NSUInteger beforeUnapproved = writeCalls;

        NSMutableDictionary *badRoute = [routes.firstObject mutableCopy];
        badRoute[@"packagePath"] = @"/System/Library/Unapproved.ca";
        fixture[@"packageRoutes"] = @[badRoute];
        NSDictionary *unapproved = CNDCCThemingFileBackingRunFixture(YES, fixture, artwork,
            targetRoot, [temporary URLByAppendingPathComponent:@"new-journal"], @"23A341", writer);
        Check(![unapproved[@"success"] boolValue] && writeCalls == beforeUnapproved, @"unapproved system paths fail closed");
        printf("CC file backing: %lu native geometry/state contracts, all four CoreUI 970 catalogs, transaction/readback, durable restore, idempotency, partial rollback, build and conflict assertions passed.\n", (unsigned long)verified);
    }
    return 0;
}
