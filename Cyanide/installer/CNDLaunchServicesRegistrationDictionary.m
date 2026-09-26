#import "CNDLaunchServicesRegistrationDictionary.h"
#import "CNDLaunchServicesRegistration.h"

#import <Security/Security.h>
#import <dlfcn.h>
#import <objc/message.h>

typedef OSStatus (*CNDSecStaticCodeCreate)(
    CFURLRef path,
    uint32_t flags,
    CFDictionaryRef _Nullable attributes,
    CFTypeRef _Nullable *staticCode);

typedef OSStatus (*CNDSecCodeCopySigningInformation)(
    CFTypeRef code,
    uint32_t flags,
    CFDictionaryRef _Nullable *information);

// This is the signing-information flag used by the sourced registration
// implementation to request the embedded entitlement dictionary.
static const uint32_t CNDLSRequirementInformation = 1U << 2;

static NSDictionary<NSString *, id> *cnd_ls_info_result(
    BOOL ok,
    NSString *stage,
    NSString *message,
    NSDictionary<NSString *, id> *details)
{
    NSMutableDictionary<NSString *, id> *result = details
        ? [details mutableCopy] : [NSMutableDictionary dictionary];
    result[@"ok"] = @(ok);
    result[@"stage"] = stage ?: @"unknown";
    result[@"message"] = message ?: @"";
    return result;
}

static NSString *cnd_ls_canonical_path(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0) return nil;
    return path.stringByStandardizingPath.stringByResolvingSymlinksInPath;
}

static CFStringRef cnd_ls_security_dictionary_key(const char *symbol)
{
    if (!symbol) return NULL;
    CFStringRef *keyAddress = (CFStringRef *)dlsym(RTLD_DEFAULT, symbol);
    return keyAddress ? *keyAddress : NULL;
}

static id cnd_ls_signing_value(NSDictionary *signingInfo,
                               const char *symbol,
                               NSString *fallbackKey)
{
    CFStringRef key = cnd_ls_security_dictionary_key(symbol);
    id value = key ? signingInfo[(__bridge NSString *)key] : nil;
    return value ?: signingInfo[fallbackKey];
}

static NSDictionary<NSString *, id> *cnd_ls_copy_signing_info(
    NSString *executablePath,
    NSString **failureOut)
{
    CNDSecStaticCodeCreate createCode =
        (CNDSecStaticCodeCreate)dlsym(
            RTLD_DEFAULT, "SecStaticCodeCreateWithPathAndAttributes");
    CNDSecCodeCopySigningInformation copyInfo =
        (CNDSecCodeCopySigningInformation)dlsym(
            RTLD_DEFAULT, "SecCodeCopySigningInformation");
    if (!createCode || !copyInfo) {
        if (failureOut) {
            *failureOut = @"the Security signing-information API is unavailable";
        }
        return nil;
    }

    NSURL *executableURL = [NSURL fileURLWithPath:executablePath isDirectory:NO];
    CFTypeRef code = NULL;
    OSStatus createStatus = createCode(
        (__bridge CFURLRef)executableURL, 0, NULL, &code);
    if (createStatus != errSecSuccess || !code) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"SecStaticCodeCreateWithPathAndAttributes failed (%d)",
                (int)createStatus];
        }
        if (code) CFRelease(code);
        return nil;
    }

    CFDictionaryRef copiedInfo = NULL;
    OSStatus copyStatus = copyInfo(
        code, CNDLSRequirementInformation, &copiedInfo);
    CFRelease(code);
    if (copyStatus != errSecSuccess || !copiedInfo) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"SecCodeCopySigningInformation failed (%d)",
                (int)copyStatus];
        }
        if (copiedInfo) CFRelease(copiedInfo);
        return nil;
    }

    NSDictionary *signingInfo = CFBridgingRelease(copiedInfo);
    if (![signingInfo isKindOfClass:NSDictionary.class]) {
        if (failureOut) *failureOut = @"Security returned invalid signing metadata";
        return nil;
    }
    return signingInfo;
}

static BOOL cnd_ls_is_property_list(id value)
{
    if (!value) return NO;
    NSError *error = nil;
    NSData *data = [NSPropertyListSerialization
        dataWithPropertyList:value
                      format:NSPropertyListBinaryFormat_v1_0
                     options:0
                       error:&error];
    return data.length > 0 && error == nil;
}

static BOOL cnd_ls_entitlement_bool(NSDictionary *entitlements,
                                    NSString *key,
                                    BOOL fallback)
{
    id value = entitlements[key];
    return [value respondsToSelector:@selector(boolValue)]
        ? [value boolValue] : fallback;
}

static BOOL cnd_ls_is_containerized(NSDictionary *entitlements)
{
    if (cnd_ls_entitlement_bool(
            entitlements, @"com.apple.private.security.no-container", NO) ||
        cnd_ls_entitlement_bool(
            entitlements, @"com.apple.private.security.no-sandbox", NO)) {
        return NO;
    }

    id required = entitlements[@"com.apple.private.security.container-required"];
    if ([required isKindOfClass:NSNumber.class]) {
        return [required boolValue];
    }
    return YES;
}

static NSDictionary<NSString *, NSString *> *
cnd_ls_resolve_application_groups(NSDictionary *entitlements,
                                  NSString **failureOut)
{
    id rawGroups = entitlements[@"com.apple.security.application-groups"];
    if (!rawGroups) return @{};
    if (![rawGroups isKindOfClass:NSArray.class]) {
        if (failureOut) {
            *failureOut = @"the application-groups entitlement is not an array";
        }
        return nil;
    }

    NSMutableDictionary<NSString *, NSString *> *containers =
        [NSMutableDictionary dictionary];
    for (id rawIdentifier in (NSArray *)rawGroups) {
        if (![rawIdentifier isKindOfClass:NSString.class] ||
            [(NSString *)rawIdentifier length] == 0) {
            if (failureOut) {
                *failureOut = @"the application-groups entitlement contains an invalid identifier";
            }
            return nil;
        }
        NSString *identifier = rawIdentifier;
        NSURL *containerURL = [[NSFileManager defaultManager]
            containerURLForSecurityApplicationGroupIdentifier:identifier];
        NSString *containerPath = cnd_ls_canonical_path(containerURL.path);
        if (containerPath.length == 0) {
            if (failureOut) {
                *failureOut = [NSString stringWithFormat:
                    @"could not resolve the current container for application group %@",
                    identifier];
            }
            return nil;
        }
        containers[identifier] = containerPath;
    }
    return containers;
}

static id cnd_ls_msg0(id object, NSString *selectorName)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (!object || ![object respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static BOOL cnd_ls_bool0(id object, NSString *selectorName, BOOL fallback)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (!object || ![object respondsToSelector:selector]) return fallback;
    return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector);
}

static uint64_t cnd_ls_uint0(id object, NSString *selectorName,
                             uint64_t fallback)
{
    SEL selector = NSSelectorFromString(selectorName);
    if (!object || ![object respondsToSelector:selector]) return fallback;
    return ((uint64_t (*)(id, SEL))objc_msgSend)(object, selector);
}

static uint64_t cnd_ls_number0(id object, NSString *selectorName,
                               uint64_t fallback)
{
    id value = cnd_ls_msg0(object, selectorName);
    return [value respondsToSelector:@selector(unsignedLongLongValue)]
        ? [value unsignedLongLongValue] : fallback;
}

static NSDictionary *cnd_ls_unwrap_dictionary(id value)
{
    if ([value isKindOfClass:NSDictionary.class]) return value;
    id propertyList = cnd_ls_msg0(value, @"propertyList");
    if (![propertyList isKindOfClass:NSDictionary.class]) {
        propertyList = cnd_ls_msg0(value,
            @"_expensiveDictionaryRepresentation");
    }
    return [propertyList isKindOfClass:NSDictionary.class] ? propertyList : nil;
}

static NSString *cnd_ls_url_path(id value)
{
    if (![value isKindOfClass:NSURL.class]) return nil;
    return cnd_ls_canonical_path([(NSURL *)value path]);
}

static NSDictionary<NSString *, NSString *> *
cnd_ls_container_paths(id rawContainerURLs)
{
    if (![rawContainerURLs isKindOfClass:NSDictionary.class]) return @{};
    NSMutableDictionary<NSString *, NSString *> *paths =
        [NSMutableDictionary dictionary];
    [(NSDictionary *)rawContainerURLs enumerateKeysAndObjectsUsingBlock:
        ^(id key, id value, BOOL *stop) {
            (void)stop;
            NSString *path = cnd_ls_url_path(value);
            if ([key isKindOfClass:NSString.class] && path.length > 0) {
                paths[key] = path;
            }
        }];
    return paths;
}

static NSDictionary<NSString *, id> *
cnd_ls_registration_for_proxy(id proxy,
                              NSString *ownerBundleIdentifier,
                              NSArray *explicitPlugins,
                              NSString **failureOut)
{
    id record = cnd_ls_msg0(proxy, @"correspondingApplicationRecord");
    NSDictionary *info = cnd_ls_unwrap_dictionary(
        cnd_ls_msg0(record, @"infoDictionary"));
    if (!info) {
        info = cnd_ls_unwrap_dictionary(cnd_ls_msg0(proxy, @"_infoDictionary"));
    }

    NSString *bundleIdentifier = cnd_ls_msg0(proxy, @"bundleIdentifier");
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0) {
        bundleIdentifier = info[@"CFBundleIdentifier"];
    }
    NSString *bundlePath = cnd_ls_url_path(cnd_ls_msg0(proxy, @"bundleURL"));
    NSString *containerPath = cnd_ls_url_path(
        cnd_ls_msg0(record, @"dataContainerURL"));
    if (containerPath.length == 0) {
        containerPath = cnd_ls_url_path(cnd_ls_msg0(proxy, @"dataContainerURL"));
    }
    NSDictionary *entitlements = cnd_ls_unwrap_dictionary(
        cnd_ls_msg0(record, @"entitlements"));
    if (!entitlements) {
        entitlements = cnd_ls_unwrap_dictionary(cnd_ls_msg0(proxy, @"entitlements"));
    }

    if (![info isKindOfClass:NSDictionary.class] ||
        bundleIdentifier.length == 0 || bundlePath.length == 0 ||
        ![entitlements isKindOfClass:NSDictionary.class]) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"LaunchServices did not expose complete identity metadata for %@",
                bundleIdentifier ?: @"the target"];
        }
        return nil;
    }

    BOOL isPlugin = ownerBundleIdentifier.length > 0;
    BOOL containerized = cnd_ls_bool0(proxy, @"isContainerized", YES);
    if (containerized && containerPath.length == 0) {
        if (failureOut) {
            *failureOut = [NSString stringWithFormat:
                @"LaunchServices did not expose %@'s existing data container; refusing to replace its record",
                bundleIdentifier];
        }
        return nil;
    }

    NSMutableDictionary<NSString *, id> *registration = [info mutableCopy];
    registration[@"ApplicationType"] = isPlugin
        ? @"PluginKitPlugin" : (cnd_ls_msg0(proxy, @"applicationType") ?: @"User");
    registration[@"BundleNameIsLocalized"] = @YES;
    registration[@"CFBundleIdentifier"] = bundleIdentifier;
    registration[@"CodeInfoIdentifier"] = bundleIdentifier;
    registration[@"CompatibilityState"] =
        @(cnd_ls_uint0(proxy, @"compatibilityState", 0));
    registration[@"Entitlements"] = entitlements;
    registration[@"IsContainerized"] = @(containerized);
    registration[@"Path"] = bundlePath;
    if (containerPath.length > 0) registration[@"Container"] = containerPath;

    NSDictionary *environment = cnd_ls_unwrap_dictionary(
        cnd_ls_msg0(proxy, @"environmentVariables"));
    if (environment.count > 0) {
        registration[@"EnvironmentVariables"] = environment;
    } else if (containerPath.length > 0) {
        registration[@"EnvironmentVariables"] = @{
            @"CFFIXED_USER_HOME": containerPath,
            @"HOME": containerPath,
            @"TMPDIR": [containerPath stringByAppendingPathComponent:@"tmp"],
        };
    }

    id signerIdentity = cnd_ls_msg0(record, @"signerIdentity") ?:
        cnd_ls_msg0(proxy, @"signerIdentity");
    id signerOrganization = cnd_ls_msg0(record, @"signerOrganization") ?:
        cnd_ls_msg0(proxy, @"signerOrganization");
    id teamIdentifier = cnd_ls_msg0(record, @"teamIdentifier") ?:
        cnd_ls_msg0(proxy, @"teamID");
    registration[@"SignerIdentity"] =
        [signerIdentity isKindOfClass:NSString.class]
            ? signerIdentity : @"Apple iPhone OS Application Signing";
    registration[@"SignerOrganization"] =
        [signerOrganization isKindOfClass:NSString.class]
            ? signerOrganization : @"Apple Inc.";
    if ([teamIdentifier isKindOfClass:NSString.class] &&
        [teamIdentifier length] > 0) {
        registration[@"TeamIdentifier"] = teamIdentifier;
    }
    registration[@"SignatureVersion"] =
        @(cnd_ls_uint0(record, @"codeSignatureVersion", 132352));

    if (isPlugin) {
        registration[@"PluginOwnerBundleID"] = ownerBundleIdentifier;
    } else {
        registration[@"FamilyID"] = @(cnd_ls_number0(proxy, @"familyID", 0));
        registration[@"HasMIDBasedSINF"] =
            @(cnd_ls_bool0(proxy, @"hasMIDBasedSINF", NO));
        registration[@"IsAdHocSigned"] =
            @(cnd_ls_bool0(proxy, @"isAdHocCodeSigned", YES));
        registration[@"IsDeletable"] =
            @(cnd_ls_bool0(proxy, @"isDeletable", YES));
        registration[@"IsOnDemandInstallCapable"] =
            @(cnd_ls_bool0(proxy, @"supportsODR", NO));
        registration[@"LSInstallType"] =
            @(cnd_ls_uint0(proxy, @"installType", 1));
        registration[@"MissingSINF"] =
            @(cnd_ls_bool0(proxy, @"missingRequiredSINF", NO));
    }

    NSDictionary *groupContainers = cnd_ls_container_paths(
        cnd_ls_msg0(record, @"groupContainerURLs") ?:
        cnd_ls_msg0(proxy, @"groupContainerURLs"));
    if (groupContainers.count > 0) {
        registration[@"GroupContainers"] = groupContainers;
        NSArray *applicationGroups =
            entitlements[@"com.apple.security.application-groups"];
        NSArray *systemGroups = entitlements[@"com.apple.security.system-groups"];
        if ([applicationGroups isKindOfClass:NSArray.class] &&
            applicationGroups.count > 0) {
            registration[@"HasAppGroupContainers"] = @YES;
        }
        if ([systemGroups isKindOfClass:NSArray.class] &&
            systemGroups.count > 0) {
            registration[@"HasSystemGroupContainers"] = @YES;
        }
    }

    if (!isPlugin) {
        NSMutableDictionary *pluginRegistrations = [NSMutableDictionary dictionary];
        id rawPlugins = explicitPlugins ?: cnd_ls_msg0(proxy, @"plugInKitPlugins");
        if ([rawPlugins isKindOfClass:NSArray.class]) {
            for (id pluginProxy in (NSArray *)rawPlugins) {
                NSString *pluginFailure = nil;
                NSDictionary *plugin = cnd_ls_registration_for_proxy(
                    pluginProxy, bundleIdentifier, nil, &pluginFailure);
                NSString *pluginIdentifier = plugin[@"CFBundleIdentifier"];
                if (!plugin || pluginIdentifier.length == 0) {
                    if (failureOut) *failureOut = pluginFailure ?:
                        @"an installed plug-in record could not be preserved";
                    return nil;
                }
                pluginRegistrations[pluginIdentifier] = plugin;
            }
        }
        registration[@"_LSBundlePlugins"] = pluginRegistrations;
    }

    if (!cnd_ls_is_property_list(registration)) {
        if (failureOut) *failureOut =
            @"the captured LaunchServices identity is not property-list serializable";
        return nil;
    }
    return registration;
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopySelfRegistrationDictionary(void)
{
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundlePath = cnd_ls_canonical_path(bundle.bundlePath);
    NSDictionary *info = bundle.infoDictionary;
    NSString *bundleIdentifier = info[@"CFBundleIdentifier"];
    NSString *executableName = info[@"CFBundleExecutable"];
    if (bundlePath.length == 0 || bundleIdentifier.length == 0 ||
        executableName.length == 0) {
        return cnd_ls_info_result(NO, @"bundle-identity",
            @"the running application has incomplete bundle identity metadata",
            nil);
    }

    // This path is intentionally scoped to Cyanide's current user-app
    // installation. It must never synthesize a System application record.
    if (![bundlePath hasPrefix:@"/private/var/containers/Bundle/Application/"] &&
        ![bundlePath hasPrefix:@"/var/containers/Bundle/Application/"]) {
        return cnd_ls_info_result(NO, @"bundle-location",
            @"the running bundle is not a user application-container installation", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
            });
    }

    NSString *executablePath = [bundlePath
        stringByAppendingPathComponent:executableName];
    BOOL executableIsDirectory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:executablePath
                                               isDirectory:&executableIsDirectory] ||
        executableIsDirectory) {
        return cnd_ls_info_result(NO, @"bundle-executable",
            @"the running bundle's main executable could not be resolved", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
            });
    }

    NSString *signingFailure = nil;
    NSDictionary *signingInfo =
        cnd_ls_copy_signing_info(executablePath, &signingFailure);
    NSDictionary *entitlements = cnd_ls_signing_value(
        signingInfo, "kSecCodeInfoEntitlementsDict", @"entitlements-dict");
    if (![entitlements isKindOfClass:NSDictionary.class] ||
        !cnd_ls_is_property_list(entitlements)) {
        return cnd_ls_info_result(NO, @"signing-entitlements",
            signingFailure ?: @"the exact signed entitlement dictionary could not be read", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
            });
    }

    NSString *codeInfoIdentifier = cnd_ls_signing_value(
        signingInfo, "kSecCodeInfoIdentifier", @"identifier");
    if (![codeInfoIdentifier isKindOfClass:NSString.class] ||
        codeInfoIdentifier.length == 0) {
        codeInfoIdentifier = bundleIdentifier;
    }

    NSString *containerPath = cnd_ls_canonical_path(NSHomeDirectory());
    if (containerPath.length == 0 ||
        (![containerPath hasPrefix:@"/private/var/mobile/Containers/Data/Application/"] &&
         ![containerPath hasPrefix:@"/var/mobile/Containers/Data/Application/"])) {
        return cnd_ls_info_result(NO, @"data-container",
            @"the current user data-container path could not be established", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
                @"containerPath": containerPath ?: @"",
            });
    }

    NSString *pluginsPath = [bundlePath stringByAppendingPathComponent:@"PlugIns"];
    NSArray<NSString *> *plugins = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:pluginsPath error:nil];
    if (plugins.count > 0) {
        return cnd_ls_info_result(NO, @"plugins-unsupported",
            @"the current build contains plug-ins; Phase 2 refuses to omit their existing registration records", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
                @"pluginCount": @(plugins.count),
            });
    }

    id systemGroups = entitlements[@"com.apple.security.system-groups"];
    if ([systemGroups isKindOfClass:NSArray.class] &&
        [(NSArray *)systemGroups count] > 0) {
        return cnd_ls_info_result(NO, @"system-groups-unsupported",
            @"the current build uses system-group containers; Phase 2 refuses to synthesize their paths", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
                @"systemGroupCount": @([(NSArray *)systemGroups count]),
            });
    }

    NSString *groupFailure = nil;
    NSDictionary<NSString *, NSString *> *groupContainers =
        cnd_ls_resolve_application_groups(entitlements, &groupFailure);
    if (!groupContainers) {
        return cnd_ls_info_result(NO, @"application-groups",
            groupFailure ?: @"the current application-group containers could not be resolved", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
            });
    }

    BOOL containerized = cnd_ls_is_containerized(entitlements);
    NSMutableDictionary<NSString *, id> *registration = [@{
        @"ApplicationType": @"User",
        @"BundleNameIsLocalized": @YES,
        @"CFBundleIdentifier": bundleIdentifier,
        @"CodeInfoIdentifier": codeInfoIdentifier,
        @"CompatibilityState": @0,
        @"Container": containerPath,
        @"Entitlements": entitlements,
        @"EnvironmentVariables": @{
            @"CFFIXED_USER_HOME": containerized ? containerPath : @"/var/mobile",
            @"HOME": containerized ? containerPath : @"/var/mobile",
            @"TMPDIR": containerized
                ? [containerPath stringByAppendingPathComponent:@"tmp"]
                : @"/var/tmp",
        },
        @"FamilyID": @0,
        @"HasMIDBasedSINF": @NO,
        @"IsAdHocSigned": @YES,
        @"IsContainerized": @(containerized),
        @"IsDeletable": @YES,
        @"IsOnDemandInstallCapable": @NO,
        @"LSInstallType": @1,
        @"MissingSINF": @NO,
        @"Path": bundlePath,
        @"SignatureVersion": @132352,
        @"SignerIdentity": @"Apple iPhone OS Application Signing",
        @"SignerOrganization": @"Apple Inc.",
        @"_LSBundlePlugins": @{},
    } mutableCopy];

    NSString *teamIdentifier = entitlements[@"com.apple.developer.team-identifier"];
    if (![teamIdentifier isKindOfClass:NSString.class] || teamIdentifier.length == 0) {
        teamIdentifier = cnd_ls_signing_value(
            signingInfo, "kSecCodeInfoTeamIdentifier", @"teamid");
    }
    if ([teamIdentifier isKindOfClass:NSString.class] && teamIdentifier.length > 0) {
        registration[@"TeamIdentifier"] = teamIdentifier;
    }
    if (groupContainers.count > 0) {
        registration[@"HasAppGroupContainers"] = @YES;
        registration[@"GroupContainers"] = groupContainers;
    }

    if (!cnd_ls_is_property_list(registration)) {
        return cnd_ls_info_result(NO, @"registration-serialization",
            @"the synthesized registration dictionary is not a property list", @{
                @"bundleIdentifier": bundleIdentifier,
                @"bundlePath": bundlePath,
            });
    }

    return cnd_ls_info_result(YES, @"registration-ready",
        @"the current installation identity was captured without contacting installd", @{
            @"bundleIdentifier": bundleIdentifier,
            @"bundlePath": bundlePath,
            @"containerPath": containerPath,
            @"entitlementCount": @(entitlements.count),
            @"applicationGroupCount": @(groupContainers.count),
            @"pluginCount": @0,
            @"registrationDictionary": registration,
        });
}

static NSDictionary<NSString *, id> *
cnd_ls_copy_registration_dictionary_for_bundle_identifier(
    NSString *bundleIdentifier, BOOL retainSession)
{
    if (![bundleIdentifier isKindOfClass:NSString.class] ||
        bundleIdentifier.length == 0) {
        return cnd_ls_info_result(NO, @"target-identifier",
            @"the target bundle identifier is empty", nil);
    }

    NSDictionary<NSString *, id> *installdCapture = retainSession
        ? CNDLaunchServicesCopyApplicationProxyArchiveViaInstalldRetainingSession(
            bundleIdentifier)
        : CNDLaunchServicesCopyApplicationProxyArchiveViaInstalld(
            bundleIdentifier);
    NSData *proxyArchive = installdCapture[@"proxyArchive"];
    if (![installdCapture[@"ok"] boolValue] ||
        ![proxyArchive isKindOfClass:NSData.class] ||
        proxyArchive.length == 0) {
        NSDictionary *failure = cnd_ls_info_result(NO, @"installd-capture",
            @"stock installd could not return the target LaunchServices identity", @{
                @"bundleIdentifier": bundleIdentifier,
                @"installdCapture": installdCapture ?: @{},
            });
        if (retainSession) CNDLaunchServicesFinishRetainedInstalldSession();
        return failure;
    }

    dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices",
           RTLD_NOW | RTLD_LOCAL);
    id archiveRoot = nil;
    @try {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        archiveRoot = [NSKeyedUnarchiver unarchiveObjectWithData:proxyArchive];
#pragma clang diagnostic pop
    } @catch (NSException *exception) {
        NSDictionary *failure = cnd_ls_info_result(NO, @"proxy-decode",
            @"kslop could not decode installd's detached LaunchServices proxy", @{
                @"bundleIdentifier": bundleIdentifier,
                @"exception": exception.description ?: @"unknown",
                @"installdCapture": installdCapture,
            });
        if (retainSession) CNDLaunchServicesFinishRetainedInstalldSession();
        return failure;
    }
    NSDictionary *archiveEnvelope = [archiveRoot isKindOfClass:NSDictionary.class]
        ? archiveRoot : nil;
    id proxy = archiveEnvelope[@"application"];
    NSArray *explicitPlugins = [archiveEnvelope[@"plugins"]
        isKindOfClass:NSArray.class] ? archiveEnvelope[@"plugins"] : nil;
    NSString *decodedIdentifier = cnd_ls_msg0(proxy, @"bundleIdentifier");
    if (!archiveEnvelope || !proxy || !explicitPlugins ||
        ![decodedIdentifier isEqual:bundleIdentifier]) {
        NSDictionary *failure = cnd_ls_info_result(NO, @"proxy-identity",
            @"installd's decoded proxy envelope did not match the requested application", @{
                @"bundleIdentifier": bundleIdentifier,
                @"decodedBundleIdentifier": decodedIdentifier ?: @"",
                @"installdCapture": installdCapture,
            });
        if (retainSession) CNDLaunchServicesFinishRetainedInstalldSession();
        return failure;
    }

    NSString *failure = nil;
    NSDictionary *registration = cnd_ls_registration_for_proxy(
        proxy, nil, explicitPlugins, &failure);
    if (!registration) {
        NSDictionary *identityFailure = cnd_ls_info_result(NO, @"target-identity",
            failure ?: @"the target LaunchServices identity could not be captured", @{
                @"bundleIdentifier": bundleIdentifier,
                @"installdCapture": installdCapture,
            });
        if (retainSession) CNDLaunchServicesFinishRetainedInstalldSession();
        return identityFailure;
    }

    NSDictionary *plugins = registration[@"_LSBundlePlugins"];
    NSDictionary *entitlements = registration[@"Entitlements"];
    NSDictionary *groupContainers = registration[@"GroupContainers"];
    return cnd_ls_info_result(YES, @"registration-ready",
        @"stock installd resolved the bundle identifier and supplied its complete identity", @{
            @"bundleIdentifier": bundleIdentifier,
            @"bundlePath": registration[@"Path"] ?: @"",
            @"containerPath": registration[@"Container"] ?: @"",
            @"entitlementCount": @([entitlements isKindOfClass:NSDictionary.class]
                ? entitlements.count : 0),
            @"applicationGroupCount": @([groupContainers isKindOfClass:NSDictionary.class]
                ? groupContainers.count : 0),
            @"pluginCount": @([plugins isKindOfClass:NSDictionary.class]
                ? plugins.count : 0),
            @"installdSessionRetained": @(retainSession),
            @"installdCapture": installdCapture,
            @"registrationDictionary": registration,
        });
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifier(
    NSString *bundleIdentifier)
{
    return cnd_ls_copy_registration_dictionary_for_bundle_identifier(
        bundleIdentifier, NO);
}

NSDictionary<NSString *, id> *
CNDLaunchServicesCopyRegistrationDictionaryForBundleIdentifierRetainingSession(
    NSString *bundleIdentifier)
{
    return cnd_ls_copy_registration_dictionary_for_bundle_identifier(
        bundleIdentifier, YES);
}
