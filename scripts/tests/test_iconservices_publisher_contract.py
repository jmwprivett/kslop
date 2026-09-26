"""Host-only tests for the transport-neutral IconServices publisher contract."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_SOURCE = ROOT / "Cyanide/installer/CNDIconServicesPublisherContract.m"
CONTRACT_HEADER_DIR = CONTRACT_SOURCE.parent


HARNESS = r"""
#import "CNDIconServicesPublisher.h"
#include <stdio.h>

static int fail(const char *name) {
    fprintf(stderr, "validator fixture failed: %s\n", name);
    return 1;
}

static NSMutableDictionary *publication(BOOL batch) {
    return [@{
        @"operationCompleted": @YES,
        @"agentCacheReadbackVerified": @YES,
        @"persistentStoreReadbackVerified": @YES,
        @"transportHealthy": @YES,
        @"transportLifecycleVerified": @YES,
        @"hookRestored": @YES,
        @"hookQuiescent": @YES,
        @"hookStillInstalledAtCleanup": @NO,
        @"payloadLifecycleVerified": @YES,
        @"transactionCleaned": @YES,
        @"transportAbandoned": @NO,
        @"batchTransportBorrowed": @(batch),
        @"transportRetained": @(batch),
        @"transportClosed": @(!batch),
        @"transportLocalStateRemaining": @(batch),
        @"mode": @"replace",
        @"stockCaptured": @YES,
        @"replacementCreated": @YES,
        @"replacementReturned": @YES,
        @"triggerVerified": @YES,
    } mutableCopy];
}

static NSMutableDictionary *directPublication(BOOL batch) {
    NSMutableDictionary *result = publication(batch);
    result[@"acceptancePolicy"] = @"stock-iconservices-direct";
    result[@"customExecutablePayloadUsed"] = @NO;
    result[@"methodInterpositionUsed"] = @NO;
    result[@"payloadLifecycleRequired"] = @NO;
    result[@"stockGenerationPersisted"] = @YES;
    result[@"persistentIndexIdentitySettled"] = @YES;
    result[@"persistentIndexTokenWriteVerified"] = @YES;
    result[@"persistentIndexTokenLookupVerified"] = @YES;
    result[@"replacementPublished"] = @YES;
    result[@"directStoreRemoveVerified"] = @YES;
    result[@"directStoreWriteIssued"] = @YES;
    result[@"directStoreWriteSkippedAlreadyStock"] = @NO;
    result[@"directStoreWriteVerified"] = @YES;
    return result;
}

int main(void) {
    @autoreleasepool {
        NSMutableDictionary *batch = publication(YES);
        if (!CNDIconServicesPublisherPublicationResultIsVerified(batch)) {
            return fail("batch retained success");
        }

        /* Legacy RemoteCall-shaped keys must not control the contract. */
        batch[@"remoteOK"] = @NO;
        batch[@"sessionLifecycleVerified"] = @NO;
        batch[@"batchSessionBorrowed"] = @NO;
        batch[@"sessionRetained"] = @NO;
        batch[@"closed"] = @YES;
        batch[@"abandoned"] = @YES;
        batch[@"mappingCleaned"] = @NO;
        if (!CNDIconServicesPublisherPublicationResultIsVerified(batch)) {
            return fail("legacy transport key leaked into validator");
        }

        NSMutableDictionary *benchmarkBypass = publication(YES);
        benchmarkBypass[@"agentCacheReadbackVerified"] = @NO;
        benchmarkBypass[@"persistentStoreReadbackVerified"] = @NO;
        benchmarkBypass[@"deepVerificationSkippedForBenchmark"] = @YES;
        if (CNDIconServicesPublisherPublicationResultIsVerified(
                benchmarkBypass)) {
            return fail("benchmark bypass accepted");
        }

        for (NSString *field in @[
            @"agentCacheReadbackVerified",
            @"persistentStoreReadbackVerified"
        ]) {
            NSMutableDictionary *missing = publication(YES);
            missing[field] = @NO;
            if (CNDIconServicesPublisherPublicationResultIsVerified(missing)) {
                return fail("missing cache/store proof accepted");
            }
        }

        NSMutableDictionary *notQuiescent = publication(YES);
        notQuiescent[@"hookQuiescent"] = @NO;
        if (CNDIconServicesPublisherPublicationResultIsVerified(notQuiescent)) {
            return fail("non-quiescent hook accepted");
        }

        NSMutableDictionary *unsafePayload = publication(YES);
        unsafePayload[@"payloadLifecycleVerified"] = @NO;
        if (CNDIconServicesPublisherPublicationResultIsVerified(unsafePayload)) {
            return fail("unsafe payload lifecycle accepted");
        }

        NSMutableDictionary *standalone = publication(NO);
        if (!CNDIconServicesPublisherPublicationResultIsVerified(standalone)) {
            return fail("standalone closed success rejected");
        }

        NSMutableDictionary *wrongMode = publication(YES);
        wrongMode[@"mode"] = @"stock";
        if (CNDIconServicesPublisherPublicationResultIsVerified(wrongMode)) {
            return fail("wrong publication mode accepted");
        }

        NSMutableDictionary *wrongReplacement = publication(YES);
        wrongReplacement[@"replacementReturned"] = @NO;
        if (CNDIconServicesPublisherPublicationResultIsVerified(
                wrongReplacement)) {
            return fail("wrong replacement state accepted");
        }

        NSMutableDictionary *restoration = publication(YES);
        restoration[@"mode"] = @"stock";
        restoration[@"replacementCreated"] = @NO;
        restoration[@"replacementReturned"] = @NO;
        if (!CNDIconServicesPublisherRestorationResultIsVerified(restoration)) {
            return fail("stock restoration rejected");
        }

        NSMutableDictionary *badRestoration = [restoration mutableCopy];
        badRestoration[@"replacementCreated"] = @YES;
        if (CNDIconServicesPublisherRestorationResultIsVerified(
                badRestoration)) {
            return fail("replacement restoration accepted");
        }

        NSMutableDictionary *direct = directPublication(YES);
        if (!CNDIconServicesPublisherPublicationResultIsVerified(direct)) {
            return fail("direct remove/write publication rejected");
        }
        direct[@"directStoreRemoveVerified"] = @NO;
        if (CNDIconServicesPublisherPublicationResultIsVerified(direct)) {
            return fail("direct publication without remove proof accepted");
        }

        direct = directPublication(YES);
        direct[@"persistentIndexTokenLookupVerified"] = @NO;
        if (CNDIconServicesPublisherPublicationResultIsVerified(direct)) {
            return fail("direct publication without persistent token proof accepted");
        }

        NSMutableDictionary *directRestore = directPublication(YES);
        directRestore[@"mode"] = @"stock";
        directRestore[@"replacementCreated"] = @NO;
        directRestore[@"replacementReturned"] = @NO;
        directRestore[@"replacementPublished"] = @NO;
        directRestore[@"persistentIndexTokenWriteVerified"] = @NO;
        directRestore[@"persistentIndexTokenLookupVerified"] = @YES;
        if (!CNDIconServicesPublisherRestorationResultIsVerified(
                directRestore)) {
            return fail("direct remove/write restoration rejected");
        }
        NSMutableDictionary *alreadyStockRestore =
            [directRestore mutableCopy];
        alreadyStockRestore[@"directStoreWriteIssued"] = @NO;
        alreadyStockRestore[@"directStoreWriteSkippedAlreadyStock"] = @YES;
        if (CNDIconServicesPublisherRestorationResultIsVerified(
                alreadyStockRestore)) {
            return fail("restoration-only write skip accepted");
        }

        NSMutableDictionary *publicationCannotSkip = directPublication(YES);
        publicationCannotSkip[@"directStoreWriteIssued"] = @NO;
        publicationCannotSkip[@"directStoreWriteSkippedAlreadyStock"] = @YES;
        if (CNDIconServicesPublisherPublicationResultIsVerified(
                publicationCannotSkip)) {
            return fail("publication accepted restoration-only write skip");
        }
        directRestore[@"directStoreWriteVerified"] = @NO;
        if (CNDIconServicesPublisherRestorationResultIsVerified(
                directRestore)) {
            return fail("direct restoration without write proof accepted");
        }

        return 0;
    }
}
"""


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("xcrun"),
    "Foundation validator fixture requires macOS Xcode",
)
class IconServicesPublisherContractTests(unittest.TestCase):
    def test_validator_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cnd-publisher-contract-") as directory:
            root = Path(directory)
            harness = root / "harness.m"
            binary = root / "harness"
            harness.write_text(textwrap.dedent(HARNESS), encoding="utf-8")
            sdk = subprocess.check_output(
                ["xcrun", "--sdk", "macosx", "--show-sdk-path"],
                text=True,
            ).strip()
            clang = subprocess.check_output(
                ["xcrun", "--sdk", "macosx", "--find", "clang"],
                text=True,
            ).strip()
            subprocess.run(
                [
                    clang,
                    "-fobjc-arc",
                    "-fobjc-runtime=macosx-14.0",
                    "-isysroot",
                    sdk,
                    "-I",
                    str(CONTRACT_HEADER_DIR),
                    str(CONTRACT_SOURCE),
                    str(harness),
                    "-framework",
                    "Foundation",
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
