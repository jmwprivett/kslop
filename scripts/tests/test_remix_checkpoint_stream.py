"""Compiled host checks for bounded SnowBoard Remix journal deltas."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REMIX = ROOT / "Cyanide/installer/CNDSnowBoardRemix.m"


HARNESS = r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "checkpoint fixture failed at line %d: %s\n", \
            __LINE__, #condition); return 1; } } while (0)

static NSMutableDictionary *variant(NSString *identity, NSString *state) {
    return [@{
        @"descriptorIdentity": identity,
        @"descriptorSpecification": @{@"id": identity},
        @"state": state,
        @"publicationDispatchPossible": @NO,
    } mutableCopy];
}

int main(void) {
    @autoreleasepool {
        NSString *bundle = @"com.example.checkpoint";
        NSMutableDictionary *journal = [@{
            @"schemaVersion": @2,
            @"bundleIdentifier": bundle,
            @"state": @"prepared",
            @"variants": @[
                variant(@"first", @"prepared"),
                variant(@"second", @"prepared"),
            ],
            @"updatedAt": NSDate.date,
        } mutableCopy];
        CHECK(CNDRemixWriteIconServicesJournal(journal));
        CHECK([journal[@"checkpointSequence"] unsignedIntegerValue] == 0);
        NSString *firstStream = journal[@"checkpointStreamIdentifier"];
        CHECK(CNDRemixCheckpointStreamIdentifierIsValid(firstStream));

        NSMutableArray *variants = [journal[@"variants"] mutableCopy];
        NSMutableDictionary *first = [variants[0] mutableCopy];
        first[@"state"] = @"dispatch-possible";
        first[@"publicationDispatchPossible"] = @YES;
        variants[0] = first;
        journal[@"variants"] = variants;
        journal[@"state"] = @"dispatch-possible";
        journal[@"updatedAt"] = NSDate.date;
        CHECK(CNDRemixAppendIconServicesJournalCheckpoint(journal, @[@0]));

        variants = [journal[@"variants"] mutableCopy];
        first = [variants[0] mutableCopy];
        first[@"state"] = @"published-pending-session-close";
        first[@"publication"] = @{@"ok": @YES};
        NSMutableDictionary *second = [variants[1] mutableCopy];
        second[@"state"] = @"dispatch-possible";
        second[@"publicationDispatchPossible"] = @YES;
        variants[0] = first;
        variants[1] = second;
        journal[@"variants"] = variants;
        journal[@"updatedAt"] = NSDate.date;
        CHECK(CNDRemixAppendIconServicesJournalCheckpoint(journal, @[@0, @1]));
        CHECK([journal[@"checkpointSequence"] unsignedIntegerValue] == 2);

        NSDictionary *rawBase = [NSDictionary dictionaryWithContentsOfURL:
            CNDRemixIconServicesJournalURL(bundle)];
        CHECK([rawBase[@"checkpointSequence"] unsignedIntegerValue] == 0);
        CHECK([rawBase[@"variants"][0][@"state"] isEqualToString:@"prepared"]);
        NSDictionary *replayed = CNDRemixReadIconServicesJournal(bundle);
        CHECK([replayed[@"checkpointSequence"] unsignedIntegerValue] == 2);
        CHECK([replayed[@"checkpointReplayCount"] unsignedIntegerValue] == 2);
        CHECK([replayed[@"variants"][0][@"state"]
            isEqualToString:@"published-pending-session-close"]);
        CHECK([replayed[@"variants"][1][@"state"]
            isEqualToString:@"dispatch-possible"]);

        NSMutableDictionary *compacted = [replayed mutableCopy];
        CHECK(CNDRemixWriteIconServicesJournal(compacted));
        CHECK(![compacted[@"checkpointStreamIdentifier"]
            isEqualToString:firstStream]);
        CHECK([compacted[@"checkpointSequence"] unsignedIntegerValue] == 0);
        CHECK(![NSFileManager.defaultManager fileExistsAtPath:
            CNDRemixIconServicesCheckpointDirectoryURL(bundle).path]);

        variants = [compacted[@"variants"] mutableCopy];
        first = [variants[0] mutableCopy];
        first[@"state"] = @"dispatch-possible";
        variants[0] = first;
        compacted[@"variants"] = variants;
        compacted[@"state"] = @"dispatch-possible";
        compacted[@"updatedAt"] = NSDate.date;
        CHECK(CNDRemixAppendIconServicesJournalCheckpoint(compacted, @[@0]));
        NSURL *recordOne = CNDRemixIconServicesCheckpointURL(
            bundle, compacted[@"checkpointStreamIdentifier"], 1);
        NSData *corrupt = [@"not a property list" dataUsingEncoding:
            NSUTF8StringEncoding];
        CHECK([corrupt writeToURL:recordOne options:NSDataWritingAtomic error:nil]);
        NSDictionary *failed = CNDRemixReadIconServicesJournal(bundle);
        CHECK([failed[@"checkpointReplayIncomplete"] boolValue]);
        CHECK([failed[@"state"] isEqualToString:@"recovery-required"]);
        for (NSDictionary *entry in failed[@"variants"]) {
            CHECK([entry[@"publicationDispatchPossible"] boolValue]);
            CHECK([entry[@"restorationDispatchPossible"] boolValue]);
        }

        CHECK(CNDRemixWriteIconServicesJournal(compacted));
        compacted[@"updatedAt"] = NSDate.date;
        CHECK(CNDRemixAppendIconServicesJournalCheckpoint(compacted, @[@0]));
        variants = [compacted[@"variants"] mutableCopy];
        second = [variants[1] mutableCopy];
        second[@"state"] = @"restoring";
        second[@"restorationDispatchPossible"] = @YES;
        variants[1] = second;
        compacted[@"variants"] = variants;
        compacted[@"state"] = @"restoring";
        compacted[@"updatedAt"] = NSDate.date;
        CHECK(CNDRemixAppendIconServicesJournalCheckpoint(compacted, @[@1]));
        recordOne = CNDRemixIconServicesCheckpointURL(
            bundle, compacted[@"checkpointStreamIdentifier"], 1);
        CHECK([NSFileManager.defaultManager removeItemAtURL:recordOne error:nil]);
        failed = CNDRemixReadIconServicesJournal(bundle);
        CHECK([failed[@"checkpointReplayIncomplete"] boolValue]);
        CHECK([failed[@"checkpointReplayFailureReason"]
            isEqualToString:@"noncontiguous-record-stream"]);

        CHECK(!CNDRemixAppendIconServicesJournalCheckpoint(
            compacted, @[@0, @0]));
        CHECK(!CNDRemixAppendIconServicesJournalCheckpoint(
            compacted, @[@0, @1, @0]));
        CHECK(CNDRemixRemoveIconServicesJournal(bundle));
        CHECK(![NSFileManager.defaultManager fileExistsAtPath:
            CNDRemixIconServicesJournalURL(bundle).path]);
        CHECK(![NSFileManager.defaultManager fileExistsAtPath:
            CNDRemixIconServicesCheckpointDirectoryURL(bundle).path]);
    }
    return 0;
}
'''


class RemixCheckpointStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = REMIX.read_text(encoding="utf-8")

    @unittest.skipUnless(
        sys.platform == "darwin" and shutil.which("clang"),
        "requires macOS Foundation and clang",
    )
    def test_compiled_append_replay_compaction_and_fail_closed_corruption(self) -> None:
        start = self.source.index(
            "static NSURL *CNDRemixIconServicesJournalURL("
        )
        end = self.source.index(
            "static NSDictionary<NSString *, NSData *> *CNDRemixNormalizedThemeLookup(",
            start,
        )
        helpers = self.source[start:end]
        with tempfile.TemporaryDirectory(
            prefix="cyanide-checkpoint-stream-"
        ) as directory:
            source_file = Path(directory) / "checkpoint.m"
            executable = Path(directory) / "checkpoint"
            root_literal = (
                Path(directory).as_posix().replace("\\", "\\\\").replace('"', '\\"')
            )
            source_file.write_text(
                "#import <Foundation/Foundation.h>\n#include <stdio.h>\n"
                "static const NSUInteger CNDRemixIconServicesCheckpointSchemaVersion = 1;\n"
                "static const NSUInteger CNDRemixIconServicesCheckpointMaximumRecords = 256;\n"
                "static const NSUInteger CNDRemixIconServicesCheckpointMaximumVariantUpdates = 2;\n"
                f'static NSString * const TestRoot = @"{root_literal}/store";\n'
                "static NSURL *CNDRemixIconServicesRootURL(void) {\n"
                "    return [NSURL fileURLWithPath:TestRoot isDirectory:YES];\n"
                "}\n"
                "static NSURL *CNDRemixIconServicesTransactionsURL(void) {\n"
                "    return [CNDRemixIconServicesRootURL() "
                "URLByAppendingPathComponent:@\"Transactions\" isDirectory:YES];\n"
                "}\n"
                + helpers
                + HARNESS,
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "clang",
                    "-fobjc-arc",
                    "-framework",
                    "Foundation",
                    str(source_file),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_stream_is_bounded_and_replay_failures_force_recovery(self) -> None:
        start = self.source.index(
            "static NSDictionary *CNDRemixJournalByReplayingCheckpoints("
        )
        end = self.source.index(
            "static NSDictionary *CNDRemixReadIconServicesJournal(", start
        )
        replay = self.source[start:end]
        self.assertIn("CNDRemixIconServicesCheckpointMaximumRecords", replay)
        self.assertIn("candidateBySequence", replay)
        self.assertNotIn("sortUsingComparator", replay)
        self.assertIn("noncontiguous-record-stream", replay)
        self.assertIn("invalid-variant-update", replay)
        self.assertIn('updated[@"publicationDispatchPossible"] = @YES;', self.source)
        self.assertIn('updated[@"restorationDispatchPossible"] = @YES;', self.source)
        self.assertGreaterEqual(
            self.source.count('@"journalCheckpointStrategy": @"bounded-append-v1"'),
            3,
        )
        self.assertIn(
            '@"journalCheckpointComplexity": @"linear-in-variants"',
            self.source,
        )


if __name__ == "__main__":
    unittest.main()
