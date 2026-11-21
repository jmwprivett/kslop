import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "Cyanide" / "installer"


class RemixBlanketRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.remix = (INSTALLER / "CNDSnowBoardRemix.m").read_text(
            encoding="utf-8"
        )
        cls.publisher = (INSTALLER / "CNDIconServicesPublisher.m").read_text(
            encoding="utf-8"
        )
        cls.transport = (
            INSTALLER / "CNDIconServicesPublisherRemoteTransport.m"
        ).read_text(encoding="utf-8")
        start = cls.remix.index(
            "static NSDictionary<NSString *, id> *CNDRemixRestoreIconServicesJournals("
        )
        end = cls.remix.index("\n@implementation CNDSnowBoardRemix", start)
        cls.restore = cls.remix[start:end]

    def test_restore_uses_one_matrix_dispatch_and_no_singular_dispatch(self) -> None:
        self.assertEqual(
            self.restore.count(
                "CNDIconServicesPublisherRestoreStockVariantsInBatch("
            ),
            1,
        )
        self.assertNotIn(
            "CNDIconServicesPublisherRestoreStockVariantInBatch(", self.restore
        )

    def test_entire_app_is_checkpointed_before_matrix_mutation(self) -> None:
        arm = self.restore.index(
            'dispatchVariant[@"restorationDispatchPossible"] ='
        )
        checkpoint = self.restore.index(
            "CNDRemixWriteIconServicesJournal(journal);", arm
        )
        dispatch = self.restore.index(
            "CNDIconServicesPublisherRestoreStockVariantsInBatch(", checkpoint
        )
        self.assertLess(arm, checkpoint)
        self.assertLess(checkpoint, dispatch)
        self.assertNotIn(
            "CNDRemixAppendIconServicesJournalCheckpoint(",
            self.restore[arm:dispatch],
        )

    def test_full_matrix_does_not_exceed_incremental_checkpoint_limit(self) -> None:
        self.assertIn(
            "CNDRemixIconServicesCheckpointMaximumVariantUpdates = 2;",
            self.remix,
        )
        self.assertIn(
            '@"journalCheckpointStrategy": @"app-matrix-atomic-base-v1"',
            self.restore,
        )

    def test_successful_restore_deletes_without_per_variant_result_writes(self) -> None:
        dispatch = self.restore.index(
            "CNDIconServicesPublisherRestoreStockVariantsInBatch("
        )
        delete = self.restore.index(
            "CNDRemixRemoveIconServicesJournal(bundleIdentifier)", dispatch
        )
        result_path = self.restore[dispatch:delete]
        self.assertNotIn(
            "CNDRemixAppendIconServicesJournalCheckpoint(", result_path
        )
        self.assertNotIn("CNDRemixWriteIconServicesJournal(", result_path)
        self.assertIn(
            '@"journalCheckpointComplexity": @"constant-writes-per-app"',
            self.restore,
        )

    def test_matrix_reuses_one_transport_boundary(self) -> None:
        method_start = self.transport.index(
            "descriptorSpecifications:(NSArray<NSDictionary<NSString *,NSNumber *> *> *)descriptorSpecifications",
            self.transport.index(
                "restoreStockForBundleIdentifier:(NSString *)bundleIdentifier"
            ),
        )
        method_end = self.transport.index("\n- (", method_start)
        method = self.transport[method_start:method_end]
        self.assertEqual(method.count("cnd_remote_transport_call("), 1)
        self.assertIn("cnd_publisher_restore_matrix(", method)

        matrix_start = self.transport.index(
            "static NSDictionary<NSString *, id> *cnd_publisher_restore_matrix("
        )
        matrix_end = self.transport.index(
            "\nstatic const NSUInteger CNDIconServicesPublisherMaximumAuditMatrixCount",
            matrix_start,
        )
        matrix = self.transport[matrix_start:matrix_end]
        self.assertIn("cnd_publisher_run(", matrix)
        self.assertIn('@"variants": reports', matrix)
        self.assertIn("CNDIconServicesPublisherMaximumMutationMatrixCount", matrix)

    def test_facade_forwards_the_ordered_matrix(self) -> None:
        start = self.publisher.index(
            "CNDIconServicesPublisherRestoreStockVariantsInBatch("
        )
        end = self.publisher.index("\nNSDictionary<NSString *, id> *", start + 1)
        method = self.publisher[start:end]
        self.assertIn(
            "descriptorSpecifications:descriptorSpecifications", method
        )


if __name__ == "__main__":
    unittest.main()
