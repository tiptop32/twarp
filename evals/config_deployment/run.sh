#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

go test ./internal/fsutil ./internal/render \
  -run '^(TestWriteFileAtomicOwnedSetsOwnerBeforeRename|TestWriteFileAtomicOwnedKeepsDestinationWhenOwnerFails|TestWriteFileAtomicOwnedReplacesSymlinkDestination|TestWriteRuleSetOwnedGivesOwnerBeforeRename|TestWriteRuleSetStaysUnprivileged)$' \
  -count=1

go test ./internal/launchd \
  -run '^(TestInstallFailedCheckPreservesInstalledConfigAndService|TestInstallFileFailureKeepsRunningServiceAndConfig|TestInstallPromoteFailureRestoresInstalledFiles|TestInstallGeoServiceFailureKeepsSingBoxRunning|TestInstallPerformsSystemSetupInOrder|TestOSFSCandidatePromotionKeepsInstalledConfigUntilPromote)$' \
  -count=1

go test -race ./cmd/twarp \
  -run '^(TestRunApplyFailedCheckPreservesInstalledConfig|TestRunApplyFailedReloadRestoresInstalledFiles|TestRunApplyRejectsUninstalledService|TestRunApplyRejectsUnexpectedPrintError|TestRunApplyChecksAndReloadsRunningService|TestRunInstallHoldsStateLockUntilRuleSetWrite)$' \
  -count=1
