#pragma once

#include "stdafx.h"

// Keeps xam's saved feature mask from losing the features in protectMask (bit = feature id - 1).
// Writes that would turn a protected feature off still go through, but with the protected
// features kept on, and the requested mask is remembered in Hdd:\Filesystems\featurelock.bin.
// At install the saved mask is set to (remembered request | protected features), on from the
// next boot, so features dropped from protectMask go back to what xbGuard asked for. Modules named xbGuard* then
// read that remembered mask from XamFeatureEnabled / ExGetXConfigSetting, so they see the change
// they asked for; xam and titles keep seeing the real mask. Every caller is logged (once per
// function + return address) to Hdd:\Filesystems\featurelock.log.
// Only installed on xam 17489 (checks each function's first instructions).
BOOL FeatureLock_Install(ULONGLONG protectMask);
