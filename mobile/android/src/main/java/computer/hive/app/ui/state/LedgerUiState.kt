package computer.hive.app.ui.state

import androidx.compose.runtime.Immutable

/**
 * LedgerUiState — sealed class enumerating the 6 surface states (S1-S6) the
 * LEDGER MainActivity surface MUST render.
 *
 * The 6 states map to:
 *   S1 — First-run / empty       → [Empty]
 *   S2 — Populated                → [Populated] with `banner = null`
 *   S3 — Loading / sync-progress  → [Loading] (initial)  OR  [Populated.syncState != null]
 *   S4 — Permission denied (BLE)  → [Populated.banner = PermissionBanner]
 *   S5 — Storage critical         → [Populated.banner = StorageBanner]
 *   S6 — Crash-recovery           → [Populated.rows[0].isCrashRecovery = true]
 *
 * Banner-priority rule: storage > permission > peer-unreachable > none.
 * Implemented at LedgerViewModel; LedgerScreen renders whatever banner is
 * present without re-resolving priority.
 */
@Immutable
sealed interface LedgerUiState {

    /** S3 entry-point — initial composition, before first state observation. */
    data object Loading : LedgerUiState

    /** S1 — first-run / no extractions stored. */
    data object Empty : LedgerUiState

    /**
     * S2/S3/S4/S5/S6 — list visible. The `banner` and `syncState` fields
     * carry the per-state distinguishing information per the 6-state map.
     */
    @Immutable
    data class Populated(
        val rows: List<ExtractionSummary>,
        val syncState: GlobalSyncState? = null,
        val banner: BannerState? = null,
    ) : LedgerUiState
}

/**
 * GlobalSyncState — coalesced sync-banner triggered when ≥3 concurrent transfers
 * fire. Rendered as a 1px accent.signal bar below the LedgerHeader OR (when ≥3
 * concurrent transfers are active) the coalesced banner using
 * `R.plurals.hive_ledger_sync_banner`.
 *
 * Determinate progress is rendered as a 1px bar; indeterminate is the same bar
 * with the `progress = null` case animating (280ms cycle).
 */
@Immutable
sealed interface GlobalSyncState {
    /** Discovery in progress — shows `Checking nearby devices.` */
    data object CheckingNearby : GlobalSyncState

    /** Coalesced sync — render via `pluralStringResource(R.plurals.hive_ledger_sync_banner, ...)`. */
    @Immutable
    data class Syncing(val extractionCount: Int, val peerCount: Int) : GlobalSyncState
}

/**
 * BannerState — at most one banner (banner-priority). The ViewModel resolves
 * precedence; the screen renders whichever wins.
 */
@Immutable
sealed interface BannerState {
    /** S4 — Nearby-devices permission not yet granted. */
    data object PermissionNotGranted : BannerState

    /** S4 alt — peer-unreachable post-pairing. */
    data object PeerUnreachable : BannerState

    /** S5 — storage unreachable (pre-empts everything). */
    data object StorageUnreachable : BannerState
}
