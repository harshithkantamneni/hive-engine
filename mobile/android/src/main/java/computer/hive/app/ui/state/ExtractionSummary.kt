package computer.hive.app.ui.state

import androidx.compose.runtime.Immutable

/**
 * ExtractionSummary — data class for a single LEDGER row's content.
 *
 * The row layout is three lines:
 *   Line 1 — `title`         (16sp ink.primary, 1 line truncated)
 *   Line 2 — `factSnippet`   (14sp ink.secondary, 1 line truncated)
 *   Line 3 — `relativeTime` + ` · ` + `sourceApp` (14sp ink.dim, tabular)
 *            -- the separator is U+00B7 MIDDLE DOT.
 *
 * Per-row sync state:
 *   - `syncState = Sending`   → row footer reads "Sending."
 *   - `syncState = Receiving` → row footer reads "Receiving."
 *   - `syncState = SyncedAt`  → row footer reads `Synced N minutes ago.`
 *   - `syncState = LocalOnly` → row footer reads relative-time only.
 *   - `syncState = TransferFailed` → row footer reads `This extraction
 *      didn't transfer cleanly. HIVE will retry.`
 *   - `syncState = TransferFailedPersistent` → row footer reads `Couldn't
 *      receive this extraction. Try pairing again on the source device.`
 *
 * Per-row crash-recovery (S6) is rendered as `isCrashRecovery = true` → the
 * row gains a `state.warn` accent on the timestamp column + two inline-text
 * actions ("Resume." / "Discard.").
 */
@Immutable
data class ExtractionSummary(
    val id: String,
    val title: String,
    val factSnippet: String,
    val relativeTime: String,
    val sourceApp: String?,
    val syncState: RowSyncState = RowSyncState.LocalOnly,
    val isCrashRecovery: Boolean = false,
)

/** Per-row sync state — feeds the row's third-line copy + accent treatment. */
enum class RowSyncState {
    LocalOnly,
    Sending,
    Receiving,
    SyncedAt,
    TransferFailed,
    TransferFailedPersistent,
}
