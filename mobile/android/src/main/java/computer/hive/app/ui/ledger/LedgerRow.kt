package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import computer.hive.app.R
import computer.hive.app.ui.state.ExtractionSummary
import computer.hive.app.ui.state.RowSyncState
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerRow — three-line extraction row.
 *
 * 56dp tall, three-line layout — line 1 source title (16sp ink.primary, 1 line
 * truncated), line 2 a single-row extracted "fact" (14sp ink.secondary, 1 line
 * truncated, italic OFF — italics are anti-mono), line 3 timestamp +
 * extraction-mode marker (14sp ink.dim, tabular).
 *
 * The row height transitions from a fixed 56dp to `wrapContentHeight()` when the
 * font scale is large (three lines at large font may overflow fixed height).
 * This is implemented via `defaultMinSize(minHeight = 56.dp)` paired with
 * `wrapContentHeight()` so the row grows when the user has a high font-scale set.
 *
 * TalkBack a11y is exposed via `Modifier.semantics { contentDescription =
 * '[source]. extracted on [date]. status: [status]' }`.
 *
 * **No card containers, no shadows, no rounded corners.**
 */
@Composable
fun LedgerRow(
    extraction: ExtractionSummary,
    onResumeCrashed: () -> Unit = {},
    onDiscardCrashed: () -> Unit = {},
    onClick: () -> Unit = {},
    modifier: Modifier = Modifier,
) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    val title = extraction.title.ifBlank { stringResource(R.string.hive_ledger_row_untitled) }
    val secondaryText = extraction.factSnippet
    val tertiaryText = buildTertiaryText(extraction)

    val a11y = "$title. extracted on ${extraction.relativeTime}. " +
        (extraction.sourceApp?.let { "source: $it. " } ?: "") +
        "status: ${rowStatusForA11y(extraction.syncState)}."

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .background(colors.surfaceCanvas)
            .defaultMinSize(minHeight = dims.ledgerRowHeight)
            .wrapContentHeight()
            .padding(
                start = dims.gutter,
                end = dims.gutter,
                top = dims.spaceXs,
                bottom = dims.spaceXs,
            )
            .semantics { contentDescription = a11y },
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodyLarge,
            color = colors.inkPrimary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = secondaryText,
            style = MaterialTheme.typography.bodyMedium,
            color = colors.inkSecondary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = tertiaryText,
            style = MaterialTheme.typography.labelLarge,
            color = if (extraction.isCrashRecovery) colors.stateWarn else colors.inkDim,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )

        // S6 crash-recovery row — two inline-text actions.
        if (extraction.isCrashRecovery) {
            Row(
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = stringResource(R.string.hive_ledger_crash_recovery_action_resume),
                    style = MaterialTheme.typography.labelLarge,
                    color = colors.accentSignal,
                    modifier = Modifier
                        .clickable(onClick = onResumeCrashed)
                        .padding(end = dims.spaceMd, top = dims.spaceXxs),
                )
                Text(
                    text = stringResource(R.string.hive_ledger_crash_recovery_action_discard),
                    style = MaterialTheme.typography.labelLarge,
                    color = colors.inkSecondary,
                    modifier = Modifier
                        .clickable(onClick = onDiscardCrashed)
                        .padding(top = dims.spaceXxs),
                )
            }
        }
    }
}

/**
 * Build tertiary line — `relativeTime` + ` · ` + `sourceApp`.
 *
 * The dot separator `·` is U+00B7 MIDDLE DOT, not the ASCII period — the
 * visual-rhythm distinction matters at small sizes.
 *
 * Per-row sync state appended to the line:
 *   - Sending     → `Sending.` replaces the time-stamp line until complete.
 *   - Receiving   → `Receiving.` replaces the time-stamp line until complete.
 *   - SyncedAt    → `Synced N minutes ago.` (uses the relativeTime field).
 *   - LocalOnly   → relative-time only.
 *   - TransferFailed             → `This extraction didn't transfer cleanly.
 *                                    HIVE will retry.`
 *   - TransferFailedPersistent   → `Couldn't receive this extraction. Try
 *                                    pairing again on the source device.`
 *
 * NOTE: this builder produces a single line for the tertiary slot. Where a
 * longer string applies (TransferFailed*), the row's `bodyMedium` slot is used
 * by the `factSnippet` and the failure message replaces the tertiary slot. The
 * "1 line truncated" rule applies to all three rows.
 */
@Composable
private fun buildTertiaryText(extraction: ExtractionSummary): String {
    val sourceSuffix = extraction.sourceApp?.let { " · $it" } ?: ""
    return when (extraction.syncState) {
        RowSyncState.Sending -> stringResource(R.string.hive_ledger_sending)
        RowSyncState.Receiving -> stringResource(R.string.hive_ledger_receiving)
        RowSyncState.SyncedAt -> "Synced ${extraction.relativeTime}.$sourceSuffix"
        RowSyncState.LocalOnly -> "${extraction.relativeTime}$sourceSuffix"
        RowSyncState.TransferFailed ->
            stringResource(R.string.hive_ledger_extraction_failure)
        RowSyncState.TransferFailedPersistent ->
            stringResource(R.string.hive_ledger_extraction_failure_persistent)
    }
}

private fun rowStatusForA11y(state: RowSyncState): String = when (state) {
    RowSyncState.Sending -> "sending"
    RowSyncState.Receiving -> "receiving"
    RowSyncState.SyncedAt -> "synced"
    RowSyncState.LocalOnly -> "local only"
    RowSyncState.TransferFailed -> "transfer failed; will retry"
    RowSyncState.TransferFailedPersistent -> "transfer failed; user action required"
}
