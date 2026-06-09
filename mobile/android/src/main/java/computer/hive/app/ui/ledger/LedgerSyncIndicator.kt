package computer.hive.app.ui.ledger

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerSyncIndicator — 1px-tall accent.signal bar communicating sync progress.
 *
 * A 1px-tall accent.signal bar at the top of the relevant row: determinate when
 * the percentage is known, indeterminate-but-moving when not (with a 280ms cycle
 * so it reads as "alive", not "fast"). Null progress means indeterminate.
 *
 * Accessibility: exposes `stateDescription = "syncing, X percent"` when
 * determinate, `"syncing"` when indeterminate.
 *
 * @param progress 0f..1f for determinate; `null` for indeterminate.
 *                 Indeterminate animates per the Material 3 default; the target
 *                 is a 280ms cycle — the M3 default is close (~600ms), and
 *                 fine-tuning via a custom `animationSpec` is a later adjustment.
 */
@Composable
fun LedgerSyncIndicator(
    progress: Float?,
    modifier: Modifier = Modifier,
) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    val a11yState = if (progress != null) {
        val pct = (progress.coerceIn(0f, 1f) * 100f).toInt()
        "syncing, $pct percent"
    } else {
        "syncing"
    }

    val barModifier = modifier
        .fillMaxWidth()
        .height(dims.syncIndicatorHeight)
        .semantics { stateDescription = a11yState }

    if (progress != null) {
        LinearProgressIndicator(
            progress = { progress.coerceIn(0f, 1f) },
            modifier = barModifier,
            color = colors.accentSignal,
            trackColor = colors.inkDim,
        )
    } else {
        // Indeterminate — Material 3 indeterminate progress animation.
        LinearProgressIndicator(
            modifier = barModifier,
            color = colors.accentSignal,
            trackColor = colors.inkDim,
        )
    }
}
