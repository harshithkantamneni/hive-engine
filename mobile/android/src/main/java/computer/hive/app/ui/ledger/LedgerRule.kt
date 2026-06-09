package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerRule — 1px hairline divider in `ink.dim`.
 *
 * Hairline rules (1px ink.dim) between rows. NO card containers, NO shadows,
 * NO rounded corners.
 *
 * Reused as both:
 *   - Row-divider (between LedgerRow instances).
 *   - Section-divider (below LedgerHeader).
 *
 * Aesthetic checklist:
 *   - Zero `Modifier.shadow` on this composable.
 *   - Zero gradient fills.
 *   - 0dp corner radius (RoundedCornerShape(0.dp)).
 */
@Composable
fun LedgerRule(modifier: Modifier = Modifier) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current
    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(dims.hairline)
            .background(colors.inkDim),
    )
}
