package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerPrimaryAction — bottom-pinned, full-width row-shaped affordance.
 *
 * NOT a Material FAB. A persistent bottom row affordance — full-width, 48dp
 * tall, hairline rule above, label centered in the accent.signal copper color.
 * Reads as the next-line entry in the ledger. When pressed, the row inverts
 * (accent.signal background, surface.canvas text) momentarily, then the
 * permission/extraction flow begins.
 *
 * **Disabled-state visual** (storage-critical case): the primary-action row is
 * rendered with ink.dim text + a disabled-tap state (NOT
 * greyed-out-with-strikethrough — a quiet visual demotion, not visual
 * punishment).
 *
 * Aesthetic checklist:
 *   - Zero `FloatingActionButton`.
 *   - Zero `Modifier.shadow`.
 *   - 0dp corner radius.
 *
 * Touch target sizing: 48dp × full-width ≥ the 48dp × 48dp minimum.
 */
@Composable
fun LedgerPrimaryAction(
    label: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    Column(modifier = modifier) {
        // Hairline rule above.
        LedgerRule()
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(dims.primaryActionHeight)
                .background(colors.surfaceCanvas)
                .clickable(enabled = enabled, onClick = onClick)
                .semantics { role = Role.Button },
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = if (enabled) colors.accentSignal else colors.inkDim,
            )
        }
    }
}
