package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import computer.hive.app.R
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerEmptyState — S1 first-run / no-extractions surface.
 *
 * Brand mark `hive` top-left, a section label, and a single hairline rule. A
 * vertically centered region (mid-screen) holds two lines of typography: a 22sp
 * ink.primary statement and a 14sp ink.secondary qualifier line. NO
 * illustration, NO animation, NO arrow pointing at the action. The empty state
 * is calm, not anxious.
 *
 * Strings:
 *   - Title:  `R.string.hive_ledger_empty_title`  → "No extractions on this device."
 *   - Body:   `R.string.hive_ledger_empty_body`   → "Pair another device to start
 *               sharing extractions. Pairing happens directly between your devices."
 *
 * Aesthetic: no illustration, no animation, no arrow / Lottie / sparkle —
 * purely typographic.
 */
@Composable
fun LedgerEmptyState(modifier: Modifier = Modifier) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.surfaceCanvas)
            .padding(horizontal = dims.gutter),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.hive_ledger_empty_title),
            style = MaterialTheme.typography.displayLarge,
            color = colors.inkPrimary,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(dims.spaceMd))
        Text(
            text = stringResource(R.string.hive_ledger_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = colors.inkSecondary,
            textAlign = TextAlign.Center,
        )
    }
}
