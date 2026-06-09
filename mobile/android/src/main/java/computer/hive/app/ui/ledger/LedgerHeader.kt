package computer.hive.app.ui.ledger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import computer.hive.app.R
import computer.hive.app.ui.theme.LocalHiveColors
import computer.hive.app.ui.theme.LocalHiveDimensions

/**
 * LedgerHeader — brand mark + small-caps section label + hairline rule.
 *
 * Brand mark `hive` (top-left, 16sp) + a small-caps section label (14sp) — no
 * top app bar, no back button (this is the home), no overflow menu (settings
 * are reached via long-press on a row or via gesture).
 *
 * Note: the brand mark is intentionally lowercase `hive`, not uppercase. This is
 * a deliberate brand-identity statement.
 *
 * The string resource `R.string.hive_appbar_title` is `HIVE` — authored at
 * uppercase for the app-bar surface (not THIS surface). The header here uses a
 * literal `hive` string: this is brand chrome, not user copy, so the Compose
 * chrome owns the punctuation/casing.
 */
@Composable
fun LedgerHeader(
    label: String,
    modifier: Modifier = Modifier,
) {
    val colors = LocalHiveColors.current
    val dims = LocalHiveDimensions.current

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(colors.surfaceCanvas)
            .semantics { heading() },
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    start = dims.gutter,
                    end = dims.gutter,
                    top = dims.spaceLg,
                    bottom = dims.spaceXs,
                ),
            horizontalArrangement = Arrangement.spacedBy(dims.spaceMd),
            verticalAlignment = Alignment.Bottom,
        ) {
            // Brand mark — lowercase mono (intentional brand-identity).
            Text(
                text = "hive",
                style = MaterialTheme.typography.titleMedium,
                color = colors.inkPrimary,
            )
            // Small-caps section label — letter-spaced 0.08em via labelLarge style.
            Text(
                text = label.uppercase(),
                style = MaterialTheme.typography.labelLarge,
                color = colors.inkSecondary,
            )
        }
        LedgerRule()
    }
}

/**
 * LedgerHeaderDefault — convenience wrapper hard-coded to the "ledger" section
 * label. Repoint at a dedicated label string if a section-label entry is added.
 */
@Composable
fun LedgerHeaderDefault(modifier: Modifier = Modifier) {
    // Uses the app-bar title literal (the only visible label for the
    // home-surface chrome at present).
    LedgerHeader(label = stringResource(R.string.hive_appbar_title), modifier = modifier)
}
