package computer.hive.app.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * HiveDimensions — LEDGER spacing + size scale.
 *
 * Spacing scale (4, 8, 12, 16, 24, 32 dp); row heights; hairline width.
 *
 * Density-over-decoration: a user with 30 extractions sees ~10 rows on screen,
 * which serves the pragmatic privacy-tool user better than empty space.
 *
 * Hairline width is 1.dp (Compose minimum drawable line on most densities;
 * `Modifier.height(1.dp)` on a `Box` with `inkDim` background is the canonical
 * `LedgerRule()` implementation).
 */
@Immutable
data class HiveDimensions(
    /** Spacing scale — 4-step base for paddings + gutters. */
    val spaceXxs: Dp = 4.dp,
    val spaceXs: Dp = 8.dp,
    val spaceSm: Dp = 12.dp,
    val spaceMd: Dp = 16.dp,
    val spaceLg: Dp = 24.dp,
    val spaceXl: Dp = 32.dp,

    /** Row heights — list rows are 56dp tall (three-line layout). */
    val ledgerRowHeight: Dp = 56.dp,
    /** Primary action row — full-width, 48dp tall. */
    val primaryActionHeight: Dp = 48.dp,

    /** Horizontal gutter — 16dp. */
    val gutter: Dp = 16.dp,

    /** Hairline rule — 1px ink.dim. */
    val hairline: Dp = 1.dp,

    /** Sync indicator height — 1px-tall accent.signal bar. */
    val syncIndicatorHeight: Dp = 1.dp,

    /** Banner inset — 12dp. */
    val bannerInset: Dp = 12.dp,
)

/** Composition-local for HiveDimensions; default is the canonical scale. */
val LocalHiveDimensions = staticCompositionLocalOf { HiveDimensions() }
