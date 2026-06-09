package computer.hive.app.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/**
 * HiveTypography — LEDGER type-scale.
 *
 * **Display + body:** iA Writer Mono S (preferred) OR JetBrains Mono (an
 * Apache-2.0 fallback if licensing escalates).
 *
 * **This currently uses `FontFamily.Monospace`** as a deliberate placeholder
 * until the iA Writer Mono S licensing is resolved. Material 3's monospace
 * fallback resolves to the platform default mono (Roboto Mono on most Android
 * devices) — this is structurally a humanist mono and preserves the
 * "deliberate / calm / authored" reading pattern intended here. When the
 * licensing decision lands, swap `FontFamily.Monospace` for the
 * `FontFamily(Font(R.font.ia_writer_mono_s_regular))` family resolved against
 * `mobile/android/src/main/res/font/`.
 *
 * **Forbidden:** no Inter, no Geist, no SF Pro Display, no Roboto. Material 3's
 * default Roboto is replaced wholesale on the content surface (system chrome
 * that we don't paint — status bar, IME — keeps the platform default). The
 * current `FontFamily.Monospace` deliberately AVOIDS the Material default Roboto
 * sans surface.
 *
 * Sizes:
 *   - Section header: 22sp (small-caps where the typeface supports `smcp`).
 *   - Body:           16sp.
 *   - Metadata:       14sp.
 *   - Brand mark:     16sp.
 *
 * Tabular figures: numerics use tabular figures (mono-spaced numerals).
 * FontFamily.Monospace already provides this behavior structurally; iA Writer
 * Mono S would need OpenType `tnum` enabled (post-licensing).
 */

/** Brand-default monospace family — placeholder for iA Writer Mono S until licensing lands. */
private val HiveMono: FontFamily = FontFamily.Monospace

/**
 * Material 3 Typography wired to monospace for every type role.
 *
 * Material 3's default Roboto is replaced wholesale on the content surface. This
 * typography object overrides M3's Roboto-by-default for every textstyle the
 * LEDGER surface uses (display, headline, title, body, label).
 *
 * The corner-rounding override (M3 default 4-16dp) lives in `HiveShapes.kt` — that
 * file forces 0dp on small/medium/large to kill M3's default rounded card / button
 * cosmetics. Together these two overrides convert M3 from "the default Material
 * dashboard" to a typographically neutral substrate for the LEDGER surface.
 */
val HiveTypography = Typography(
    // Display — used for the large-form empty-state typography (a vertically
    // centered region holding a 22sp ink.primary statement and a 14sp
    // ink.secondary qualifier line).
    displayLarge = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 22.sp,
        lineHeight = 32.sp,
    ),
    // Headline — section labels (small-caps treatment applied via letter-spacing).
    headlineMedium = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 18.sp,
        lineHeight = 26.sp,
    ),
    // Title — about-screen + populated-state primary lines.
    titleMedium = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Medium,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    // Body — list-row primary text (16sp ink.primary).
    bodyLarge = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    // Body — secondary fact-line (14sp ink.secondary, italic OFF).
    bodyMedium = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    // Label — small-caps section labels + ledger-row metadata (14sp tabular).
    labelLarge = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
        // letterSpacing approximates `letter-spacing: 0.08em` (smcp where
        // supported; otherwise lowercase + letter-spacing 0.08em).
        letterSpacing = 1.12.sp,
    ),
    // Label — small chrome (timestamp dim line + a11y hint footer).
    labelSmall = TextStyle(
        fontFamily = HiveMono,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
)
