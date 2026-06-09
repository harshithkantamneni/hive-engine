package computer.hive.app.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/**
 * HiveShapes — LEDGER shape system.
 *
 * Overrides the M3 `Shapes` to set all corner radii to `0.dp` for
 * `Shapes.small`, `Shapes.medium`, `Shapes.large` — kills M3's default 4-16dp
 * rounding on cards, buttons, etc.
 *
 * Aesthetic constraint: zero `RoundedCornerShape(n.dp)` with n > 0 on content
 * surfaces (system chrome exempt).
 *
 * Hairline / row-divider / banner shapes are all rectangular by intent —
 * the LEDGER metaphor is "entries in a typeset bound book", which has zero
 * rounded-corner ornament. The `0.dp` override is the technical mechanism that
 * makes M3-default Compose primitives (Card, Button, Surface) align with this
 * requirement without per-call-site shape parameter passing.
 */
val HiveShapes = Shapes(
    extraSmall = RoundedCornerShape(0.dp),
    small = RoundedCornerShape(0.dp),
    medium = RoundedCornerShape(0.dp),
    large = RoundedCornerShape(0.dp),
    extraLarge = RoundedCornerShape(0.dp),
)
