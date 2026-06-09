package computer.hive.app.ui.state

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * LedgerViewModel — surface-state holder for the LEDGER MainActivity Compose
 * surface.
 *
 * A standard `androidx.lifecycle.ViewModel` — no Hilt requirement (single
 * dependency tree; manual injection is acceptable) and no third-party DI
 * library.
 *
 * Exposes `val uiState: StateFlow<LedgerUiState>`, collected in LedgerScreen via
 * `collectAsStateWithLifecycle()`. Side-effect handling (extract-document tap →
 * permission flow → JNI extraction call) emits a one-shot event via
 * `Channel<LedgerEvent>` collected in LedgerScreen.
 *
 * The persistence layer is not yet wired. For now the ViewModel ships with a
 * hardcoded `LedgerUiState.Empty` so the surface is launch-shaped, previewable,
 * and structurally compiles. When the persistence layer lands, this ViewModel
 * gains a constructor injection accepting `Flow<List<ExtractionSummary>>` and
 * emits `Populated` accordingly.
 *
 * ZERO-TELEMETRY: no analytics SDK invocation, no Firebase, no Crashlytics, no
 * GMS Play Services analytics. The `Channel<LedgerEvent>` is in-process only.
 *
 * Aesthetic: the ViewModel is data + behavior; aesthetic compliance lives at the
 * Composable + theme layers (HiveTheme.kt + HiveColors.kt + HiveTypography.kt +
 * HiveShapes.kt).
 */
class LedgerViewModel : ViewModel() {

    // Initial state: Loading — the initial composition, before first state
    // observation. When the persistence layer lands, the constructor accepts a
    // `Flow<List<ExtractionSummary>>` and the body here transitions
    // Loading → Empty / Populated based on stream contents.
    private val _uiState: MutableStateFlow<LedgerUiState> = MutableStateFlow(LedgerUiState.Loading)
    val uiState: StateFlow<LedgerUiState> = _uiState.asStateFlow()

    private val _events: Channel<LedgerEvent> = Channel(Channel.BUFFERED)
    val events = _events.receiveAsFlow()

    init {
        // Bootstrap — the surface settles to Empty immediately (no persistence
        // layer to read from). When persistence lands, this collects from
        // `Flow<List<ExtractionSummary>>` and transitions to Populated with
        // banner-priority resolution.
        _uiState.value = LedgerUiState.Empty
    }

    /**
     * Primary CTA — "Pair a device." Emits a one-shot event collected by
     * LedgerScreen, which routes into the system-permission pre-prompt flow.
     * The screen handles the permission-launcher contract and surfaces results
     * back to the VM.
     */
    fun onExtractRequested() {
        _events.trySend(LedgerEvent.PairDeviceRequested)
    }

    /** Secondary CTA — "About HIVE." */
    fun onAboutRequested() {
        _events.trySend(LedgerEvent.AboutRequested)
    }

    /** App-bar refresh action. */
    fun onRefreshRequested() {
        _events.trySend(LedgerEvent.RefreshRequested)
    }

    /** Banner secondary action — Settings deep-link for permission denial. */
    fun onOpenSettingsRequested() {
        _events.trySend(LedgerEvent.OpenSettingsRequested)
    }

    /** S6 crash-recovery row "Resume." action. */
    fun onResumeCrashedExtraction(id: String) {
        _events.trySend(LedgerEvent.ResumeCrashedExtraction(id))
    }

    /** S6 crash-recovery row "Discard." action. */
    fun onDiscardCrashedExtraction(id: String) {
        _events.trySend(LedgerEvent.DiscardCrashedExtraction(id))
    }
}

/**
 * LedgerEvent — one-shot side-effect events emitted by the ViewModel and
 * collected by LedgerScreen via `events.collect { ... }`.
 *
 * The screen handles platform contracts (permission launcher, intent-launcher
 * for the Settings deep-link) and surfaces results back.
 */
sealed interface LedgerEvent {
    data object PairDeviceRequested : LedgerEvent
    data object AboutRequested : LedgerEvent
    data object RefreshRequested : LedgerEvent
    data object OpenSettingsRequested : LedgerEvent
    data class ResumeCrashedExtraction(val id: String) : LedgerEvent
    data class DiscardCrashedExtraction(val id: String) : LedgerEvent
}
