package replay

import "errors"

// Why a replay fails, besides io's ErrReplayCoverage and ErrReplayDeadline.
// Each is a reason the join falls back to the raw ring.
var (
	ErrSizeCap          = errors.New("replay: a size exceeds the cap")
	ErrNotContained     = errors.New("replay: the joiner's terminal doesn't contain the render size")
	ErrTrackerDisagrees = errors.New("replay: the tracker and the emulator disagree")
	ErrOverBudget       = errors.New("replay: the reconstruction exceeds its budget")
	// ErrHandoffInvariant means a published handoff point broke A13: the
	// emulator still carries a cluster there. It is a bug, never an
	// expected outcome.
	ErrHandoffInvariant = errors.New("replay: the emulator isn't at a handoff point")
)

// IneligibleError names state R13 doesn't restore.
type IneligibleError struct{ State string }

func (e *IneligibleError) Error() string {
	return "replay: the render can't restore " + e.State
}
