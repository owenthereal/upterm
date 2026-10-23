package internal

import "time"

// serverTiming is resolved before a session starts and copied to its actors.
// Non-positive durations use the production defaults.
type serverTiming struct {
	pacingStall, primaryStall, promoteFlush time.Duration
	outputIdle, outputDrain                 time.Duration
	hangup, forceCommandStop                time.Duration
}

func (v serverTiming) orDefault() serverTiming {
	if v.pacingStall <= 0 {
		v.pacingStall = pacingStallTimeout
	}
	if v.primaryStall <= 0 {
		v.primaryStall = primaryStallTimeout
	}
	if v.promoteFlush <= 0 {
		v.promoteFlush = promoteFlushTimeout
	}
	if v.outputIdle <= 0 {
		v.outputIdle = outputIdleTimeout
	}
	if v.outputDrain <= 0 {
		v.outputDrain = outputDrainTimeout
	}
	if v.hangup <= 0 {
		v.hangup = hangupGrace
	}
	if v.forceCommandStop <= 0 {
		v.forceCommandStop = forceCommandStopGrace
	}
	return v
}
