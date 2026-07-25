// Package report - render-time options threaded from the CLI. Kept in a small file so the
// surface is easy to scan: DefaultTab flips which HTML tab is active on load, UsageInfo
// carries the audit-log window summary that the Least Privilege tab renders in its
// header.
package report

import (
	"time"

	"github.com/0hardik1/kubesplaining/internal/usage"
)

// Options bundles CLI-supplied render-time settings. Zero value = legacy behavior:
// DefaultTab "" preserves the report's existing initial tab (attack); UsageInfo nil hides
// the audit-log header on the Least Privilege tab; LeastPrivilegeOnly false leaves all
// four tab buttons visible; MaxPrivescDepth 0 omits the search-depth line from the
// escalation-paths tab.
type Options struct {
	// DefaultTab is the data-active-tab value the HTML report initializes to. Empty
	// preserves the existing default ("attack"). Currently the only non-empty caller is
	// scan.go's --least-privilege-only mode, which sets "leastprivilege".
	DefaultTab string

	// LeastPrivilegeOnly hides the other three tab buttons + the recon panel when
	// true. Set by scan.go's --least-privilege-only mode. Without this, an operator in
	// focus mode would still see Attack Paths / Risk Overview / Findings buttons
	// they aren't using.
	LeastPrivilegeOnly bool

	// UsageInfo is a snapshot of the usage index's window/event metadata, captured for
	// the report layer. nil means no audit data was supplied; the tab's empty-state
	// shows a help block instead of a window summary.
	UsageInfo *UsageInfo

	// MaxPrivescDepth is the --max-privesc-depth value the privesc module searched
	// with, set by scan.go from the same variable that feeds analyzer.Config. Zero
	// (the zero value) renders nothing, so a caller that does not set it (or an older
	// caller that predates this field) gets today's output unchanged. Non-zero prints
	// one line alongside the escalation paths so an operator can tell how far both the
	// primary and cut-resilient alternate search went: see the AlternateHops doc
	// comment on models.EscalationPath for why that number matters to reading an empty
	// alternate correctly.
	MaxPrivescDepth int
}

// UsageInfo carries the audit-log window summary into the report layer. We don't pass
// the full *usage.UsageIndex because (a) the report has no need for the per-subject map
// and (b) keeping the report-side type small means changing the index internals doesn't
// ripple through the renderer.
type UsageInfo struct {
	WindowStart     time.Time
	WindowEnd       time.Time
	EventsProcessed int
	EventsSkipped   int
	NonSAUsernames  int
}

// UsageInfoFrom captures the window metadata from idx. Returns nil for a nil index so
// scan.go can pass through both audit-log and no-audit-log runs uniformly.
func UsageInfoFrom(idx *usage.UsageIndex) *UsageInfo {
	if idx == nil {
		return nil
	}
	return &UsageInfo{
		WindowStart:     idx.WindowStart,
		WindowEnd:       idx.WindowEnd,
		EventsProcessed: idx.EventsProcessed,
		EventsSkipped:   idx.EventsSkipped,
		NonSAUsernames:  idx.NonSAUsernames,
	}
}

// WindowDays returns the integer day-count covered by [WindowStart, WindowEnd]. Used by
// the HTML tab header.
func (u *UsageInfo) WindowDays() int {
	if u == nil {
		return 0
	}
	return int(u.WindowEnd.Sub(u.WindowStart).Hours() / 24)
}
