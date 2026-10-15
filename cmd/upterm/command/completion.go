package command

import (
	"context"
	"strings"
	"time"

	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
)

// completeTimeout bounds a completion. The shell waits on it at every <TAB>,
// so a registry lock held by a stopped process must cost a second and an
// empty list, not a hung prompt.
const completeTimeout = time.Second

// completeSessionNames lists the running sessions' names that start with
// toComplete, for a command's first argument only. It reads the records
// (sessiondir.ListLive) under a 1 s bound and never asks a daemon: a session
// that cannot answer is as completable as one that can.
//
// Anything that goes wrong is an empty list, since the shell has no place to
// show an error, and never file names: a session's name is not a path.
func completeSessionNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), completeTimeout)
	defer cancel()
	live, err := sessiondir.ListLive(ctx, utils.UptermStateDir())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var names []string
	for _, r := range live {
		if strings.HasPrefix(r.Name, toComplete) {
			names = append(names, r.Name)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// completeValues completes a flag from a fixed list. A value ending in = is
// the start of one that goes on (go-template='...'), so the shell leaves the
// cursor against it.
func completeValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		directive := cobra.ShellCompDirectiveNoFileComp
		var matches []string
		for _, v := range values {
			if !strings.HasPrefix(v, toComplete) {
				continue
			}
			matches = append(matches, v)
			if strings.HasSuffix(v, "=") {
				directive |= cobra.ShellCompDirectiveNoSpace
			}
		}
		return matches, directive
	}
}
