package command

import (
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// A command's help can list its flags under headings rather than as one
// Flags list. The command's upterm/help-groups annotation is its headings,
// in order, one per line; a flag's upterm/help-group annotation is the
// heading it is listed under. A flag with none, cobra's -h among them, is
// listed under the last heading.
const (
	annotationHelpGroups = "upterm/help-groups"
	annotationHelpGroup  = "upterm/help-group"
)

// flagGroup lists the flags of fs named in names under heading.
func flagGroup(fs *pflag.FlagSet, heading string, names ...string) {
	for _, name := range names {
		// Only errors on an unknown flag name; TestHostHelpGroupsItsFlags
		// pins every heading's flags.
		_ = fs.SetAnnotation(name, annotationHelpGroup, []string{heading})
	}
}

// The section of cobra's usage template that lists a command's own flags,
// and the one groupFlags puts in its place.
const (
	flagsSection = `{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}`
	groupedFlagsSection = `{{if .HasAvailableLocalFlags}}{{range flagGroups .}}

{{.Heading}}:
{{.Usages | trimTrailingWhitespaces}}{{end}}{{end}}`
)

// registerFlagGroups makes flagGroups a function cobra's templates can call,
// once: cobra keeps them in a map of its own.
var registerFlagGroups sync.Once

// groupFlags makes cmd's help list its flags under headings, in this order.
func groupFlags(cmd *cobra.Command, headings ...string) {
	registerFlagGroups.Do(func() { cobra.AddTemplateFunc("flagGroups", flagGroups) })
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[annotationHelpGroups] = strings.Join(headings, "\n")
	cmd.SetUsageTemplate(strings.Replace(cmd.UsageTemplate(), flagsSection, groupedFlagsSection, 1))
}

// flagGroupUsage is a heading and the usage lines of the flags under it.
type flagGroupUsage struct{ Heading, Usages string }

// usageLineFlag matches the line of pflag's usages that starts a flag's
// entry, "  -r, --read-only ..." or "      --accept ...", and captures the
// flag's name. An entry whose usage runs over lines continues on lines that
// don't match.
var usageLineFlag = regexp.MustCompile(`^  (?:-\S, |    )--([^\s=]+)`)

// flagGroups is cmd's flags under its headings, each heading's in the order
// pflag lists them, leaving out a heading with none. The usages are pflag's
// for all of cmd's flags at once, cut into the groups, so their columns line
// up across the headings.
func flagGroups(cmd *cobra.Command) []flagGroupUsage {
	headings := strings.Split(cmd.Annotations[annotationHelpGroups], "\n")
	usages := make(map[string]*strings.Builder, len(headings))
	for _, h := range headings {
		usages[h] = &strings.Builder{}
	}
	flags := cmd.LocalFlags()
	var entry *strings.Builder
	for _, line := range strings.SplitAfter(flags.FlagUsages(), "\n") {
		if m := usageLineFlag.FindStringSubmatch(line); m != nil {
			entry = usages[headings[len(headings)-1]]
			if f := flags.Lookup(m[1]); f != nil {
				if g := f.Annotations[annotationHelpGroup]; len(g) == 1 && usages[g[0]] != nil {
					entry = usages[g[0]]
				}
			}
		}
		if entry != nil {
			entry.WriteString(line)
		}
	}
	var groups []flagGroupUsage
	for _, h := range headings {
		if u := usages[h].String(); u != "" {
			groups = append(groups, flagGroupUsage{h, u})
		}
	}
	return groups
}
