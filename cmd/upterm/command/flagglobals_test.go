package command

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// commandPackage is this package's own files, as this platform builds them,
// type-checked against an empty stand-in for every package they import: only
// this package's own declarations, and the reads of its own variables, have
// to resolve, and they do whatever the imports hold.
type commandPackage struct {
	pkg   *types.Package
	files []*ast.File
	info  *types.Info
	fset  *token.FileSet
	decls map[*types.Func]*ast.FuncDecl
}

// standIns imports every package as an empty one, named as its path names it.
type standIns struct{}

var versionElem = regexp.MustCompile(`^v[0-9]+$`)

func (standIns) Import(importPath string) (*types.Package, error) {
	elems := strings.Split(importPath, "/")
	name := elems[len(elems)-1]
	if versionElem.MatchString(name) && len(elems) > 1 {
		name = elems[len(elems)-2]
	}
	name, _, _ = strings.Cut(strings.TrimPrefix(name, "go-"), ".")
	p := types.NewPackage(importPath, name)
	p.MarkComplete()
	return p, nil
}

// loadCommandPackage loads this package's files, and extra, each the source
// of one more file of it.
func loadCommandPackage(t *testing.T, extra ...string) *commandPackage {
	t.Helper()
	bp, err := build.ImportDir(".", 0)
	require.NoError(t, err)
	cp := &commandPackage{
		fset:  token.NewFileSet(),
		decls: make(map[*types.Func]*ast.FuncDecl),
		info: &types.Info{
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		},
	}
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(cp.fset, name, nil, 0)
		require.NoError(t, err)
		cp.files = append(cp.files, f)
	}
	for i, src := range extra {
		f, err := parser.ParseFile(cp.fset, fmt.Sprintf("extra%d.go", i), src, 0)
		require.NoError(t, err)
		cp.files = append(cp.files, f)
	}
	conf := types.Config{Importer: standIns{}, Error: func(error) {}}
	cp.pkg, _ = conf.Check(bp.ImportPath, cp.fset, cp.files, cp.info)
	require.NotNil(t, cp.pkg)
	for _, f := range cp.files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if fn, ok := cp.info.Defs[fd.Name].(*types.Func); ok {
					cp.decls[fn] = fd
				}
			}
		}
	}
	return cp
}

// funcDecl is the declaration of the package function name.
func (cp *commandPackage) funcDecl(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	fn, ok := cp.pkg.Scope().Lookup(name).(*types.Func)
	require.True(t, ok, "no function %s", name)
	return cp.decls[fn]
}

// packageVar is v when it is one of this package's package-level variables.
func (cp *commandPackage) packageVar(obj types.Object) (*types.Var, bool) {
	v, ok := obj.(*types.Var)
	return v, ok && v.Parent() == cp.pkg.Scope()
}

// registersFlag reports whether call registers a flag with a pointer it is
// given: a FlagSet's String*Var, Bool*Var, Var, VarP and the like, or a
// function of this package whose body makes one of those calls.
func (cp *commandPackage) registersFlag(call *ast.CallExpr) bool {
	var name string
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	case *ast.Ident:
		fn, ok := cp.info.Uses[fun].(*types.Func)
		if !ok || cp.decls[fn] == nil {
			return false
		}
		found := false
		ast.Inspect(cp.decls[fn].Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok && flagRegistration(s.Sel.Name) {
					found = true
				}
			}
			return !found
		})
		return found
	}
	return flagRegistration(name)
}

func flagRegistration(method string) bool {
	return strings.HasSuffix(method, "Var") || strings.HasSuffix(method, "VarP")
}

// flagVariables is every package-level variable whose address is passed to a
// call that registers a flag with it, and suppliedFlags and commandLineFlags.
func (cp *commandPackage) flagVariables(t *testing.T) map[*types.Var]bool {
	t.Helper()
	vars := make(map[*types.Var]bool)
	for _, f := range cp.files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !cp.registersFlag(call) {
				return true
			}
			for _, arg := range call.Args {
				if u, ok := arg.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if id, ok := u.X.(*ast.Ident); ok {
						if v, ok := cp.packageVar(cp.info.Uses[id]); ok {
							vars[v] = true
						}
					}
				}
			}
			return true
		})
	}
	for _, name := range []string{"suppliedFlags", "commandLineFlags"} {
		v, ok := cp.packageVar(cp.pkg.Scope().Lookup(name))
		require.True(t, ok, name)
		vars[v] = true
	}
	// The set is the flag variables upterm host has, and more: a test that
	// found none would pass whatever the walk below saw.
	for _, name := range []string{"flagServer", "flagReadOnly", "flagHostOutput", "flagGitHubUsers", "flagAllowForwarding", "flagHideClientIP"} {
		v, _ := cp.packageVar(cp.pkg.Scope().Lookup(name))
		require.True(t, vars[v], "%s isn't among the flag variables", name)
	}
	return vars
}

// pointersTo is, for each package-level variable whose initializer takes the
// address of variables in vars, those variables: legacyUserFlags holds the
// per-service flags' variables, and code reads them through it.
func (cp *commandPackage) pointersTo(vars map[*types.Var]bool) map[*types.Var][]*types.Var {
	out := make(map[*types.Var][]*types.Var)
	for _, f := range cp.files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					holder, ok := cp.packageVar(cp.info.Defs[name])
					if !ok || len(vs.Values) == 0 {
						continue
					}
					value := vs.Values[min(i, len(vs.Values)-1)]
					ast.Inspect(value, func(n ast.Node) bool {
						if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
							if id, ok := u.X.(*ast.Ident); ok {
								if v, ok := cp.packageVar(cp.info.Uses[id]); ok && vars[v] {
									out[holder] = append(out[holder], v)
								}
							}
						}
						return true
					})
				}
			}
		}
	}
	return out
}

// initializers is each package-level variable's initializer, which code
// that reads the variable runs, or calls, as hostSpawn's is guardedSpawn.
func (cp *commandPackage) initializers() map[*types.Var]ast.Expr {
	out := make(map[*types.Var]ast.Expr)
	for _, f := range cp.files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if holder, ok := cp.packageVar(cp.info.Defs[name]); ok && len(vs.Values) > 0 {
						out[holder] = vs.Values[min(i, len(vs.Values)-1)]
					}
				}
			}
		}
	}
	return out
}

// reads is every read of a variable in vars in the code reachable from
// roots: the nodes themselves, every function or method of this package they
// reference, called or not, the initializer of every package-level variable
// they read, function literals included, and the methods of every type of
// this package they build with a composite literal, transitively. An
// assignment's target isn't a read of it. A read of a variable that holds
// pointers to some of them is a read of each.
//
// The walk is static, and doesn't see:
//   - a method of a type of this package whose value reaches the walk other
//     than by a composite literal of it, by a conversion or as a zero value,
//     and called through an interface;
//   - a method called through an interface on a value from outside the
//     package; the package implements host.Broker's Place in verbatimBroker,
//     which the walk reaches as the composite literal runDaemon builds, and
//     whose body reads no flag variable;
//   - a function assigned to a package-level variable after its
//     initializer, as tests assign hostSpawn.
func (cp *commandPackage) reads(roots []ast.Node, vars map[*types.Var]bool) map[*types.Var][]string {
	pointers := cp.pointersTo(vars)
	inits := cp.initializers()
	found := make(map[*types.Var][]string)
	seen := make(map[ast.Node]bool)
	queue := append([]ast.Node(nil), roots...)
	enqueue := func(obj types.Object) {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() != cp.pkg {
			return
		}
		if d := cp.decls[fn]; d != nil && !seen[d] {
			seen[d] = true
			queue = append(queue, d)
		}
	}
	// The methods of a type of this package a composite literal builds,
	// which may be called through an interface.
	enqueueMethods := func(typ ast.Expr) {
		id, ok := typ.(*ast.Ident)
		if !ok {
			return
		}
		tn, ok := cp.info.Uses[id].(*types.TypeName)
		if !ok || tn.Pkg() != cp.pkg {
			return
		}
		ms := types.NewMethodSet(types.NewPointer(tn.Type()))
		for i := range ms.Len() {
			enqueue(ms.At(i).Obj())
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		written := make(map[*ast.Ident]bool)
		ast.Inspect(n, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if n.Tok == token.ASSIGN {
					for _, lhs := range n.Lhs {
						if id, ok := lhs.(*ast.Ident); ok {
							written[id] = true
						}
					}
				}
			case *ast.Ident:
				obj := cp.info.Uses[n]
				if v, ok := cp.packageVar(obj); ok && !written[n] {
					at := cp.fset.Position(n.Pos()).String()
					if vars[v] {
						found[v] = append(found[v], at)
					}
					for _, p := range pointers[v] {
						found[p] = append(found[p], at)
					}
				}
				if v, ok := cp.packageVar(obj); ok {
					if init := inits[v]; init != nil && !seen[init] {
						seen[init] = true
						queue = append(queue, init)
					}
				}
				enqueue(obj)
			case *ast.CompositeLit:
				enqueueMethods(n.Type)
			case *ast.SelectorExpr:
				if sel := cp.info.Selections[n]; sel != nil {
					enqueue(sel.Obj())
				}
			}
			return true
		})
	}
	return found
}

// assigned is every variable in vars that decl assigns.
func (cp *commandPackage) assigned(decl *ast.FuncDecl, vars map[*types.Var]bool) map[*types.Var]bool {
	out := make(map[*types.Var]bool)
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && a.Tok == token.ASSIGN {
			for _, lhs := range a.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					if v, ok := cp.packageVar(cp.info.Uses[id]); ok && vars[v] {
						out[v] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// fieldValues is the value of each key named one of keys in the composite
// literals in decl, such as a cobra.Command's PreRunE.
func fieldValues(decl *ast.FuncDecl, keys ...string) []ast.Node {
	var out []ast.Node
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok {
				for _, k := range keys {
					if id.Name == k {
						out = append(out, kv.Value)
					}
				}
			}
		}
		return true
	})
	return out
}

func describe(found map[*types.Var][]string) string {
	var lines []string
	for v, at := range found {
		lines = append(lines, v.Name()+" read at "+path.Base(at[0]))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// buildDaemonHost builds the host from its HostSettings alone, so that a
// delegated run's host is the one its parent resolved: neither it nor
// anything it calls reads a flag's variable.
func TestBuildDaemonHostReadsNoFlagGlobal(t *testing.T) {
	cp := loadCommandPackage(t)
	vars := cp.flagVariables(t)
	found := cp.reads([]ast.Node{cp.funcDecl(t, "buildDaemonHost")}, vars)
	require.Empty(t, found, "buildDaemonHost reads flag variables:\n%s", describe(found))
}

// A delegated run's session process takes every flag variable it reads, from
// the root's pre-run through upterm host's pre-run to the session, from its
// handoff: each is one applySettings assigns.
func TestHostSettingsCoverEveryHostFlag(t *testing.T) {
	cp := loadCommandPackage(t)
	vars := cp.flagVariables(t)

	var roots []ast.Node
	roots = append(roots, fieldValues(cp.funcDecl(t, "RootWith"), "PersistentPreRunE")...)
	roots = append(roots, fieldValues(cp.funcDecl(t, "hostCmdWith"), "PreRunE")...)
	require.Len(t, roots, 2, "the root's PersistentPreRunE and upterm host's PreRunE")
	roots = append(roots, cp.funcDecl(t, "runDaemon"))

	found := cp.reads(roots, vars)
	require.NotEmpty(t, found)
	assigned := cp.assigned(cp.funcDecl(t, "applySettings"), vars)
	for v := range assigned {
		delete(found, v)
	}
	require.Empty(t, found, "a delegated run's session process reads these, which applySettings doesn't assign:\n%s", describe(found))
}

// The walk the two tests above rely on sees each kind of reach it claims to:
// a package variable's initializer, a function literal one included, and a
// method of a type a composite literal builds, called through an interface.
func TestTheFlagWalkFollowsWhatItClaims(t *testing.T) {
	cp := loadCommandPackage(t, `package command

var zzLiteral = func() string { return flagEscapeChar }

func zzTerm() string { return flagTerm }

var zzNamed = zzTerm

type zzType struct{}

func (zzType) zzMethod() string { return flagPtySize }

type zzIface interface{ zzMethod() string }

func zzRoot() {
	_ = zzLiteral()
	_ = zzNamed()
	var i zzIface = zzType{}
	_ = i.zzMethod()
}
`)
	found := cp.reads([]ast.Node{cp.funcDecl(t, "zzRoot")}, cp.flagVariables(t))
	var names []string
	for v := range found {
		names = append(names, v.Name())
	}
	require.ElementsMatch(t, []string{"flagEscapeChar", "flagTerm", "flagPtySize"}, names)
}
