// SPDX-License-Identifier: AGPL-3.0-or-later

// Command sql-lint is a build-time guard that catches the two failure
// modes that have produced production OAuth outages on this codebase:
//
//  1. Boundary-whitespace concat bug (2026-05-01).
//     `oauthClientColumns` Go raw-string constant ended with a bare
//     identifier (`client_uri`) and was concatenated directly via `+`
//     against the literal `FROM iam_oauth_clients ...` with no
//     whitespace at the boundary. The result `client_uriFROM` mashed
//     into a single identifier; PG rejected the SELECT (SQLSTATE
//     42703) and every /oauth/authorize, /oauth/token, /oauth/introspect
//     failed for hours.
//
//     Note: only `+` concatenation triggers this — `fmt.Sprintf("SELECT
//     %s FROM ...", const)` is safe because the format string supplies
//     the boundary whitespace.
//
//  2. Schema-vs-Scan drift (2026-04-24).
//     `iam_oauth_tokens` Go repo SELECTed `token_type, token,
//     refresh_token, ...` while the live PG schema still carried the
//     legacy `access_token_hash, refresh_token_hash, ...` shape. Every
//     /oauth/token round-tripped a SQLSTATE 42703 "column \"token_type\"
//     of relation \"iam_oauth_tokens\" does not exist".
//
// Strategy:
//
//   - Walk every Go file under internal/repositories/. Find all const
//     declarations whose name ends in `Columns` and whose value is a
//     single raw-string literal.
//   - Boundary check: only enforced when the constant is used in a `+`
//     concatenation expression. We walk every usage AST and inspect
//     the neighboring StringLits — if a literal sits next to the const
//     without trailing/leading whitespace at the join, flag the
//     constant. fmt.Sprintf usage is exempt (format string provides
//     whitespace).
//   - Schema-drift check: extract every bare column identifier from
//     the constant's body (skipping COALESCE/CAST wrappers, SQL
//     keywords, and content inside single-quoted SQL string literals)
//     and confirm each appears at least once in migrations/*.up.sql.
//     A column referenced in repo code that does not appear in any
//     migration is by definition drift.
//
// Run with `go run ./hack/sql-lint`. Exits 0 on clean, non-zero with a
// structured report on failure.

package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	repoRoot       = "."
	repositoryDir  = "internal/repositories"
	migrationsDir  = "migrations"
	columnsSuffix  = "Columns"
	migrationsGlob = "*.up.sql"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sql-lint: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	root := repoRoot
	if v := os.Getenv("SQL_LINT_ROOT"); v != "" {
		root = v
	}

	repoFiles, err := goFilesUnder(filepath.Join(root, repositoryDir))
	if err != nil {
		return fmt.Errorf("scan repositories: %w", err)
	}
	if len(repoFiles) == 0 {
		return fmt.Errorf("no Go files found under %s — wrong working directory?", repositoryDir)
	}

	// Schema-drift check uses migrations/*.up.sql as the source of truth
	// for "which columns exist in the live PG schema". Phase-2b MR4
	// (2026-05-04) deleted migrations/embed.go + every *.up.sql — realm
	// schema now comes from the canonical SchemaDefinition CR
	// `falcon-id-tenant-desired` (the GitOps repository). The platform-admin
	// schema remains MigrationBundle-driven (also in the GitOps repository).
	//
	// Schema-drift detection from the SD CR is a follow-up — the
	// 17,998-line YAML at <gitops-repo>/keystone/resources/
	// falcon-id/schema-definition-tenant.yaml is the single source of
	// truth, but parsing it lives in another repo. Until that lands,
	// schema-drift checks degrade to "skipped, with a clear message"
	// when the legacy migrations/ tree is absent. The boundary-
	// whitespace check (the more common 2026-05-01 outage shape) still
	// runs unconditionally.
	migrationsCorpus, err := loadMigrations(filepath.Join(root, migrationsDir))
	if err != nil {
		// Treat "no migrations dir" / "empty migrations dir" as a soft
		// signal that schema-drift checks are skipped under MR4. Other
		// errors (read failure on a present file) still propagate.
		if errors.Is(err, errNoMigrationsCorpus) {
			fmt.Fprintln(os.Stderr,
				"sql-lint: schema-drift check skipped — migrations/*.up.sql is gone post-phase-2b MR4. Boundary-whitespace check still runs.")
			migrationsCorpus = ""
		} else {
			return fmt.Errorf("load migrations: %w", err)
		}
	}

	// Collect all consts and all `+`-concat usages across files.
	consts := map[string]columnsConstant{}
	var concatUsages []concatUsage
	for _, f := range repoFiles {
		fset := token.NewFileSet()
		ast, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", f, err)
		}
		extractConsts(fset, ast, f, consts)
		concatUsages = append(concatUsages, extractConcatUsages(fset, ast, f, consts)...)
	}

	var findings []finding
	// Boundary check: only flag a constant if at least one `+` usage
	// has missing whitespace at the join.
	flaggedHead := map[string]bool{}
	flaggedTail := map[string]bool{}
	for _, u := range concatUsages {
		c, ok := consts[u.constName]
		if !ok {
			continue
		}
		if u.left != nil && !endsWithSQLBoundaryWhitespace(*u.left) && !startsWithSQLBoundaryWhitespace(c.value) && !flaggedHead[u.constName] {
			findings = append(findings, finding{
				severity: "error",
				location: u.position,
				message: fmt.Sprintf(
					"%s is concatenated via `+` after a string literal that does not end in whitespace, and the constant itself does not start with whitespace. The two sides will mash into a single SQL identifier (the 2026-05-01 outage shape). Either add a trailing space to the literal at this call site, or add a leading newline/space to %s. Constant declared at %s.",
					u.constName, u.constName, c.position,
				),
			})
			flaggedHead[u.constName] = true
		}
		if u.right != nil && !startsWithSQLBoundaryWhitespace(*u.right) && !endsWithSQLBoundaryWhitespace(c.value) && !flaggedTail[u.constName] {
			findings = append(findings, finding{
				severity: "error",
				location: u.position,
				message: fmt.Sprintf(
					"%s is concatenated via `+` before a string literal that does not start with whitespace, and the constant itself does not end with whitespace. The two sides will mash into a single SQL identifier (the 2026-05-01 outage shape: `client_uriFROM` was parsed as one identifier and PG rejected the SELECT with SQLSTATE 42703). Either add a leading space to the literal at this call site, or add a trailing newline/space to %s. Constant declared at %s.",
					u.constName, u.constName, c.position,
				),
			})
			flaggedTail[u.constName] = true
		}
	}

	// Schema-drift check: every constant, every column. Skipped silently
	// when migrationsCorpus is empty (post-MR4 — see loadMigrations
	// comment for the SD-CR-based replacement plan).
	if migrationsCorpus != "" {
		for _, c := range consts {
			findings = append(findings, checkSchemaDrift(c, migrationsCorpus)...)
		}
	}

	if len(findings) == 0 {
		fmt.Println("sql-lint: 0 findings")
		return nil
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].severity != findings[j].severity {
			return findings[i].severity > findings[j].severity
		}
		return findings[i].location < findings[j].location
	})
	fmt.Fprintln(os.Stderr, "sql-lint findings:")
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  [%s] %s — %s\n", f.severity, f.location, f.message)
	}
	return fmt.Errorf("%d finding(s)", len(findings))
}

// columnsConstant is a parsed `const xxxColumns = \`...\`` declaration.
type columnsConstant struct {
	name     string
	value    string
	file     string
	position string // file:line for error messages
}

// concatUsage is a `+` BinaryExpr where one operand is a *Columns
// identifier. left/right are the neighboring StringLit values when
// the neighbour is a literal; nil when it is some other expression
// (in which case we don't have enough info to flag).
type concatUsage struct {
	constName string
	position  string
	left      *string // literal value to the left, or nil
	right     *string // literal value to the right, or nil
}

type finding struct {
	severity string // "error" or "warn"
	location string
	message  string
}

func goFilesUnder(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	return out, err
}

// errNoMigrationsCorpus is the soft-skip signal returned by loadMigrations
// when the migrations directory is missing or empty. The schema-drift
// check is skipped in that case rather than failing — see the lengthy
// comment at the call site for the phase-2b MR4 context.
var errNoMigrationsCorpus = errors.New("no migrations corpus found")

func loadMigrations(dir string) (string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, migrationsGlob))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", errNoMigrationsCorpus
	}
	var sb strings.Builder
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", m, err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func extractConsts(fset *token.FileSet, f *ast.File, file string, out map[string]columnsConstant) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasSuffix(name.Name, columnsSuffix) {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val := lit.Value
				if len(val) >= 2 {
					val = val[1 : len(val)-1]
				}
				out[name.Name] = columnsConstant{
					name:     name.Name,
					value:    val,
					file:     file,
					position: fset.Position(name.NamePos).String(),
				}
			}
		}
	}
}

// extractConcatUsages walks the AST and reports every `+` BinaryExpr
// involving a *Columns identifier from `consts`. We descend into nested
// `+` chains so an expression like `"a" + xColumns + "b"` reports both
// neighbors.
func extractConcatUsages(fset *token.FileSet, f *ast.File, file string, consts map[string]columnsConstant) []concatUsage {
	var usages []concatUsage
	ast.Inspect(f, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return true
		}
		// Flatten the chain into a list of operands so we can find
		// the constant and its immediate neighbours.
		operands := flattenAdd(bin)
		for i, op := range operands {
			id, ok := op.(*ast.Ident)
			if !ok {
				continue
			}
			if _, isConst := consts[id.Name]; !isConst {
				continue
			}
			u := concatUsage{
				constName: id.Name,
				position:  fset.Position(id.NamePos).String(),
			}
			if i > 0 {
				if v, ok := stringLitValue(operands[i-1]); ok {
					u.left = &v
				}
			}
			if i+1 < len(operands) {
				if v, ok := stringLitValue(operands[i+1]); ok {
					u.right = &v
				}
			}
			usages = append(usages, u)
		}
		return true
	})
	_ = file
	return usages
}

// flattenAdd turns `a + b + c + d` (left-associated as
// `((a+b)+c)+d`) into [a, b, c, d].
func flattenAdd(e ast.Expr) []ast.Expr {
	bin, ok := e.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return []ast.Expr{e}
	}
	var out []ast.Expr
	out = append(out, flattenAdd(bin.X)...)
	out = append(out, flattenAdd(bin.Y)...)
	return out
}

func stringLitValue(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v := lit.Value
	if len(v) >= 2 {
		v = v[1 : len(v)-1]
	}
	return v, true
}

func startsWithSQLBoundaryWhitespace(s string) bool {
	if s == "" {
		return false
	}
	return isSQLBoundaryWhitespace(s[0])
}

func endsWithSQLBoundaryWhitespace(s string) bool {
	if s == "" {
		return false
	}
	return isSQLBoundaryWhitespace(s[len(s)-1])
}

func isSQLBoundaryWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// checkSchemaDrift catches the 2026-04-24 outage shape: a column name
// referenced in a repo SELECT that no migration has ever introduced.
//
// We extract bare identifier tokens from the constant body, then grep
// the migrations corpus for each. False positives are avoided by:
//
//   - skipping SQL keywords + common function names + type names
//   - skipping function-call syntax (identifier immediately followed
//     by `(`)
//   - skipping cast targets (identifier preceded by `::`)
//   - stripping content inside single-quoted SQL string literals so
//     `'RS256'` does not register as the column `rs256`
//   - requiring the migrations match be a word-boundary match so
//     `id` does not false-positive against `tenant_id`
func checkSchemaDrift(c columnsConstant, migrationsCorpus string) []finding {
	cols := extractBareColumns(c.value)
	if len(cols) == 0 {
		return nil
	}
	var out []finding
	for _, col := range cols {
		if !columnReferencedInMigrations(col, migrationsCorpus) {
			out = append(out, finding{
				severity: "error",
				location: c.position,
				message: fmt.Sprintf(
					"%s references column %q but no migration under migrations/*.up.sql declares it. This is the 2026-04-24 schema-drift shape: repo code SELECTs a column the live PG schema does not have, and every query 500s with SQLSTATE 42703 at runtime. Add the column via a migration, fix the typo, or remove the reference.",
					c.name, col,
				),
			})
		}
	}
	return out
}

func extractBareColumns(body string) []string {
	// Strip single-quoted SQL string literals so identifiers inside
	// 'RS256' / 'general' / etc. do not register as columns.
	body = stripSQLStringLiterals(body)

	skip := map[string]bool{
		"select": true, "from": true, "where": true, "and": true,
		"or": true, "as": true, "on": true, "join": true, "left": true,
		"right": true, "inner": true, "outer": true, "full": true,
		"by": true, "order": true, "group": true, "having": true,
		"limit": true, "offset": true, "asc": true, "desc": true,
		"true": true, "false": true, "null": true, "is": true,
		"not": true, "in": true, "like": true, "between": true,
		"distinct": true, "exists": true, "values": true, "set": true,
		"into": true, "returning": true, "case": true, "when": true,
		"then": true, "else": true, "end": true,
		// Aggregate / scalar functions.
		"coalesce": true, "count": true, "sum": true, "avg": true,
		"min": true, "max": true, "now": true, "lower": true,
		"upper": true, "trim": true, "length": true, "concat": true,
		"nullif": true, "greatest": true, "least": true, "extract": true,
		// Type names that appear after `::`.
		"text": true, "jsonb": true, "json": true, "uuid": true,
		"timestamp": true, "timestamptz": true, "int": true,
		"integer": true, "bigint": true, "smallint": true,
		"boolean": true, "bool": true, "varchar": true, "char": true,
		"date": true, "time": true, "interval": true, "numeric": true,
		"decimal": true, "real": true, "float": true, "bytea": true,
		// Verb of CAST(... AS <type>).
		"cast": true,
	}

	re := regexp.MustCompile(`[a-z_][a-z0-9_]{1,}`)
	matches := re.FindAllStringIndex(strings.ToLower(body), -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		tok := strings.ToLower(body[m[0]:m[1]])
		if skip[tok] {
			continue
		}
		if m[1] < len(body) && body[m[1]] == '(' {
			continue
		}
		if m[0] >= 2 && body[m[0]-2:m[0]] == "::" {
			continue
		}
		if seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

// stripSQLStringLiterals replaces every `'...'` with the same number of
// spaces, preserving offsets so the regex still operates on the same
// byte positions but ignores literal contents.
func stripSQLStringLiterals(s string) string {
	out := []byte(s)
	inStr := false
	for i := 0; i < len(out); i++ {
		b := out[i]
		if b == '\'' {
			out[i] = ' '
			inStr = !inStr
			continue
		}
		if inStr {
			out[i] = ' '
		}
	}
	return string(out)
}

func columnReferencedInMigrations(col, corpus string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(col) + `\b`)
	return re.MatchString(corpus)
}
