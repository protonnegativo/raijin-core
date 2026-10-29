package scope

import (
	"errors"
	"fmt"
	"strings"

	"github.com/protonnegativo/raijin-core/schema"
)

// ErrorKind is the Kind of the schema.Error a scope problem becomes.
const ErrorKind = "scope"

// LineError is one rule Parse cannot use. It is written for a reader that has to fix the scope file
// without asking anyone: Hint says what to write instead.
type LineError struct {
	// Line is the 1-based line in the scope file; 0 when the problem is not about one line (a scope with
	// no include rule).
	Line int
	// Rule is the line as written, trimmed.
	Rule string
	// Reason is what is wrong, such as "port in rule".
	Reason string
	// Hint is what to write instead.
	Hint string
}

// Error implements error.
func (e *LineError) Error() string {
	return e.message()
}

func (e *LineError) message() string {
	var b strings.Builder
	if e.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	b.WriteString(e.Reason)
	if e.Rule != "" {
		fmt.Fprintf(&b, " '%s'", e.Rule)
	}
	if e.Hint != "" {
		b.WriteString("; " + e.Hint)
	}
	return b.String()
}

// SchemaError returns the problem as a schema.Error: Kind "scope" and a Hint such as
// "line 3: port in rule 'example.com:443'; use the host only: 'example.com'".
func (e *LineError) SchemaError() schema.Error {
	return schema.Error{Kind: ErrorKind, Hint: e.message()}
}

// ParseError is what Parse returns for an invalid scope: every line that cannot be used, in file order.
// errors.As finds a *ParseError, and also each *LineError in it.
type ParseError struct {
	Lines []*LineError
}

// Error implements error. It lists every problem, one per line.
func (e *ParseError) Error() string {
	parts := make([]string, len(e.Lines))
	for i, l := range e.Lines {
		parts[i] = l.Error()
	}
	return "invalid scope: " + strings.Join(parts, "\n")
}

// Unwrap lets errors.As and errors.Is reach each LineError.
func (e *ParseError) Unwrap() []error {
	out := make([]error, len(e.Lines))
	for i, l := range e.Lines {
		out[i] = l
	}
	return out
}

// SchemaErrors returns one schema.Error per problem in err, for a tool to put in its result's errors: one
// per invalid line when err is (or wraps) a *ParseError, and a single error of Kind "scope" for anything
// else Load can fail with, such as a file that cannot be read. It returns nil for a nil error.
func SchemaErrors(err error) []schema.Error {
	if err == nil {
		return nil
	}
	var pe *ParseError
	if errors.As(err, &pe) {
		out := make([]schema.Error, len(pe.Lines))
		for i, l := range pe.Lines {
			out[i] = l.SchemaError()
		}
		return out
	}
	return []schema.Error{{Kind: ErrorKind, Hint: "cannot read the scope file: " + err.Error()}}
}
