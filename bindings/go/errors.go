package cb2

/*
#include "cb2_c.h"
*/
import "C"

// The error codes of the C ABI, the Code of an *Error; 0 is success and
// never appears in an error.
const (
	CodeInvalid          = 1
	CodeTooLarge         = 2
	CodeArgument         = 3
	CodeRulesIncomplete  = 4
	CodeInternal         = 5
	CodeUnavailable      = 6
	CodeClaimsMalformed  = 7
	CodeMissingExp       = 8
	CodeExpired          = 9
	CodeNotYetValid      = 10
	CodeIssuedInFuture   = 11
	CodeLifetimeExceeded = 12
	CodeIssuerMismatch   = 13
	CodeAudienceMismatch = 14
	CodeSubjectMismatch  = 15
	CodeMissingJTI       = 16
	CodeReplayed         = 17
	CodeMissingCnf       = 18
	CodeMissingProof     = 19
	CodeProofInvalid     = 20
	CodeProofMalformed   = 21
	CodeProofExpired     = 22
	CodeProofMismatch    = 23
	CodeProofReplayed    = 24
)

// Error is a verdict of the library: its positive code and the stable
// name the library gives that code ("invalid", "expired", ...).
// errors.Is matches two Errors by Code, so the Err sentinels work as
// targets; errors.As gives access to the code itself. Every call returns
// a fresh *Error, so a caller may keep or change the one it receives.
type Error struct {
	Code int
	Name string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return "cb2: " + e.Name
}

// Is reports whether target is an *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// ErrorName returns the library's name for a code, "ok" for 0 and
// "unknown" for a code it does not have.
func ErrorName(code int) string {
	return C.GoString(C.cb2_error_name(C.int(code)))
}

// NewError builds the Error for a code with the library's name for it.
func NewError(code int) *Error {
	return &Error{Code: code, Name: ErrorName(code)}
}

// Sentinel errors for errors.Is, one per code of the C ABI.
var (
	ErrInvalid          = NewError(CodeInvalid)
	ErrTooLarge         = NewError(CodeTooLarge)
	ErrArgument         = NewError(CodeArgument)
	ErrRulesIncomplete  = NewError(CodeRulesIncomplete)
	ErrInternal         = NewError(CodeInternal)
	ErrUnavailable      = NewError(CodeUnavailable)
	ErrClaimsMalformed  = NewError(CodeClaimsMalformed)
	ErrMissingExp       = NewError(CodeMissingExp)
	ErrExpired          = NewError(CodeExpired)
	ErrNotYetValid      = NewError(CodeNotYetValid)
	ErrIssuedInFuture   = NewError(CodeIssuedInFuture)
	ErrLifetimeExceeded = NewError(CodeLifetimeExceeded)
	ErrIssuerMismatch   = NewError(CodeIssuerMismatch)
	ErrAudienceMismatch = NewError(CodeAudienceMismatch)
	ErrSubjectMismatch  = NewError(CodeSubjectMismatch)
	ErrMissingJTI       = NewError(CodeMissingJTI)
	ErrReplayed         = NewError(CodeReplayed)
	ErrMissingCnf       = NewError(CodeMissingCnf)
	ErrMissingProof     = NewError(CodeMissingProof)
	ErrProofInvalid     = NewError(CodeProofInvalid)
	ErrProofMalformed   = NewError(CodeProofMalformed)
	ErrProofExpired     = NewError(CodeProofExpired)
	ErrProofMismatch    = NewError(CodeProofMismatch)
	ErrProofReplayed    = NewError(CodeProofReplayed)
)

// ErrClosed is returned by every call made with a closed or nil key, or
// with a closed claim table. It wraps an argument error, the code the C
// ABI gives a missing handle, so errors.Is(err, ErrArgument) holds for it
// as well.
var ErrClosed error = closedError{}

type closedError struct{}

func (closedError) Error() string {
	return "cb2: key is closed"
}

func (closedError) Unwrap() error {
	return NewError(CodeArgument)
}

func check(code C.int) error {
	if code == 0 {
		return nil
	}
	return NewError(int(code))
}

func nilResult() error {
	return NewError(CodeInternal)
}
