package errors

import stderrors "errors"

// errIs is an internal alias to stdlib errors.Is.
// We need this because this package is also named "errors", which shadows
// the standard library import from within the same package.
func errIs(err, target error) bool {
	return stderrors.Is(err, target)
}

// errAs is an internal alias to stdlib errors.As.
func errAs(err error, target interface{}) bool {
	return stderrors.As(err, target)
}
