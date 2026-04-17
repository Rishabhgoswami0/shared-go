package validator

import (
	"fmt"
	"reflect"
	"strings"

	playgroundvalidator "github.com/go-playground/validator/v10"

	apperrors "github.com/Rishabhgoswami0/shared-go/pkg/errors"
)

// Validate is the shared validator instance.
var Validate *playgroundvalidator.Validate

func Init() {
	Validate = playgroundvalidator.New()

	// Use JSON field names in error messages instead of Go struct field names.
	Validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

func init() {
	Init()
}

// ValidateStruct validates any struct and returns a ready-to-use *AppError.
func ValidateStruct(s any) *apperrors.AppError {
	err := Validate.Struct(s)
	if err == nil {
		return nil
	}

	params := toInvalidParams(err)
	return apperrors.NewValidationError("request validation failed", params)
}

// toInvalidParams converts go-playground ValidationErrors to []apperrors.InvalidParam.
func toInvalidParams(err error) []apperrors.InvalidParam {
	ve, ok := err.(playgroundvalidator.ValidationErrors)
	if !ok {
		return []apperrors.InvalidParam{{Name: "request", Reason: err.Error()}}
	}

	params := make([]apperrors.InvalidParam, 0, len(ve))
	for _, fe := range ve {
		// Strip the root struct name from the namespace.
		// e.g. "CreateTenantRequest.address.street" -> "address.street"
		name := fe.Namespace()
		if idx := strings.Index(name, "."); idx != -1 {
			name = name[idx+1:]
		}

		params = append(params, apperrors.InvalidParam{
			Name:   name,
			Reason: msgForTag(fe),
		})
	}
	return params
}

func msgForTag(fe playgroundvalidator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "this field is required"
	case "email":
		return "invalid email format"
	case "min":
		return fmt.Sprintf("must be at least %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters", fe.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", fe.Param())
	}
	return fmt.Sprintf("validation failed on '%s' tag", fe.Tag())
}
