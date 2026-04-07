package validator

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validate is the global validator instance.
var Validate *validator.Validate

func Init() {
	Validate = validator.New()

	// Register a custom function to get JSON tag names for error messages
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

// FormatValidationErrors standardizes validator.ValidationErrors into a map[string]string.
func FormatValidationErrors(err error) map[string]string {
	errors := make(map[string]string)
	if ve, ok := err.(validator.ValidationErrors); ok {
		for _, fe := range ve {
			errors[fe.Field()] = msgForTag(fe)
		}
	} else {
		errors["error"] = err.Error()
	}
	return errors
}

func msgForTag(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Invalid email format"
	case "min":
		return fmt.Sprintf("Must be at least %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("Must be at most %s characters", fe.Param())
	}
	return fmt.Sprintf("Validation failed on the %s tag", fe.Tag())
}
