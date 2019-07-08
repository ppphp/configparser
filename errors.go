package configparser

import (
	"fmt"
	"strings"
)

type Err struct {
	message string
}

func (e *Err) Error() string {
	return e.message
}

func newErr(msg string) *Err {
	return &Err{message: msg}
}

type NoSectionError struct {
	*Err
	section string
	args    []interface{}
}

func newNoSectionError(section string) *NoSectionError {
	return &NoSectionError{
		Err:     &Err{message: fmt.Sprintf("No section: %v", section)},
		section: section,
		args:    []interface{}{section},
	}
}

type DuplicateSectionError struct {
	*Err
	section string
	source  interface{}
	lineno  int
	args    []interface{}
}

func newDuplicateSectionError(section string, source interface{}, lineno int) *DuplicateSectionError { // nil, 0
	msg := []string{fmt.Sprintf("%v", section), " already exists"}
	if source != nil {
		message := []string{"While reading from ", fmt.Sprintf("%v", source)}
		if lineno != 0 {
			message = append(message, fmt.Sprintf(" [line %02d]", lineno))
		}
		message = append(message, ": section ")
		message = append(message, msg...)
		msg = message
	} else {
		msg = append([]string{"Section "}, msg...)
	}
	return &DuplicateSectionError{
		Err:     &Err{message: strings.Join(msg, "")},
		section: section,
		source:  source,
		lineno:  lineno,
		args:    []interface{}{section, source, lineno},
	}
}

type DuplicateOptionError struct {
	*Err
	section string
	option  string
	source  interface{}
	lineno  int
	args    []interface{}
}

func newDuplicateOptionError(section, option, source string, lineno int) *DuplicateOptionError { // "", nil
	msg := []string{fmt.Sprintf("%v", option), " in section ", fmt.Sprintf("%v", section), " already exists"}
	if source != "" {
		message := []string{"While reading from ", fmt.Sprintf("%v", source)}
		if lineno != 0 {
			message = append(message, fmt.Sprintf(" [line %02d]", lineno))
		}
		message = append(message, ": option ")
		message = append(message, msg...)
		msg = message
	} else {
		msg = append([]string{"Option "}, msg...)
	}
	return &DuplicateOptionError{
		Err:     &Err{message: strings.Join(msg, "")},
		section: section,
		option:  option,
		source:  source,
		lineno:  lineno,
		args:    []interface{}{section, option, source, lineno},
	}
}

type NoOptionError struct {
	*Err
	option  string
	section string
	args    []string
}

func newNoOptionError(option, section string) *NoOptionError {
	return &NoOptionError{
		Err:     newErr(fmt.Sprintf("No option %v in section: %v", option, section)),
		option:  option,
		section: section,
		args:    []string{option, section},
	}
}

type InterpolationError struct {
	*Err
	option  string
	section string
	args    []string
}

func newInterpolationError(option, section, msg string) *InterpolationError {
	return &InterpolationError{
		Err:     &Err{message: msg},
		option:  option,
		section: section,
		args:    []string{option, section, msg},
	}
}

type InterpolationMissingOptionError struct {
	*InterpolationError
	reference string
	args      []string
}

func newInterpolationMissingOptionError(option, section, rawval, reference string) *InterpolationMissingOptionError {
	msg := fmt.Sprintf("Bad value substitution: option %v in section %v contains an interpolation key %v which is not a valid option name. Raw value: %v", option, section, reference, rawval)
	return &InterpolationMissingOptionError{
		InterpolationError: newInterpolationError(option, section, msg),
		reference:          reference,
		args:               []string{option, section, rawval, reference},
	}
}

type InterpolationSyntaxError struct {
	*InterpolationError
}

func newInterpolationSyntaxError(option, section, msg string) *InterpolationSyntaxError {
	return &InterpolationSyntaxError{
		InterpolationError: newInterpolationError(option, section, msg),
	}
}

type InterpolationDepthError struct {
	*InterpolationError
	args []string
}

func newInterpolationDepthError(option, section, rawval string) *InterpolationDepthError {
	msg := fmt.Sprintf("Recursion limit exceeded in value substitution: option %v in section %v contains an interpolation key which cannot be substituted in %v steps. Raw value: %v", option, section, MaxInterpolationDepth, rawval)
	return &InterpolationDepthError{
		InterpolationError: newInterpolationError(option, section, msg),
		args:               []string{option, section, rawval},
	}
}

type ParsingError struct {
	*Err
	source string
	errors []struct {
		int
		string
	}
	args []string
}

func (p *ParsingError) append(lineno int, line string) {
	p.errors = append(p.errors, struct {
		int
		string
	}{lineno, line})
	p.message += fmt.Sprintf("\n\t[line %2d]: %s", lineno, line)
}

func newParsingError(source string) *ParsingError {
	return &ParsingError{
		Err:    &Err{message: fmt.Sprintf("Source contains parsing errors: %s", source)},
		source: source,
		errors: []struct {
			int
			string
		}{},
		args: []string{source},
	}
}

type MissingSectionHeaderError struct {
	*ParsingError
	source string
	lineno int
	line   string
	args   []interface{}
}

func newMissingSectionHeaderError(filename string, lineno int, line string) *MissingSectionHeaderError {
	return &MissingSectionHeaderError{
		ParsingError: &ParsingError{Err: newErr(fmt.Sprintf("File contains no section headers.\nfile: %v, line: %d\n%v", filename, lineno, line))},
		source:       filename,
		lineno:       lineno,
		line:         line,
		args:         []interface{}{filename, lineno, line},
	}
}
