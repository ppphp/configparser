package configparser

// stupid copy of python version

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	DefaultSect = "DEFAULT"

	MaxInterpolationDepth = 10
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

var _UNSET = newInterpolation()

type Interpolation interface {
	beforeGet(parser ConfigParser, section, option, value string, defaults map[string]string) (string, error)
	beforeSet(parser ConfigParser, section, option, value string) (string, error)
	beforeRead(parser ConfigParser, section, option, value string) (string, error)
	beforeWrite(parser ConfigParser, section, option, value string) (string, error)
}

type interpolation struct{}

func (i *interpolation) beforeGet(parser ConfigParser, section, option, value string, defaults map[string]string) (string, error) {
	return value, nil
}

func (i *interpolation) beforeSet(parser ConfigParser, section, option, value string) (string, error) {
	return value, nil
}

func (i *interpolation) beforeRead(parser ConfigParser, section, option, value string) (string, error) {
	return value, nil
}

func (i *interpolation) beforeWrite(parser ConfigParser, section, option, value string) (string, error) {
	return value, nil
}

func newInterpolation() *interpolation {
	return &interpolation{}
}

type basicInterpolation struct {
	*interpolation
	KeyCre *regexp.Regexp
}

func (b *basicInterpolation) beforeGet(parser ConfigParser, section, option, value string, defaults map[string]string) (string, error) {
	L := []string{}
	if err := b._interpolate_some(parser, option, L, value, section, defaults, 1); err != nil {
		return "", err
	}
	return strings.Join(L, ""), nil
}

func (b *basicInterpolation) beforeSet(parser ConfigParser, section, option, value string) (string, error) {
	tmpValue := strings.Replace(value, "%%", "", -1)
	tmpValue = b.KeyCre.ReplaceAllString(tmpValue, "")
	if strings.Contains(tmpValue, "%") {
		return "", fmt.Errorf("invalid interpolation syntax in %s at position %d", value, strings.Index(tmpValue, "%")) // ValueError
	}
	return value, nil
}

func (b *basicInterpolation) _interpolate_some(parser ConfigParser, option string, accum []string, rest string, section string, mapp map[string]string, depth int) error {
	rawval, _ := parser.Get(section, option, true, nil, rest)
	if depth > MaxInterpolationDepth {
		return newInterpolationDepthError(option, section, rawval)
	}
	for len(rest) > 0 {
		p := strings.Index(rest, "%")
		if p < 0 {
			accum = append(accum, rest)
			return nil
		}
		if p > 0 {
			accum = append(accum, rest[:p])
			rest = rest[p:]
		}
		c := rest[1:2]
		if c == "%" {
			accum = append(accum, "%")
			rest = rest[2:]
		} else if c == "(" {
			if !b.KeyCre.MatchString(rest) {
				return newInterpolationSyntaxError(option, section, fmt.Sprintf("bad interpolation variable reference %s", rest))
			}
			varr := parser.optionxform(b.KeyCre.FindAllStringSubmatch(rest, -1)[0][1])
			rest = rest[b.KeyCre.FindAllStringSubmatchIndex(rest, -1)[0][1]:]
			v, ok := mapp[varr]
			if !ok {
				return newInterpolationMissingOptionError(option, section, rawval, varr)
			}
			in := false
			for _, m := range v {
				if m == '%' {
					in = true
					break
				}
			}
			if in {
				//if err := b._interpolate_some(parser, option, accum, v,
				//	section, mapp, depth+1); err != nil {
				//	return err
				//}
			} else {
				//accum = append(accum, v)
			}
		} else {
			return newInterpolationSyntaxError(option, section, fmt.Sprintf("'%%' must be followed by '%%' or '(', found: %s", rest))
		}
	}
	return nil
}

func newBasicInterpolation() *basicInterpolation {
	return &basicInterpolation{
		interpolation: &interpolation{},
		KeyCre:        regexp.MustCompile("%\\(([^)]+)\\)s"),
	}
}

type extendedInterpolation struct {
	*interpolation
	KeyCre *regexp.Regexp
}

func (b *extendedInterpolation) beforeGet(parser ConfigParser, section, option, value string, defaults map[string]string) (string, error) {
	L := []string{}
	//if err := b._interpolate_some(parser, option, L, value, section, defaults, 1); err != nil {
	//	return "", err
	//}
	return strings.Join(L, ""), nil
}

func (b *extendedInterpolation) beforeSet(parser ConfigParser, section, option, value string) (string, error) {
	tmpValue := strings.Replace(value, "$$", "", -1)
	tmpValue = b.KeyCre.ReplaceAllString(tmpValue, "")
	if strings.Contains(tmpValue, "$") {
		return "", fmt.Errorf("invalid interpolation syntax in %s at position %d", value, strings.Index(tmpValue, "$")) // ValueError
	}
	return value, nil
}

func (b *extendedInterpolation) _interpolate_some(parser ConfigParser, option string, accum []string, rest string, section string, mapp map[string][]string, depth int) error {
	rawval, _ := parser.Get(section, option, true, nil, rest)
	if depth > MaxInterpolationDepth {
		return newInterpolationDepthError(option, section, rawval)
	}
	for len(rest) > 0 {
		p := strings.Index(rest, "$")
		if p < 0 {
			accum = append(accum, rest)
			return nil
		}
		if p > 0 {
			accum = append(accum, rest[:p])
			rest = rest[p:]
		}
		c := rest[1:2]
		if c == "$" {
			accum = append(accum, "$")
			rest = rest[2:]
		} else if c == "{" {
			if !b.KeyCre.MatchString(rest) {
				return newInterpolationSyntaxError(option, section, fmt.Sprintf("bad interpolation variable reference %s", rest))
			}
			path := strings.Split(b.KeyCre.FindAllStringSubmatch(rest, -1)[0][1], ":")
			rest = rest[b.KeyCre.FindAllStringSubmatchIndex(rest, -1)[0][1]:]
			//sect := section
			var v []string = nil
			if len(path) == 1 {
				opt := parser.optionxform(path[0])
				v = mapp[opt]
			} else if len(path) == 1 {
				//sect = path[0]
				//opt := parser.optionxform(path[1])
				//v, _ = parser.Get(sect, opt, true, nil, "")
			} else {
				return newInterpolationSyntaxError(option, section, fmt.Sprintf("More than one ':' found: %v", rest))
			}
			//except (KeyError, NoSectionError, NoOptionError):
			//raise InterpolationMissingOptionError(
			//	option, section, rawval, ":".join(path)) from None

			in := false
			for _, m := range v {
				if m == "%" {
					in = true
					break
				}
			}
			if in {
				//if err := b._interpolate_some(parser, option, accum, v,
				//	section, mapp, depth+1); err != nil {
				//	return err
				//}
			} else {
				//accum = append(accum, v)
			}
		} else {
			return newInterpolationSyntaxError(option, section, fmt.Sprintf("'%%' must be followed by '%%' or '(', found: %v", rest))
		}
	}
	return nil
}

func newExtendedInterpolation() *extendedInterpolation {
	return &extendedInterpolation{
		interpolation: &interpolation{},
		KeyCre:        regexp.MustCompile("\\$\\{([^}]+)\\}"),
	}
}

const (
	sectTmpl  = "^\\[(?P<header>[^]]+)\\]$"
	optTmpl   = "(?P<option>.*?)\\s*(?P<vi>%v)\\s*(?P<value>.*)$"
	optNvTmpl = "(?P<option>.*?)\\s*(?:(?P<vi>%v)\\s*(?P<value>.*))?$"
)

type ConfigParser interface {
	//Defaults() map[string][]string
	Sections() []string
	//add_section(section string) error
	//has_section(section string) bool
	Options(section string) ([]string, error)
	//read(filenames []string) []string
	ReadFile(interface {
		io.Reader
		Name() string
	}, string) error
	read_string(string, string) error
	//read_dict(map[string]map[string]string, string) error
	Gett(section, option string) (string, error)
	Get(section, option string, raw bool, vars map[string]string, fallback string) (string, error)
	GetSectionMap() map[string]map[string]string
	//_get()
	//_get_conv()
	//getint()
	//getfloat()
	//getboolean()
	//popitem() (string, string, error)
	optionxform(string) string
	HasOption(section, option string) bool
	OptItems(section string, raw bool, vars map[string]string) ([][]string, error)
	//set(section, option, value string) error
	//write(fp io.Writer, space_around_delimiters bool)
	//_write_section()
	//remove_option(section, option string) (bool, error)
	//remove_section(section string) bool
	//_read(io.Reader, string) error
	//_join_multiline_values()
	//_read_defaults(defaults map[string][]string)
	//_handle_error(interface {
	//	error
	//	append(int, string)
	//}, string, int, string) interface {
	//	error
	//	append(int, string)
	//}
	//_unify_values(section string, vars map[string][]string) (map[string][]string, error)
	//_convert_to_boolean(value string) (bool, error)
	//_validate_value_types(string, string, string)
}

type rawConfigParser struct {
	value map[string]string

	defaultInterpolation                    Interpolation
	SECTCRE, OPTCRE, OPTCRE_NV, NONSPACECRE *regexp.Regexp
	_sections                               map[string]map[string]string
	_defaults                               map[string]string
	BOOLEAN_STATES                          map[string]bool

	_delimiters                                 map[string]bool
	_optcre                                     *regexp.Regexp
	_strict                                     bool
	_allow_no_value                             bool
	_empty_lines_in_values                      bool
	default_section                             string
	_interpolation                              Interpolation
	_comment_prefixes, _inline_comment_prefixes map[string]bool
}

func (r *rawConfigParser) Defaults() map[string]string {
	return r._defaults
}

func (r *rawConfigParser) Sections() []string {
	s := []string{}
	for k := range r._sections {
		s = append(s, k)
	}
	return s
}

func (r *rawConfigParser) add_section(section string) error {
	if section == r.default_section {
		return fmt.Errorf("Invalid section name: %s", section)
	}
	if _, ok := r._sections[section]; ok {
		return newDuplicateSectionError(section, nil, 0)
	}
	r._sections[section] = map[string]string{}
	return nil
}

func (r *rawConfigParser) has_section(section string) bool {
	_, ok := r._sections[section]
	return ok
}

func (r *rawConfigParser) OptItems(section string, raw bool, vars map[string]string) ([][]string, error) { // false, nil
	d := map[string]string{}
	for k, v := range r._defaults {
		d[k] = v
	}
	if options, ok := r._sections[section]; !ok {
		return nil, newNoSectionError(section)
	} else {
		for k, v := range options {
			d[k] = v
		}
	}
	origKeys := []string{}
	for k := range d {
		origKeys = append(origKeys, k)
	}
	sort.Strings(origKeys)
	if len(vars) > 0 {
		for k, v := range vars {
			d[r.optionxform(k)] = v
		}
	}
	valueGetter := func(option string) (string, error) {
		return r._interpolation.beforeGet(r, section, option, d[option], d)
	}
	if raw {
		valueGetter = func(option string) (string, error) {
			if v, ok := d[option]; ok {
				return v, nil
			} else {
				return "", fmt.Errorf("no key")
			}
		}
	}

	ret := [][]string{}
	for _, option := range origKeys {
		t := []string{option}
		if s, err := valueGetter(option); err != nil {
			return nil, err
		} else {
			t = append(t, s)
		}
		ret = append(ret, t)
	}
	return ret, nil
}

func (r *rawConfigParser) Options(section string) ([]string, error) {
	if options, ok := r._sections[section]; !ok {
		return nil, newNoSectionError(section)
	} else {
		opt := []string{}
		for x := range options {
			opt = append(opt, x)
		}
		for x := range r._defaults {
			if _, ok := options[x]; !ok {
				opt = append(opt, x)
			}
		}
		return opt, nil
	}
}

func (r *rawConfigParser) read(filenames []string) []string {
	readOK := []string{}
	for _, filename := range filenames {
		fp, err := os.Open(filename)
		if err != nil {
			continue
		}
		if err := r._read(fp, filename); err != nil {
			continue
		}
		filename, err = filepath.Abs(filename)
		if err != nil {
			continue
		}

		readOK = append(readOK, filename)
	}
	return readOK
}

func (r *rawConfigParser) ReadFile(f interface {
	io.Reader
	Name() string
}, source string) error { // ""
	if source == "" {
		if f.Name() != "" {
			source = f.Name()
		} else {
			source = "<???>"
		}
	}
	if err := r._read(f, source); err != nil {
		return err
	}
	return nil
}

type stringio struct {
	*bytes.Buffer
	name string
}

func (s *stringio) Name() string {
	return s.name
}

func (r *rawConfigParser) read_string(string, source string) error { // "<string>"
	sFile := &stringio{
		Buffer: bytes.NewBuffer([]byte(string)),
	}
	sFile.name = fmt.Sprintf("StringIO <%v>", sFile)
	if err := r.ReadFile(sFile, source); err != nil {
		return err
	}
	return nil
}

func (r *rawConfigParser) read_dict(dictionary map[string]map[string]string, source string) error { // "<dict>"
	elementsAdd := map[string]map[string]bool{}
	for section, keys := range dictionary {
		if err := r.add_section(section); err != nil {
			switch err.(type) {
			case DuplicateSectionError: //TODO, ValueError:
				if _, ok := elementsAdd[section]; r._strict && ok {
					return err
				}
			default:
				return err
			}
		}
		if _, ok := elementsAdd[section]; !ok {
			elementsAdd[section] = map[string]bool{}
		}
		for key, value := range keys {
			key = r.optionxform(key)
			if value != "" {
			}
			if r._strict && elementsAdd[section][key] {
				return newDuplicateOptionError(section, key, source, 0)
			}
			elementsAdd[section][key] = true
			if err := r.set(section, key, value); err != nil {
				return err
			}
		}
	}
	return nil
}

const UNSETS = "dfayiadgvaufdiljal"

func (r *rawConfigParser) Gett(section, option string) (string, error) {
	return r.Get(section, option, false, nil, UNSETS)
}

func (r *rawConfigParser) Get(section, option string, raw bool, vars map[string]string, fallback string) (string, error) { // false, none, UNSETS
	d, err := r._unify_values(section, vars)
	switch err.(type) {
	case NoSectionError:
		if fallback == UNSETS {
			return "", err
		} else {
			return fallback, nil
		}
	}
	option = r.optionxform(option)
	value, ok := d[option]
	if !ok {
		if fallback == UNSETS {
			return "", newNoOptionError(option, section)
		} else {
			return fallback, nil
		}
	}
	if raw || !ok {
		return value, nil
	} else {
		return "", nil //TODO
		//return r._interpolation.beforeGet(r, section, option, value, d)
	}
}

func (r *rawConfigParser) GetSectionMap() map[string]map[string]string {
	return r._sections
}

func (r *rawConfigParser) _get() {}

func (r *rawConfigParser) _get_conv() {}

func (r *rawConfigParser) getint() {}

func (r *rawConfigParser) getfloat() {}

func (r *rawConfigParser) getboolean() {}

func (r *rawConfigParser) popitem() (string, string, error) {
	for _, k := range r.Sections() {
		v := r.value[k]
		delete(r.value, k)
		return k, v, nil
	}
	return "", "", errors.New("KeyError")
}

func (r *rawConfigParser) optionxform(optionstr string) string {
	return strings.ToLower(optionstr)
}

func (r *rawConfigParser) HasOption(section, option string) bool {
	if section == "" || section == r.default_section {
		option = r.optionxform(option)
		_, ok := r._defaults[option]
		return ok
	} else if _, ok := r._sections[section]; !ok {
		return false
	} else {
		option = r.optionxform(option)
		if _, ok1 := r._sections[section][option]; ok1 {
			return true
		} else if _, ok2 := r._defaults[option]; ok2 {
			return true
		}
		return false
	}
}

func (r *rawConfigParser) set(section, option, value string) error { // ""
	if value != "" {
		var err error = nil
		value, err = r._interpolation.beforeSet(r, section, option, value)
		if err != nil {
			return err
		}
	}
	var sectdict map[string]string = nil
	if section == "" || section == r.default_section {
		sectdict = r._defaults
	} else {
		ok := false
		sectdict, ok = r._sections[section]
		if !ok {
			return newNoSectionError(section)
		}
	}
	sectdict[r.optionxform(option)] = value
	return nil
}

//func (r *rawConfigParser) write(fp io.Writer, space_around_delimiters bool) { // true
//	d := ""
//	if space_around_delimiters {
//		d = fmt.Sprintf(" %v", r._delimiters[0])
//	} else {
//		d = r._delimiters[0]
//	}
//	if len(r._defaults) > 0 {
//		r._write_section(fp, r.default_section, r._defaults, d)
//	}
//	for _, section := range r._sections {
//		r._write_section(fp, newMissingSectionHeaderError(), r._sections[section], d)
//	}
//}

func (r *rawConfigParser) _write_section(fp io.Writer, section_name string, section_items map[string]string, delimiter string) {
	fp.Write([]byte(fmt.Sprintf("[%v]\n", section_name)))

	for key, value := range section_items {
		value, _ = r._interpolation.beforeWrite(r, section_name, key, value)
		if value != "" || !r._allow_no_value {
			value = delimiter + strings.Replace(value, "\n", "\n\t", -1)
		} else {
			value = ""
		}
		fp.Write([]byte(fmt.Sprintf("%v%v\n", key, value)))
	}
	fp.Write([]byte("\n"))
}

func (r *rawConfigParser) remove_option(section, option string) (bool, error) {
	var sectdict map[string]string = nil
	if section == "" || section == r.default_section {
		sectdict = r._defaults
	} else {
		var ok bool
		sectdict, ok = r._sections[section]
		if !ok {
			return false, newNoSectionError(section)
		}
	}
	option = r.optionxform(option)
	_, existed := sectdict[option]
	if existed {
		delete(sectdict, option)
	}
	return existed, nil
}

func (r *rawConfigParser) remove_section(section string) bool {
	_, existed := r._sections[section]
	if existed {
		delete(r._sections, section)
	}
	return existed
}

func (r *rawConfigParser) _read(fp io.Reader, fpname string) error {
	elementsAdded := map[string]map[string]bool{}
	var curSect map[string]string = nil
	var sectName, optname string
	var indentLevel int
	var e interface {
		error
		append(int, string)
	} = nil
	fl, err := ioutil.ReadAll(fp)
	if err != nil {
		return err
	}
	for lineno, line := range strings.Split(string(fl), "\n") {
		lineno++
		commentStart := math.MaxInt32
		inlinePrefixes := map[string]int{}
		for p := range r._inline_comment_prefixes {
			inlinePrefixes[p] = -1
		}
		for commentStart == math.MaxInt32 && len(inlinePrefixes) != 0 {
			nextPrefixes := map[string]int{}
			for prefix, index := range inlinePrefixes {
				index = strings.Index(line, prefix)
				if index == -1 {
					continue
				}
				nextPrefixes[prefix] = index
				if index == 0 || (index > 0 && strings.TrimSpace(string(line[index-1])) == "") {
					if commentStart > index {
						commentStart = index
					}
				}
			}
			inlinePrefixes = nextPrefixes
		}
		for prefix := range r._comment_prefixes {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				commentStart = 0
				break
			}
		}
		if commentStart == math.MaxInt32 {
			commentStart = len(line)
		}
		value := strings.TrimSpace(line[:commentStart])
		if value == "" {
			if r._empty_lines_in_values {
				if commentStart == 0 && curSect != nil && optname != "" && curSect[optname] != "" {
					curSect[optname] = ""
				}
			} else {
				indentLevel = math.MaxInt32
			}
			continue
		}
		curIndentLevel := 0
		if r.NONSPACECRE.MatchString(line) {
			curIndentLevel = r.NONSPACECRE.FindStringSubmatchIndex(line)[0]
		}
		if curSect != nil && optname != "" && curIndentLevel > indentLevel {
			curSect[optname] += value
		} else {
			indentLevel = curIndentLevel
			if r.SECTCRE.MatchString(value) {
				mo := r.SECTCRE.FindStringSubmatch(value)
				sectName = ""
				for i, name := range r.SECTCRE.SubexpNames() {
					if name == "header" {
						sectName = mo[i]
					}
				}
				if _, ok := r._sections[sectName]; ok {
					if _, ok := elementsAdded[sectName]; r._strict && ok {
						return newDuplicateSectionError(sectName, fpname, lineno)
					}
					curSect = r._sections[sectName]
					elementsAdded[sectName] = map[string]bool{}
				} else if sectName == r.default_section {
					curSect = r._defaults
				} else {
					curSect = map[string]string{}
					r._sections[sectName] = curSect
					elementsAdded[sectName] = map[string]bool{}
				}
				optname = ""
			} else if curSect == nil {
				return newMissingSectionHeaderError(fpname, lineno, line)
			} else {
				mo := r._optcre.FindStringSubmatch(value)
				if r._optcre.MatchString(value) {
					var optval string
					for i, name := range r._optcre.SubexpNames() {
						switch name {
						case "option":
							optname = mo[i]
						case "value":
							optval = mo[i]
						}
					}
					if optname == "" {
						e = r._handle_error(e, fpname, lineno, line)
					}
					optname = r.optionxform(strings.TrimRightFunc(optname, unicode.IsSpace))
					if r._strict && elementsAdded[sectName][optname] {
						return newDuplicateOptionError(sectName, optname, fpname, lineno)
					}
					if elementsAdded[sectName] == nil {
						elementsAdded[sectName] = map[string]bool{}
					}
					elementsAdded[sectName][optname] = true
					if optval != "" {
						optval = strings.TrimSpace(optval)
						curSect[optname] = optval
					} else {
						curSect[optname] = ""
					}
				} else {
					e = r._handle_error(e, fpname, lineno, line)
				}
			}
		}
	}
	r._join_multiline_values()
	if e != nil {
		return e
	}
	return nil
}

func (r *rawConfigParser) _join_multiline_values() {
	//
	//defaults = self.default_section, self._defaults
	//all_sections = itertools.chain((defaults,),
	//	self._sections.items())
	//for section, Options := range all_sections{
	//	for name, val := range Options{
	//		//if isinstance(val, list):
	//		//val = '\n'.join(val).rstrip()
	//		Options[name] = r._interpolation.beforeRead(r,
	//			section,
	//			name, val)
	//	}
	//}
}

func (r *rawConfigParser) _read_defaults(defaults map[string]string) {
	for key, value := range defaults {
		r._defaults[r.optionxform(key)] = value
	}
}

func (r *rawConfigParser) _handle_error(exc interface {
	error
	append(int, string)
}, fpname string, lineno int, line string) interface {
	error
	append(int, string)
} {
	if exc == nil {
		exc = newParsingError(fpname)
	}
	exc.append(lineno, line)
	return exc
}

func (r *rawConfigParser) _unify_values(section string, vars map[string]string) (map[string]string, error) {
	sectiondict, ok := r._sections[section]
	if !ok {
		if section != r.default_section {
			return nil, newNoSectionError(section)
		}
	}
	vardict := map[string]string{}
	if len(vars) > 0 {
		for key, value := range vars {
			if value != "" {
			}
			vardict[r.optionxform(key)] = value
		}
	}

	p := map[string]string{}
	for k, v := range vardict {
		p[k] = v
	}
	for k, v := range sectiondict {
		p[k] = v
	}
	for k, v := range r._defaults {
		p[k] = v
	}

	return p, nil
}

func (r *rawConfigParser) _convert_to_boolean(value string) (bool, error) {
	if v, ok := r.BOOLEAN_STATES[strings.ToLower(value)]; !ok {
		return false, fmt.Errorf("Not a boolean: %s", value)
	} else {
		return v, nil
	}
}

func (r *rawConfigParser) _validate_value_types(section, option, value string) { // "","",""

}

func NewRawConfigParser(argument Argument) *rawConfigParser { // DefaultArgument
	defaults := argument.Defaults
	allow_no_value := argument.Allow_no_value
	delimiters := argument.Delimiters
	comment_prefixes := argument.Comment_prefixes
	inline_comment_prefixes := argument.Inline_comment_prefixes
	strict := argument.Strict
	empty_lines_in_values := argument.Empty_lines_in_values
	default_section := argument.Default_section
	interpolation := argument.Interpolation
	r := &rawConfigParser{
		defaultInterpolation: newInterpolation(),
		SECTCRE:              regexp.MustCompile(sectTmpl),
		OPTCRE:               regexp.MustCompile(fmt.Sprintf(optTmpl, "=|:")),
		OPTCRE_NV:            regexp.MustCompile(fmt.Sprintf(optNvTmpl, "=|:")),
		NONSPACECRE:          regexp.MustCompile("\\S"),
		BOOLEAN_STATES: map[string]bool{"1": true, "yes": true, "true": true, "on": true,
			"0": false, "no": false, "false": false, "off": false},
	}
	r.value = map[string]string{}
	r._sections = map[string]map[string]string{}
	r._defaults = map[string]string{}
	r._delimiters = map[string]bool{}
	for _, d := range delimiters {
		r._delimiters[d] = true
	}
	if len(r._delimiters) == 2 && r._delimiters["="] && r._delimiters[":"] {
		if allow_no_value {
			r._optcre = r.OPTCRE_NV
		} else {
			r._optcre = r.OPTCRE
		}
	} else {
		e := []string{}
		for _, d := range delimiters {
			e = append(e, regexp.QuoteMeta(d))
		}
		d := strings.Join(e, "|")
		if allow_no_value {
			r._optcre = regexp.MustCompile(fmt.Sprintf(optNvTmpl, d))
		} else {
			r._optcre = regexp.MustCompile(fmt.Sprintf(optTmpl, d))
		}
	}
	r._comment_prefixes = map[string]bool{}
	for _, c := range comment_prefixes {
		r._comment_prefixes[c] = true
	}
	r._inline_comment_prefixes = map[string]bool{}
	for _, c := range inline_comment_prefixes {
		r._inline_comment_prefixes[c] = true
	}
	r._strict = strict
	r._allow_no_value = allow_no_value
	r._empty_lines_in_values = empty_lines_in_values
	r.default_section = default_section
	r._interpolation = interpolation
	if r._interpolation == _UNSET {
		r._interpolation = r.defaultInterpolation
	}
	if r._interpolation == nil {
		r._interpolation = newInterpolation()
	}
	if len(defaults) > 0 {
		r._read_defaults(defaults)
	}

	return r
}

type configParser struct {
	*rawConfigParser
}

func (c *configParser) set(section, option, value string) error { // ""
	c._validate_value_types("", option, value)
	if err := c.rawConfigParser.set(section, option, value); err != nil {
		return err
	}
	return nil
}

func (c *configParser) add_section(section string) error {
	c._validate_value_types(section, "", "")
	if err := c.rawConfigParser.add_section(section); err != nil {
		return err
	}
	return nil
}

func (c *configParser) _read_defaults(defaults map[string]string) {
	hold_interpolation := c._interpolation
	c._interpolation = newInterpolation()
	c.read_dict(map[string]map[string]string{c.default_section: defaults}, "<dict>")
	c._interpolation = hold_interpolation
}

func NewConfigParser(argument Argument) *configParser {
	r := &configParser{
		rawConfigParser: NewRawConfigParser(argument),
	}
	r.rawConfigParser.defaultInterpolation = newBasicInterpolation()
	return r
}

type Argument struct {
	Defaults                      map[string]string
	Allow_no_value                bool
	Delimiters, Comment_prefixes  []string
	Inline_comment_prefixes       []string
	Strict, Empty_lines_in_values bool
	Default_section               string
	Interpolation                 Interpolation
}

var DefaultArgument = Argument{
	nil,
	false,
	[]string{"=", ":"},
	[]string{"#", ";"},
	nil,
	true,
	true,
	DefaultSect,
	_UNSET,
}
