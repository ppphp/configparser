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
	var L []string
	if err := b.interpolateSome(parser, option, L, value, section, defaults, 1); err != nil {
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

func (b *basicInterpolation) interpolateSome(parser ConfigParser, option string, accum []string, rest string, section string, mapp map[string]string, depth int) error {
	rawVal, _ := parser.Get(section, option, true, nil, rest)
	if depth > MaxInterpolationDepth {
		return newInterpolationDepthError(option, section, rawVal)
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
				return newInterpolationMissingOptionError(option, section, rawVal, varr)
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
	var L []string
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

func (b *extendedInterpolation) interpolateSome(parser ConfigParser, option string, accum []string, rest string, section string, mapp map[string][]string, depth int) error {
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
	readString(string, string) error
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
	sections                                map[string]map[string]string
	defaults                                map[string]string
	BooleanStates                           map[string]bool

	_delimiters                            map[string]bool
	optcre                                 *regexp.Regexp
	_strict                                bool
	allowNoValue                           bool
	emptyLinesInValues                     bool
	defaultSection                         string
	interpolation                          Interpolation
	commentPrefixes, inlineCommentPrefixes map[string]bool
}

func (r *rawConfigParser) Defaults() map[string]string {
	return r.defaults
}

func (r *rawConfigParser) Sections() []string {
	s := []string{}
	for k := range r.sections {
		s = append(s, k)
	}
	return s
}

func (r *rawConfigParser) add_section(section string) error {
	if section == r.defaultSection {
		return fmt.Errorf("Invalid section name: %s", section)
	}
	if _, ok := r.sections[section]; ok {
		return newDuplicateSectionError(section, nil, 0)
	}
	r.sections[section] = map[string]string{}
	return nil
}

func (r *rawConfigParser) has_section(section string) bool {
	_, ok := r.sections[section]
	return ok
}

func (r *rawConfigParser) OptItems(section string, raw bool, vars map[string]string) ([][]string, error) { // false, nil
	d := map[string]string{}
	for k, v := range r.defaults {
		d[k] = v
	}
	if options, ok := r.sections[section]; !ok {
		return nil, newNoSectionError(section)
	} else {
		for k, v := range options {
			d[k] = v
		}
	}
	var origKeys []string
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
		return r.interpolation.beforeGet(r, section, option, d[option], d)
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

	var ret [][]string
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
	if options, ok := r.sections[section]; !ok {
		return nil, newNoSectionError(section)
	} else {
		var opt []string
		for x := range options {
			opt = append(opt, x)
		}
		for x := range r.defaults {
			if _, ok := options[x]; !ok {
				opt = append(opt, x)
			}
		}
		return opt, nil
	}
}

func (r *rawConfigParser) read(filenames []string) []string {
	var readOK []string
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

func (r *rawConfigParser) readString(string, source string) error { // "<string>"
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
		//return r.interpolation.beforeGet(r, section, option, value, d)
	}
}

func (r *rawConfigParser) GetSectionMap() map[string]map[string]string {
	return r.sections
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
	if section == "" || section == r.defaultSection {
		option = r.optionxform(option)
		_, ok := r.defaults[option]
		return ok
	} else if _, ok := r.sections[section]; !ok {
		return false
	} else {
		option = r.optionxform(option)
		if _, ok1 := r.sections[section][option]; ok1 {
			return true
		} else if _, ok2 := r.defaults[option]; ok2 {
			return true
		}
		return false
	}
}

func (r *rawConfigParser) set(section, option, value string) error { // ""
	if value != "" {
		var err error = nil
		value, err = r.interpolation.beforeSet(r, section, option, value)
		if err != nil {
			return err
		}
	}
	var sectdict map[string]string = nil
	if section == "" || section == r.defaultSection {
		sectdict = r.defaults
	} else {
		ok := false
		sectdict, ok = r.sections[section]
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
//	if len(r.defaults) > 0 {
//		r._write_section(fp, r.default_section, r.defaults, d)
//	}
//	for _, section := range r.sections {
//		r._write_section(fp, newMissingSectionHeaderError(), r.sections[section], d)
//	}
//}

func (r *rawConfigParser) _write_section(fp io.Writer, section_name string, section_items map[string]string, delimiter string) error {
	if _, err := fp.Write([]byte(fmt.Sprintf("[%v]\n", section_name))); err != nil {
		return err
	}

	for key, value := range section_items {
		value, _ = r.interpolation.beforeWrite(r, section_name, key, value)
		if value != "" || !r.allowNoValue {
			value = delimiter + strings.Replace(value, "\n", "\n\t", -1)
		} else {
			value = ""
		}
		if _, err := fp.Write([]byte(fmt.Sprintf("%v%v\n", key, value))); err != nil {
			return err
		}
	}
	if _, err := fp.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

func (r *rawConfigParser) remove_option(section, option string) (bool, error) {
	var sectDict map[string]string = nil
	if section == "" || section == r.defaultSection {
		sectDict = r.defaults
	} else {
		var ok bool
		sectDict, ok = r.sections[section]
		if !ok {
			return false, newNoSectionError(section)
		}
	}
	option = r.optionxform(option)
	_, existed := sectDict[option]
	if existed {
		delete(sectDict, option)
	}
	return existed, nil
}

func (r *rawConfigParser) remove_section(section string) bool {
	_, existed := r.sections[section]
	if existed {
		delete(r.sections, section)
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
		for p := range r.inlineCommentPrefixes {
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
		for prefix := range r.commentPrefixes {
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
			if r.emptyLinesInValues {
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
				if _, ok := r.sections[sectName]; ok {
					if _, ok := elementsAdded[sectName]; r._strict && ok {
						return newDuplicateSectionError(sectName, fpname, lineno)
					}
					curSect = r.sections[sectName]
					elementsAdded[sectName] = map[string]bool{}
				} else if sectName == r.defaultSection {
					curSect = r.defaults
				} else {
					curSect = map[string]string{}
					r.sections[sectName] = curSect
					elementsAdded[sectName] = map[string]bool{}
				}
				optname = ""
			} else if curSect == nil {
				return newMissingSectionHeaderError(fpname, lineno, line)
			} else {
				mo := r.optcre.FindStringSubmatch(value)
				if r.optcre.MatchString(value) {
					var optVal string
					for i, name := range r.optcre.SubexpNames() {
						switch name {
						case "option":
							optname = mo[i]
						case "value":
							optVal = mo[i]
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
					if optVal != "" {
						optVal = strings.TrimSpace(optVal)
						curSect[optname] = optVal
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
	//defaults = self.default_section, self.defaults
	//all_sections = itertools.chain((defaults,),
	//	self.sections.items())
	//for section, Options := range all_sections{
	//	for name, val := range Options{
	//		//if isinstance(val, list):
	//		//val = '\n'.join(val).rstrip()
	//		Options[name] = r.interpolation.beforeRead(r,
	//			section,
	//			name, val)
	//	}
	//}
}

func (r *rawConfigParser) _read_defaults(defaults map[string]string) {
	for key, value := range defaults {
		r.defaults[r.optionxform(key)] = value
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
	sectionDict, ok := r.sections[section]
	if !ok {
		if section != r.defaultSection {
			return nil, newNoSectionError(section)
		}
	}
	varDict := map[string]string{}
	if len(vars) > 0 {
		for key, value := range vars {
			if value != "" {
			}
			varDict[r.optionxform(key)] = value
		}
	}

	p := map[string]string{}
	for k, v := range varDict {
		p[k] = v
	}
	for k, v := range sectionDict {
		p[k] = v
	}
	for k, v := range r.defaults {
		p[k] = v
	}

	return p, nil
}

func (r *rawConfigParser) _convert_to_boolean(value string) (bool, error) {
	if v, ok := r.BooleanStates[strings.ToLower(value)]; !ok {
		return false, fmt.Errorf("not a boolean: %s", value)
	} else {
		return v, nil
	}
}

func (r *rawConfigParser) _validate_value_types(section, option, value string) { // "","",""

}

func NewRawConfigParser(argument Argument) *rawConfigParser { // DefaultArgument
	defaults := argument.Defaults
	allowNoValue := argument.AllowNoValue
	delimiters := argument.Delimiters
	commentPrefixes := argument.CommentPrefixes
	inlineCommentPrefixes := argument.InlineCommentPrefixes
	strict := argument.Strict
	emptyLinesInValues := argument.EmptyLinesInValues
	defaultSection := argument.DefaultSection
	interpolation := argument.Interpolation
	r := &rawConfigParser{
		defaultInterpolation: newInterpolation(),
		SECTCRE:              regexp.MustCompile(sectTmpl),
		OPTCRE:               regexp.MustCompile(fmt.Sprintf(optTmpl, "=|:")),
		OPTCRE_NV:            regexp.MustCompile(fmt.Sprintf(optNvTmpl, "=|:")),
		NONSPACECRE:          regexp.MustCompile("\\S"),
		BooleanStates: map[string]bool{"1": true, "yes": true, "true": true, "on": true,
			"0": false, "no": false, "false": false, "off": false},
	}
	r.value = map[string]string{}
	r.sections = map[string]map[string]string{}
	r.defaults = map[string]string{}
	r._delimiters = map[string]bool{}
	for _, d := range delimiters {
		r._delimiters[d] = true
	}
	if len(r._delimiters) == 2 && r._delimiters["="] && r._delimiters[":"] {
		if allowNoValue {
			r.optcre = r.OPTCRE_NV
		} else {
			r.optcre = r.OPTCRE
		}
	} else {
		var e []string
		for _, d := range delimiters {
			e = append(e, regexp.QuoteMeta(d))
		}
		d := strings.Join(e, "|")
		if allowNoValue {
			r.optcre = regexp.MustCompile(fmt.Sprintf(optNvTmpl, d))
		} else {
			r.optcre = regexp.MustCompile(fmt.Sprintf(optTmpl, d))
		}
	}
	r.commentPrefixes = map[string]bool{}
	for _, c := range commentPrefixes {
		r.commentPrefixes[c] = true
	}
	r.inlineCommentPrefixes = map[string]bool{}
	for _, c := range inlineCommentPrefixes {
		r.inlineCommentPrefixes[c] = true
	}
	r._strict = strict
	r.allowNoValue = allowNoValue
	r.emptyLinesInValues = emptyLinesInValues
	r.defaultSection = defaultSection
	r.interpolation = interpolation
	if r.interpolation == _UNSET {
		r.interpolation = r.defaultInterpolation
	}
	if r.interpolation == nil {
		r.interpolation = newInterpolation()
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
	holdInterpolation := c.interpolation
	c.interpolation = newInterpolation()
	c.read_dict(map[string]map[string]string{c.defaultSection: defaults}, "<dict>")
	c.interpolation = holdInterpolation
}

func NewConfigParser(argument Argument) *configParser {
	r := &configParser{
		rawConfigParser: NewRawConfigParser(argument),
	}
	r.rawConfigParser.defaultInterpolation = newBasicInterpolation()
	return r
}

type Argument struct {
	Defaults                    map[string]string
	AllowNoValue                bool
	Delimiters, CommentPrefixes []string
	InlineCommentPrefixes       []string
	Strict, EmptyLinesInValues  bool
	DefaultSection              string
	Interpolation               Interpolation
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
