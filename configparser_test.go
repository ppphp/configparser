package configparser

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func basicTest(t *testing.T, cf ConfigParser, argument Argument) {
	E := []string{
		"Commented Bar",
		"Foo Bar",
		"Internationalized Stuff",
		"Long Line",
		"Section\\with$weird%characters[\t",
		"Spaces",
		"Spacey Bar",
		"Spacey Bar From The Beginning",
		"Types",
	}
	allow_no_value := argument.Allow_no_value
	if allow_no_value {
		E = append(E, "NoValue")
	}
	sort.Strings(E)
	F := [][]string{{"baz", "qwe"}, {"foo", "bar3"}}
	L := cf.Sections()
	sort.Strings(L)
	if !reflect.DeepEqual(L, E) {
		t.Errorf("%v, %v", L, E)
	}
	K, err := cf.OptItems("Spacey Bar From The Beginning", false, nil)
	if err != nil {
		return
	}
	sort.Strings(L)
	if !reflect.DeepEqual(K, F) {
		t.Errorf("%v, %v", K, F)
	}
	L = []string{}
	for section := range cf.GetSectionMap() {
		L = append(L, section)
	}
	sort.Strings(L)
	if !reflect.DeepEqual(L, E) {
		t.Errorf("%v, %v", L, E)
	}
	// TODO items

	if s, err := cf.Gett("Foo Bar", "foo"); err != nil || s != "bar1" {
		t.Errorf("err %v, %v != %v", err, s, "bar1")
	}
	if s, err := cf.Gett("Spacey Bar", "foo"); err != nil || s != "bar2" {
		t.Errorf("err %v, %v != %v", err, s, "bar2")
	}
	if s, err := cf.Gett("Spacey Bar From The Beginning", "foo"); err != nil || s != "bar3" {
		t.Errorf("err %v, %v != %v", err, s, "bar3")
	}
	if s, err := cf.Gett("Spacey Bar From The Beginning", "baz"); err != nil || s != "qwe" {
		t.Errorf("err %v, %v != %v", err, s, "qwe")
	}
}

func testBasic(t *testing.T, argument Argument) {
	const config_string = "[Foo Bar]\n" +
		"foo%[1]sbar1\n" +
		"[Spacey Bar]\n" +
		"foo %[1]s bar2\n" +
		"[Spacey Bar From The Beginning]\n" +
		"  foo %[1]s bar3\n" +
		"  baz %[1]s qwe\n" +
		"[Commented Bar]\n" +
		"foo%[2]s bar4 %[4]s comment\n" +
		"baz%[1]sqwe %[3]sanother one\n" +
		"[Long Line]\n" +
		"foo%[2]s this line is much, much longer than my editor\n" +
		"   likes it.\n" +
		"[Section\\with$weird%%characters[\t]\n" +
		"[Internationalized Stuff]\n" +
		"foo[bg]%[2]s Bulgarian\n" +
		"foo%[1]sDefault\n" +
		"foo[en]%[1]sEnglish\n" +
		"foo[de]%[1]sDeutsch\n" +
		"[Spaces]\n" +
		"key with spaces %[2]s value\n" +
		"another with spaces %[1]s splat!\n" +
		"[Types]\n" +
		"int %[2]s 42\n" +
		"float %[1]s 0.44\n" +
		"boolean %[1]s NO\n" +
		"123 %[2]s strange but acceptable\n"

	cfgString := fmt.Sprintf(config_string, argument.Delimiters[0], argument.Delimiters[1], argument.Comment_prefixes[0], argument.Comment_prefixes[1])
	if argument.Allow_no_value {
		cfgString = cfgString + "[NoValue]\noption-without-value\n"
	}

	cf := NewRawConfigParser(argument)
	if err := cf.read_string(cfgString, "<string>"); err != nil {
		t.Errorf("%v", err)
	}

	basicTest(t, cf, argument)
}

var argument = Argument{
	Allow_no_value:          false,
	Delimiters:              []string{"=", ":"},
	Comment_prefixes:        []string{";", "#"},
	Inline_comment_prefixes: []string{";", "#"},
	Empty_lines_in_values:   true,
	Strict:                  false,
	Default_section:         DefaultSect,
	Interpolation:           _UNSET,
}

//func TestStrict(t *testing.T) {
//	arg := argument
//	arg.Strict = true
//
//	testBasic(t, arg)
//}

func TestNewRawConfigParser(t *testing.T) {

}
