package probe

import "testing"

func TestParseFunctions(t *testing.T) {
	got, err := ParseFunctions("/bin/app:main,/lib/libfoo.so:foo")
	if err != nil || len(got) != 2 || got[0].Binary != "/bin/app" || got[1].Symbol != "foo" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := ParseFunctions("missing-colon"); err == nil {
		t.Fatal("expected error")
	}
}
