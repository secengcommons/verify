package fuzztestmain

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(main *testing.M) {
	code := main.Run()
	fmt.Println("fixture teardown complete")
	os.Exit(code)
}

func FuzzIdentity(fuzz *testing.F) {
	fuzz.Add([]byte("seed"))
	fuzz.Fuzz(func(_ *testing.T, value []byte) {
		_ = append([]byte(nil), value...)
	})
}
