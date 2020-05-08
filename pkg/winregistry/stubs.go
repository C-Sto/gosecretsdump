// +build !windows

package winregistry

import (
	"fmt"
)

type stubIF struct {
}

func (s stubIF) GetVal(string) (x uint32, y []byte, z error)        { return }
func (s stubIF) GetClass(path string) (r []byte)                    { return }
func (s stubIF) EnumKeys(path string) (subkeys []string, err error) { return }

func InitLive(s string) (WinRegIF, error) {
	return stubIF{}, fmt.Errorf("Can't interact with registry on non Windows host")
}
