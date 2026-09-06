package securestore

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStateRejectsUnsafeParentAndFiles(t *testing.T) {
	for _, target := range []string{"parent", "state", "master-key"} {
		t.Run(target, func(t *testing.T) {
			store := testStore(t)
			bundle, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			defer bundle.ReleaseSensitive()
			path := store.StatePath
			switch target {
			case "parent":
				path = filepath.Dir(path)
			case "master-key":
				path = store.MasterKeyPath
			}
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				t.Fatal(err)
			}
			sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load()
			defer loaded.ReleaseSensitive()
			if !errors.Is(err, ErrUnsafePermissions) {
				t.Fatalf("Load(public %s ACL) = %v, want unsafe permissions", target, err)
			}
		})
	}
}
