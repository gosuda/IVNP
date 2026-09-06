package configuration

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	filesystemstore "gosuda.org/ivnp/state/internal/filesystem_store"
)

func TestLoadOperatingRejectsPublicBearerACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ivnp.conf")
	secret := []byte("[control]\nenabled = true\nlisten_host = 192.0.2.10\nlisten_port = 7650\nbearer_token = token-token-token-1\n")
	if err := filesystemstore.WriteAtomic(path, secret, 0o600, 4096); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperating(path); err != nil {
		t.Fatalf("private credentials: %v", err)
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
	if _, err := LoadOperating(path); err == nil {
		t.Fatal("LoadOperating accepted public bearer credentials")
	}
}
