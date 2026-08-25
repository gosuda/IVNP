package netdb

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"gosuda.org/ivnp/networking/internal/i2np"
)

// These corpora were sampled every 60 seconds during a 10-minute run of Java
// I2P's LeaseSet2, EncryptedLeaseSet, and DatabaseStoreMessage implementations
// at commit fda1ced99c3b1e8513b88c543bca3aeb668330a8.
const javaNetDBFixtureDirectory = "testdata/java-fda1ced/"

func readJavaNetDBCorpus(t testing.TB, name string) [][]byte {
	t.Helper()
	corpus, err := os.ReadFile(javaNetDBFixtureDirectory + name)
	if err != nil {
		t.Fatalf("read Java NetDB corpus %q: %v", name, err)
	}
	var records [][]byte
	for offset := 0; offset < len(corpus); {
		if len(corpus)-offset < 4 {
			t.Fatalf("Java NetDB corpus %q has truncated record length at byte %d", name, offset)
		}
		length := int(binary.BigEndian.Uint32(corpus[offset : offset+4]))
		offset += 4
		if length > len(corpus)-offset {
			t.Fatalf("Java NetDB corpus %q record %d declares %d bytes with %d remaining", name, len(records), length, len(corpus)-offset)
		}
		records = append(records, corpus[offset:offset+length])
		offset += length
	}
	if len(records) != 11 {
		t.Fatalf("Java NetDB corpus %q has %d records, want 11 samples spanning both run endpoints", name, len(records))
	}
	return records
}

func parseJavaDatabaseStoreRecord(t testing.TB, name string, index int, frame []byte) i2np.DatabaseStoreMessage {
	t.Helper()
	message, used, err := i2np.Parse(frame)
	if err != nil || used != len(frame) || message.Header.Type != i2np.DatabaseStore {
		t.Fatalf("record %d in %q: parse Java DatabaseStore = type %d, %d/%d bytes, %v", index, name, message.Header.Type, used, len(frame), err)
	}
	store, err := i2np.ParseDatabaseStore(message.Payload)
	if err != nil {
		t.Fatalf("record %d in %q: parse Java DatabaseStore payload: %v", index, name, err)
	}
	return store
}

func TestJavaDatabaseStoreCarriesLeaseSet2OverFourKiBCorpus(t *testing.T) {
	const name = "database-store-ls2-over-4k.corpus"
	for index, frame := range readJavaNetDBCorpus(t, name) {
		store := parseJavaDatabaseStoreRecord(t, name, index, frame)
		if store.Type != i2np.StoreLeaseSet2 || len(store.Data) <= 4*1024 {
			t.Fatalf("record %d: Java DatabaseStore = type %d, %d LeaseSet2 bytes", index, store.Type, len(store.Data))
		}
		leaseSet, err := ParseLeaseSet2(store.Data)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if valid, verifyErr := leaseSet.Verify(); verifyErr != nil || !valid {
			t.Fatalf("record %d: verify Java LeaseSet2 = %t, %v", index, valid, verifyErr)
		}
		if store.Key != leaseSet.Hash() {
			t.Fatalf("record %d: Java DatabaseStore key %x does not match LeaseSet2 hash %x", index, store.Key, leaseSet.Hash())
		}
	}
}

func TestJavaEncryptedLeaseSetMaximumReaderCorpus(t *testing.T) {
	const name = "database-store-els2-encrypted-4096.corpus"
	for index, frame := range readJavaNetDBCorpus(t, name) {
		store := parseJavaDatabaseStoreRecord(t, name, index, frame)
		if store.Type != i2np.StoreEncryptedLeaseSet || len(store.Data) <= 4*1024 {
			t.Fatalf("record %d: Java DatabaseStore = type %d, %d EncryptedLeaseSet bytes", index, store.Type, len(store.Data))
		}
		leaseSet, err := ParseEncryptedLeaseSet(store.Data)
		if err != nil {
			t.Fatalf("record %d: %v", index, err)
		}
		if len(leaseSet.EncryptedData) != MaxEncryptedLeaseSetDataBytes {
			t.Fatalf("record %d: Java EncryptedLeaseSet data = %d bytes, want %d", index, len(leaseSet.EncryptedData), MaxEncryptedLeaseSetDataBytes)
		}
		if valid, verifyErr := leaseSet.Verify(); verifyErr != nil || !valid {
			t.Fatalf("record %d: verify Java EncryptedLeaseSet = %t, %v", index, valid, verifyErr)
		}
		if store.Key != leaseSet.Hash() {
			t.Fatalf("record %d: Java DatabaseStore key %x does not match EncryptedLeaseSet hash %x", index, store.Key, leaseSet.Hash())
		}
	}
}

func TestJavaEncryptedLeaseSetWriterCanExceedReaderCapCorpus(t *testing.T) {
	const name = "database-store-els2-writer-over-4096.corpus"
	for index, frame := range readJavaNetDBCorpus(t, name) {
		store := parseJavaDatabaseStoreRecord(t, name, index, frame)
		if store.Type != i2np.StoreEncryptedLeaseSet || len(store.Data) <= 4*1024 {
			t.Fatalf("record %d: Java DatabaseStore = type %d, %d EncryptedLeaseSet bytes", index, store.Type, len(store.Data))
		}
		if _, err := ParseEncryptedLeaseSet(store.Data); !errors.Is(err, ErrMalformed) {
			t.Fatalf("record %d: parse Java writer output above encrypted-data reader cap = %v, want ErrMalformed", index, err)
		}
	}
}
