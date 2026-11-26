package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const testSeedPhraseSecret = "TOPSECRET-reseed-signing-seed"

func TestUsageOutputOmitsSeedPhrase(t *testing.T) {
	for _, args := range [][]string{
		{"-listen-addr", ":8080"},
		{"-h"},
		{"-target", "not-a-number"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv(seedPhraseEnv, testSeedPhraseSecret)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("run exit = %d, want flag error exit", code)
			}
			if !strings.Contains(stderr.String(), "-seed-phrase") {
				t.Fatalf("usage output missing -seed-phrase flag: %q", stderr.String())
			}
			for name, out := range map[string]string{"stdout": stdout.String(), "stderr": stderr.String()} {
				if strings.Contains(out, testSeedPhraseSecret) {
					t.Fatalf("%s echoes the seed phrase", name)
				}
			}
		})
	}
}

func TestResolveSeedPhraseReadsAndClearsEnv(t *testing.T) {
	t.Setenv(seedPhraseEnv, testSeedPhraseSecret)
	if got := resolveSeedPhrase(""); got != testSeedPhraseSecret {
		t.Fatalf("resolveSeedPhrase(\"\") = %q, want env value", got)
	}
	if _, ok := os.LookupEnv(seedPhraseEnv); ok {
		t.Fatalf("%s still set after it was read", seedPhraseEnv)
	}
}

func TestResolveSeedPhraseFlagOverridesEnv(t *testing.T) {
	t.Setenv(seedPhraseEnv, testSeedPhraseSecret)
	if got := resolveSeedPhrase("flag phrase"); got != "flag phrase" {
		t.Fatalf("resolveSeedPhrase(flag) = %q, want flag value", got)
	}
	if _, ok := os.LookupEnv(seedPhraseEnv); ok {
		t.Fatalf("%s still set after the flag took precedence", seedPhraseEnv)
	}
}
