package bench

import (
	"testing"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

func setup(tb testing.TB) []format {
	tb.Helper()
	fs, closeAll, err := formats()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(closeAll)
	return fs
}

func tamper(token string) string {
	b := []byte(token)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestFormats(t *testing.T) {
	for _, f := range setup(t) {
		t.Run(f.name, func(t *testing.T) {
			token, err := f.issue()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.check(token); err != nil {
				t.Fatalf("own token refused: %v", err)
			}
			if err := f.check(tamper(token)); err == nil {
				t.Fatal("tampered token accepted")
			}
			t.Logf("%d bytes", len(token))
		})
	}
}

func BenchmarkIssue(b *testing.B) {
	for _, f := range setup(b) {
		b.Run(f.name, func(b *testing.B) {
			b.ReportAllocs()
			var token string
			var err error
			for b.Loop() {
				if token, err = f.issue(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(token)), "token-bytes")
		})
	}
}

func BenchmarkCheck(b *testing.B) {
	for _, f := range setup(b) {
		b.Run(f.name, func(b *testing.B) {
			token, err := f.issue()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := f.check(token); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCgoCall(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		cb2.HasPublic()
	}
}
