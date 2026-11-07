package cb2

import (
	"errors"
	"sync"
	"testing"
)

func TestClosedKey(t *testing.T) {
	k, err := GenerateLocalKey()
	need(t, err)
	k.Close()
	k.Close()
	_, err = TokenSeal(k, claims, nil)
	if !errors.Is(err, ErrClosed) || !errors.Is(err, ErrArgument) {
		t.Fatalf("want ErrClosed wrapping ErrArgument, got %v", err)
	}
	if err.Error() != "cb2: key is closed" {
		t.Fatalf("message %q", err.Error())
	}
	if !errors.Is(k.SetKeyID("k1"), ErrClosed) {
		t.Fatal("SetKeyID on a closed key")
	}
	k.ClearKeyID()
	if _, ok := k.KeyID(); ok {
		t.Fatal("KeyID on a closed key")
	}
	var none *LocalKey
	none.Close()
	if _, err := LocalSeal(none, nil, nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil key: %v", err)
	}
	if _, err := Wrap(newLocal(t), none); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil wrapped key: %v", err)
	}
	if _, err := (&LocalKey{}).PaserkID(); !errors.Is(err, ErrClosed) {
		t.Fatalf("zero key: %v", err)
	}
}

func TestErrorsAreFresh(t *testing.T) {
	_, err := NormalizeTarget("nope")
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want *Error, got %v", err)
	}
	e.Code = CodeExpired
	if ErrArgument.Code != CodeArgument {
		t.Fatal("a returned error aliases its sentinel")
	}
}

func TestConcurrentUseCloseAndKeyID(t *testing.T) {
	k, err := GenerateLocalKey()
	need(t, err)
	wrapping := newLocal(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 50 {
				switch i % 4 {
				case 0:
					tok, err := TokenSeal(k, claims, nil)
					if err != nil {
						continue
					}
					_, err = TokenOpen(k, tok, baseRules(), nil)
					if err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, ErrInvalid) {
						t.Errorf("open: %v", err)
					}
				case 1:
					_ = k.SetKeyID("k1")
					k.ClearKeyID()
				case 2:
					_, _ = Wrap(wrapping, k)
					_, _ = Wrap(k, k)
				case 3:
					_, _ = k.KeyID()
					_, _ = k.PaserkID()
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range 20 {
			_, _ = k.PaserkID()
		}
		k.Close()
	}()
	close(start)
	wg.Wait()
	if _, err := k.PaserkID(); !errors.Is(err, ErrClosed) {
		t.Fatalf("after Close: %v", err)
	}
}
