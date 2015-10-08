package fsync

import (
	"testing"
)

func TestLock(t *testing.T) {
	m, err := Get("lockfile")
	if err != nil {
		t.Error(err)
		return
	}
	m.RLock()
	m.RUnlock()
	m.Lock()
	m.Unlock()
	r := m.RLocker()
	r.Lock()
	r.Unlock()

	m, err = GetTransient("lockfile.tmp")
	if err != nil {
		t.Error(err)
		return
	}
	m.RLock()
	m.RUnlock()
	m.Lock()
	m.Unlock()
	r = m.RLocker()
	r.Lock()
	r.Unlock()
}
