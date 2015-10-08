package fsync

import (
	"fmt"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
)

// Mutex represents an RWMutex which synchronizes its state with a file lock,
// allowing two process which use the same lock file to share reading and
// writing locks.
type Mutex struct {
	rw                    sync.RWMutex
	m                     sync.Mutex
	lockfile              string
	closeToUnlock, locked bool
	lockfd                int
	readers, writers      int
	unlocked              time.Time
}

// rmutex is a wrapper for a Mutex which provides Lock and Unlock methods which
// merely call the underlying Mutex's RLock and RUnlock methods.
type rmutex struct {
	m *Mutex
}

// lockop obtains or clears a file lock on the specified descriptor, blocking
// and retrying indefinitely if it fails to do so for any reason.
func lockop(name string, fd, lockop int) {
	err := syscall.Flock(fd, lockop)
	for err != nil {
		logrus.Debugf("waiting for file lock on %s", name)
		time.Sleep(100 * time.Millisecond)
		err = syscall.Flock(fd, lockop)
		if err == nil {
			logrus.Debugf("obtained file lock on %s", name)
		}
	}
}

// RLock obtains a read lock on the Mutex.
func (m *Mutex) RLock() {
	m.rw.RLock()
	m.m.Lock()
	defer m.m.Unlock()
	m.readers++
	if m.readers == 1 {
		if m.closeToUnlock && m.lockfd == -1 {
			lockfd, err := syscall.Creat(m.lockfile, syscall.S_IRUSR|syscall.S_IWUSR)
			if err != nil {
				panic(fmt.Sprintf("error opening lock file %s: %v", m.lockfile, err))
			}
			m.lockfd = lockfd
		}
		lockop(m.lockfile, m.lockfd, syscall.LOCK_SH)
		m.locked = true
	}
}

// RUnlock releases a read lock on the Mutex.
func (m *Mutex) RUnlock() {
	m.rw.RUnlock()
	m.m.Lock()
	defer m.m.Unlock()
	m.readers--
	if m.readers == 0 {
		if !m.locked || m.lockfd == -1 {
			panic(fmt.Sprintf("attempted to unlock %s while not locked", m.lockfile))
		}
		if m.closeToUnlock {
			syscall.Close(m.lockfd)
			m.lockfd = -1
		} else {
			lockop(m.lockfile, m.lockfd, syscall.LOCK_UN)
		}
		m.locked = false
		m.unlocked = time.Now()
	}
}

// Lock obtains a write lock on the Mutex.
func (m *Mutex) Lock() {
	m.rw.Lock()
	m.m.Lock()
	defer m.m.Unlock()
	m.writers++
	if m.writers == 1 {
		if m.closeToUnlock && m.lockfd == -1 {
			lockfd, err := syscall.Creat(m.lockfile, syscall.S_IRUSR|syscall.S_IWUSR)
			if err != nil {
				panic(fmt.Sprintf("error opening lock file %s: %v", m.lockfile, err))
			}
			m.lockfd = lockfd
		}
		lockop(m.lockfile, m.lockfd, syscall.LOCK_EX)
		m.locked = true
	}
}

// Unlock releases a write lock on the Mutex.
func (m *Mutex) Unlock() {
	var tv [2]syscall.Timeval
	m.rw.Unlock()
	m.m.Lock()
	defer m.m.Unlock()
	m.writers--
	if m.writers == 0 {
		if !m.locked || m.lockfd == -1 {
			panic(fmt.Sprintf("attempted to unlock %s while not locked", m.lockfile))
		}
		if err := syscall.Gettimeofday(&tv[0]); err != nil {
			panic(fmt.Sprintf("error reading the current time: %v", err))
		}
		tv[1] = tv[0]
		if err := syscall.Futimes(m.lockfd, tv[:]); err != nil {
			panic(fmt.Sprintf("error updating timestamp on lock file %s: %v", m.lockfile, err))
		}
		if m.closeToUnlock {
			syscall.Close(m.lockfd)
			m.lockfd = -1
		} else {
			lockop(m.lockfile, m.lockfd, syscall.LOCK_UN)
		}
		m.unlocked = time.Unix(tv[0].Sec, tv[0].Usec*1000)
		m.locked = false
	}
}

// Updated tells us if the timestamp on the lock file is more recent than the
// last time we unlocked the mutex.
func (m *Mutex) Updated() bool {
	var st syscall.Stat_t
	m.m.Lock()
	defer m.m.Unlock()
	if m.lockfd != -1 {
		if err := syscall.Fstat(m.lockfd, &st); err != nil {
			panic(fmt.Sprintf("error stat()ing lock file %s: %v", m.lockfile, err))
		}
	} else {
		if err := syscall.Stat(m.lockfile, &st); err != nil {
			panic(fmt.Sprintf("error stat()ing lock file %s: %v", m.lockfile, err))
		}
	}
	mtime := time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
	return mtime.After(m.unlocked)
}

// RLocker returns a Locker which obtains and releases read locks on the underlying Mutex.
func (m *Mutex) RLocker() sync.Locker {
	return &rmutex{m: m}
}

// Lock obtains a read lock on the underlying Mutex.
func (r *rmutex) Lock() {
	r.m.RLock()
}

// Unlock releases a read lock on the underlying Mutex.
func (r *rmutex) Unlock() {
	r.m.RUnlock()
}

var lockMgr struct {
	m     sync.Mutex
	locks map[string]*Mutex
}

func init() {
	lockMgr.locks = make(map[string]*Mutex)
}

// get initializes a mutex, defaulting to keeping the descriptor open.
func get(lockfile string) (*Mutex, error) {
	lockMgr.m.Lock()
	defer lockMgr.m.Unlock()

	name, err := filepath.Abs(lockfile)
	if err != nil {
		return nil, err
	}
	fl, ok := lockMgr.locks[name]
	if !ok {
		lockfd, err := syscall.Creat(name, syscall.S_IRUSR|syscall.S_IWUSR)
		if err != nil {
			return nil, err
		}
		syscall.CloseOnExec(lockfd)
		fl = &Mutex{
			lockfd:   lockfd,
			lockfile: name,
			unlocked: time.Now(),
		}
		lockMgr.locks[name] = fl
	}
	return fl, nil
}

// Get returns a mutex which is tied to a lock on the specified lockfile, or nil on error.  The file descriptor is kept open.
func Get(lockfile string) (*Mutex, error) {
	m, err := get(lockfile)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// GetTransient returns a mutex which is tied to a lock on the specified lockfile, or nil on error.  The file descriptor is open only when the lock is held.
func GetTransient(lockfile string) (*Mutex, error) {
	m, err := get(lockfile)
	if err != nil {
		return nil, err
	}
	if !m.closeToUnlock {
		syscall.Close(m.lockfd)
		m.lockfd = -1
		m.closeToUnlock = true
	}
	return m, nil
}

// RLock obtains a read lock on the specified lock file, or returns an error.
func RLock(lockfile string) error {
	fl, err := Get(lockfile)
	if err != nil {
		return err
	}
	fl.RLock()
	return nil
}

// RUnlock releases a read lock on the specified lock file, or returns an error.
func RUnlock(lockfile string) error {
	fl, err := Get(lockfile)
	if err != nil {
		return err
	}
	fl.RUnlock()
	return nil
}

// Lock obtains a write lock on the specified lock file, or returns an error.
func Lock(lockfile string) error {
	fl, err := Get(lockfile)
	if err != nil {
		return err
	}
	fl.Lock()
	return nil
}

// Unlock releases a write lock on the specified lock file, or returns an error.
func Unlock(lockfile string) error {
	fl, err := Get(lockfile)
	if err != nil {
		return err
	}
	fl.Unlock()
	return nil
}
