package mutex

import (
	"sync"
)

// CCKMMutex is a simple key/value store for arbitrary mutexes. It can be used to
// serialize changes across arbitrary collaborators that share knowledge of the
// keys they must serialize on.
type CCKMMutex struct {
	lock  sync.Mutex
	store map[string]*sync.Mutex
}

// Lock the mutex for the given key. Caller is responsible for calling Unlock for the same key.
func (m *CCKMMutex) Lock(key string) {
	m.get(key).Lock()
}

// Unlock the mutex for the given key. Caller must have called Lock for the same key first.
func (m *CCKMMutex) Unlock(key string) {
	m.get(key).Unlock()
}

// get returns a mutex for the given key, no guarantee of its lock status.
func (m *CCKMMutex) get(key string) *sync.Mutex {
	m.lock.Lock()
	defer m.lock.Unlock()
	mutex, ok := m.store[key]
	if !ok {
		mutex = &sync.Mutex{}
		m.store[key] = mutex
	}
	return mutex
}

// NewCCKMMutex returns a properly initialized CCKMMutex.
func NewCCKMMutex() *CCKMMutex {
	return &CCKMMutex{
		store: make(map[string]*sync.Mutex),
	}
}
