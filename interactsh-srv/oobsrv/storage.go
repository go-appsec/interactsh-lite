package oobsrv

import (
	"container/list"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/syndtr/goleveldb/leveldb"
	leveldberrors "github.com/syndtr/goleveldb/leveldb/errors"
)

// Storage is the interface for session and interaction storage backends.
type Storage interface {
	// Register stores a new session and returns its AES key. Matching secret
	// on duplicate returns existing key (keep-alive); mismatched secret errors.
	// The response is stored on initial registration and ignored on keep-alive.
	Register(ctx context.Context, correlationID string, publicKey *rsa.PublicKey, secretKey string, response *oobclient.ResponseConfig) (aesKey []byte, err error)

	// GetSession validates credentials and returns a handle for accessing
	// session data and draining interactions.
	GetSession(correlationID, secretKey string) (SessionHandle, error)

	// GetResponse returns the stored response config for a correlation ID, or nil.
	GetResponse(correlationID string) *oobclient.ResponseConfig

	// AppendInteraction adds an encrypted interaction to a session.
	AppendInteraction(correlationID string, interaction []byte) error

	// Delete removes a session after secret key validation.
	Delete(correlationID, secretKey string) error

	// Close releases resources held by the storage backend.
	Close() error

	// HasCorrelationID reports whether a correlation ID is registered.
	HasCorrelationID(correlationID string) bool

	HitCount() uint64
	MissCount() uint64
	EvictionCount() uint64
	SessionCount() uint64
	SessionsTotal() uint64
}

// SessionHandle provides access to a validated session. Obtained from Storage.GetSession.
type SessionHandle interface {
	AESKey() []byte
	PublicKey() *rsa.PublicKey
	// GetAndClearInteractions returns and removes all interactions (FIFO).
	GetAndClearInteractions() ([][]byte, error)
}

// Session holds per-client registration state.
type Session struct {
	PublicKey *rsa.PublicKey
	AESKey    []byte
	AESBlock  cipher.Block // cached from aes.NewCipher(AESKey)
	SecretKey []byte
	Response  *oobclient.ResponseConfig // nil = no configured response

	mu           sync.Mutex
	interactions [][]byte
	lastAccess   atomic.Int64 // UnixNano; atomic for lock-free read/write
	createdAt    time.Time
}

// lruEntry holds a correlation ID for the LRU list.
type lruEntry struct {
	correlationID string
}

const maxCacheCapacity = 2_500_000

// memoryStorage implements Storage with an in-memory map and LRU eviction.
type memoryStorage struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	lruList  *list.List
	lruMap   map[string]*list.Element

	ttl        time.Duration
	noEviction bool
	slidingTTL bool // true=sliding (expire-after-access), false=fixed (expire-after-write)

	hits          atomic.Uint64
	misses        atomic.Uint64
	evictions     atomic.Uint64
	sessionsTotal atomic.Uint64

	logger *slog.Logger

	// onEvict is called when a session is evicted. Receives the removed
	// session so diskStorage can lock session.mu before deleting LevelDB keys.
	onEvict func(correlationID string, session *Session)

	// onRegister is called under m.mu write lock before a new session is
	// added to the map. Used by diskStorage to delete stale LevelDB data.
	onRegister func(correlationID string)

	// clock for testable TTL; defaults to time.Now
	clock func() time.Time
}

// NewMemoryStorage creates an in-memory storage backend.
func NewMemoryStorage(cfg Config, logger *slog.Logger) *memoryStorage {
	evictionDays := cfg.Eviction
	if evictionDays < 1 { // unset/invalid falls back to the default TTL
		evictionDays = defaultEvictionDays
	}
	return &memoryStorage{
		sessions:   make(map[string]*Session),
		lruList:    list.New(),
		lruMap:     make(map[string]*list.Element),
		ttl:        time.Duration(evictionDays) * 24 * time.Hour,
		noEviction: cfg.NoEviction,
		slidingTTL: cfg.EvictionStrategy == EvictionSliding,
		logger:     logger,
		clock:      time.Now,
	}
}

func (m *memoryStorage) now() time.Time {
	return m.clock()
}

func (m *memoryStorage) isExpired(s *Session) bool {
	if m.noEviction {
		return false
	} else if m.slidingTTL {
		return m.now().Sub(s.getLastAccess()) > m.ttl
	}
	return m.now().Sub(s.createdAt) > m.ttl
}

func (s *Session) getLastAccess() time.Time {
	return time.Unix(0, s.lastAccess.Load())
}

func (m *memoryStorage) touchSession(s *Session) {
	s.lastAccess.Store(m.now().UnixNano())
}

// evictLRU removes the least-recently-accessed entry. Caller must hold write lock.
// Probes a small window from the front to compensate for stale LRU positions
// caused by lock-free lastAccess updates in AppendInteraction.
func (m *memoryStorage) evictLRU() {
	const maxProbe = 8
	var victimID string
	var victimTime int64 = math.MaxInt64
	elem := m.lruList.Front()
	for range maxProbe {
		if elem == nil {
			break
		}

		entry := elem.Value.(*lruEntry)
		session := m.sessions[entry.correlationID]
		if session == nil {
			// stale entry - clean up and continue
			next := elem.Next()
			m.lruList.Remove(elem)
			delete(m.lruMap, entry.correlationID)
			elem = next
			continue
		}
		if t := session.lastAccess.Load(); t < victimTime {
			victimTime = t
			victimID = entry.correlationID
		}
		elem = elem.Next()
	}
	if victimID != "" {
		m.removeLocked(victimID)
		m.evictions.Add(1)
	}
}

// removeLocked removes a session from the map and LRU list. Caller must hold write lock.
func (m *memoryStorage) removeLocked(correlationID string) {
	session := m.sessions[correlationID]
	delete(m.sessions, correlationID)
	if elem, ok := m.lruMap[correlationID]; ok {
		m.lruList.Remove(elem)
		delete(m.lruMap, correlationID)
	}
	if m.onEvict != nil {
		m.onEvict(correlationID, session)
	}
}

// promoteLRU moves a session to the back of the LRU list. Caller must hold write lock.
func (m *memoryStorage) promoteLRU(correlationID string) {
	if elem, ok := m.lruMap[correlationID]; ok {
		m.lruList.MoveToBack(elem)
	}
}

func (m *memoryStorage) Register(ctx context.Context, correlationID string, publicKey *rsa.PublicKey, secretKey string, response *oobclient.ResponseConfig) ([]byte, error) {
	key, _, err := m.registerInternal(ctx, correlationID, publicKey, secretKey, response)
	return key, err
}

// registerInternal performs registration and reports whether it was a new
// session (true) or a keep-alive for an existing session (false).
func (m *memoryStorage) registerInternal(_ context.Context, correlationID string, publicKey *rsa.PublicKey, secretKey string, response *oobclient.ResponseConfig) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.sessions[correlationID]; ok {
		if m.isExpired(existing) {
			m.removeLocked(correlationID)
			m.evictions.Add(1)
		} else {
			m.hits.Add(1)
			if subtle.ConstantTimeCompare(existing.SecretKey, []byte(secretKey)) != 1 {
				return nil, false, errors.New("correlation-id provided already exists")
			}
			// Keep-alive: same secret key - return existing AES key
			if m.slidingTTL {
				m.touchSession(existing)
			}
			m.promoteLRU(correlationID)
			return existing.AESKey, false, nil
		}
	}
	m.misses.Add(1)

	if len(m.sessions) >= maxCacheCapacity {
		m.evictLRU() // Evict if at capacity
	}

	aesKey, err := GenerateAESKey()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate AES key: %w", err)
	}
	aesBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	now := m.now()
	session := &Session{
		PublicKey: publicKey,
		AESKey:    aesKey,
		AESBlock:  aesBlock,
		SecretKey: []byte(secretKey),
		Response:  response,
		createdAt: now,
	}
	session.lastAccess.Store(now.UnixNano())

	if m.onRegister != nil {
		m.onRegister(correlationID)
	}
	m.sessions[correlationID] = session
	elem := m.lruList.PushBack(&lruEntry{correlationID: correlationID})
	m.lruMap[correlationID] = elem
	m.sessionsTotal.Add(1)

	return aesKey, true, nil
}

// memorySessionHandle is the SessionHandle for in-memory storage.
type memorySessionHandle struct {
	session *Session
}

func (h *memorySessionHandle) AESKey() []byte            { return h.session.AESKey }
func (h *memorySessionHandle) PublicKey() *rsa.PublicKey { return h.session.PublicKey }

func (h *memorySessionHandle) GetAndClearInteractions() ([][]byte, error) {
	h.session.mu.Lock()
	defer h.session.mu.Unlock()
	interactions := h.session.interactions
	h.session.interactions = nil
	return interactions, nil
}

func (m *memoryStorage) GetSession(correlationID, secretKey string) (SessionHandle, error) {
	session, err := m.getSession(correlationID, secretKey)
	if err != nil {
		return nil, err
	}
	return &memorySessionHandle{session: session}, nil
}

// getSession validates credentials and returns the raw session. Used by
// diskStorage to avoid a type assertion on the SessionHandle interface.
func (m *memoryStorage) getSession(correlationID, secretKey string) (*Session, error) {
	m.mu.RLock()
	session, ok := m.sessions[correlationID]
	if !ok {
		m.mu.RUnlock()
		m.misses.Add(1)
		return nil, errors.New("could not get correlation-id")
	}
	expired := m.isExpired(session)
	if !expired {
		// Validate secret while session pointer is guaranteed current under RLock
		if subtle.ConstantTimeCompare(session.SecretKey, []byte(secretKey)) != 1 {
			m.mu.RUnlock()
			return nil, errors.New("invalid secret key passed for user")
		}
		m.mu.RUnlock()

		m.hits.Add(1)
		if m.slidingTTL {
			m.touchSession(session)
		}
		m.mu.Lock()
		m.promoteLRU(correlationID)
		m.mu.Unlock()
		return session, nil
	}
	m.mu.RUnlock()

	// Lazy eviction under write lock with double-check
	m.mu.Lock()
	session, ok = m.sessions[correlationID]
	switch {
	case !ok:
		m.mu.Unlock()
		m.misses.Add(1)
		return nil, errors.New("could not get correlation-id")
	case m.isExpired(session):
		m.removeLocked(correlationID)
		m.evictions.Add(1)
		m.mu.Unlock()
		m.misses.Add(1)
		return nil, errors.New("could not get correlation-id")
	default:
		// Refreshed by concurrent touch - validate secret under write lock
		if subtle.ConstantTimeCompare(session.SecretKey, []byte(secretKey)) != 1 {
			m.mu.Unlock()
			return nil, errors.New("invalid secret key passed for user")
		}
		m.promoteLRU(correlationID)
		m.mu.Unlock()
	}

	m.hits.Add(1)
	if m.slidingTTL {
		m.touchSession(session)
	}
	return session, nil
}

func (m *memoryStorage) AppendInteraction(correlationID string, interaction []byte) error {
	m.mu.RLock()
	session, ok := m.sessions[correlationID]
	m.mu.RUnlock()

	if !ok {
		m.misses.Add(1)
		return nil
	}
	m.hits.Add(1)

	if m.slidingTTL {
		m.touchSession(session)
	}

	encrypted, err := EncryptInteractionBlock(interaction, session.AESBlock)
	if err != nil {
		m.logger.Error("failed to encrypt interaction", "error", err)
		return nil
	}

	session.mu.Lock()
	session.interactions = append(session.interactions, encrypted)
	session.mu.Unlock()

	m.logger.Debug("interaction stored", "correlation-id", correlationID)

	return nil
}

func (m *memoryStorage) Delete(correlationID, secretKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[correlationID]
	if !ok {
		m.misses.Add(1)
		return errors.New("could not get correlation-id")
	}
	m.hits.Add(1)

	if subtle.ConstantTimeCompare(session.SecretKey, []byte(secretKey)) != 1 {
		return errors.New("invalid secret key passed for user")
	}

	m.removeLocked(correlationID)
	return nil
}

func (m *memoryStorage) Close() error {
	return nil
}

func (m *memoryStorage) HasCorrelationID(correlationID string) bool {
	m.mu.RLock()
	session, ok := m.sessions[correlationID]
	if !ok {
		m.mu.RUnlock()
		return false
	}
	expired := m.isExpired(session)
	m.mu.RUnlock()

	if !expired {
		return true
	}

	// TODO - simplify?
	// Rare: lazy eviction under write lock with double-check
	m.mu.Lock()
	session, ok = m.sessions[correlationID]
	if ok && m.isExpired(session) {
		m.removeLocked(correlationID)
		m.evictions.Add(1)
		m.mu.Unlock()
		return false
	}
	m.mu.Unlock()
	return ok
}

func (m *memoryStorage) GetResponse(correlationID string) *oobclient.ResponseConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[correlationID]
	if !ok {
		return nil
	}

	if expired := m.isExpired(session); expired {
		return nil
	}
	return session.Response
}

func (m *memoryStorage) HitCount() uint64      { return m.hits.Load() }
func (m *memoryStorage) MissCount() uint64     { return m.misses.Load() }
func (m *memoryStorage) EvictionCount() uint64 { return m.evictions.Load() }
func (m *memoryStorage) SessionCount() uint64 {
	m.mu.RLock()
	n := len(m.sessions)
	m.mu.RUnlock()
	return uint64(n)
}
func (m *memoryStorage) SessionsTotal() uint64 { return m.sessionsTotal.Load() }

// sharedBucketCleanupInterval is the minimum time between stale consumer cleanups.
const sharedBucketCleanupInterval = time.Minute

// SharedBucket is an append-only interaction buffer with per-consumer read offsets.
type SharedBucket struct {
	mu           sync.RWMutex
	interactions [][]byte
	maxBuffer    int
	offsets      map[string]int
	lastSeen     map[string]time.Time
	evictionTTL  time.Duration
	lastCleanup  time.Time
}

// NewSharedBucket creates a SharedBucket with max buffer size and consumer eviction TTL.
func NewSharedBucket(maxBuffer int, evictionTTL time.Duration) *SharedBucket {
	return &SharedBucket{
		maxBuffer:   maxBuffer,
		offsets:     make(map[string]int),
		lastSeen:    make(map[string]time.Time),
		evictionTTL: evictionTTL,
		lastCleanup: time.Now(),
	}
}

// Append adds an interaction. The slice grows up to 2*maxBuffer, then the
// oldest maxBuffer elements are discarded in one batch to amortize copy cost.
func (b *SharedBucket) Append(interaction []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.interactions = append(b.interactions, interaction)

	if b.maxBuffer > 0 && len(b.interactions) >= 2*b.maxBuffer {
		n := copy(b.interactions, b.interactions[b.maxBuffer:])
		clear(b.interactions[n:])
		b.interactions = b.interactions[:n]
		for c, offset := range b.offsets {
			b.offsets[c] = max(0, offset-b.maxBuffer)
		}
	}
}

// ReadFrom returns new interactions since the consumer's last read and advances the offset.
func (b *SharedBucket) ReadFrom(consumer string) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()

	offset := b.offsets[consumer]
	if offset >= len(b.interactions) {
		b.offsets[consumer] = len(b.interactions)
		b.lastSeen[consumer] = now
		b.cleanupStaleLocked(now)
		return nil
	}

	result := slices.Clone(b.interactions[offset:])
	b.offsets[consumer] = len(b.interactions)
	b.lastSeen[consumer] = now
	b.cleanupStaleLocked(now)

	return result
}

// cleanupStaleLocked removes stale consumers past the eviction TTL. Caller must hold b.mu write lock.
func (b *SharedBucket) cleanupStaleLocked(now time.Time) {
	if now.Sub(b.lastCleanup) < sharedBucketCleanupInterval {
		return
	}
	for consumer, lastSeen := range b.lastSeen {
		if now.Sub(lastSeen) > b.evictionTTL {
			delete(b.offsets, consumer)
			delete(b.lastSeen, consumer)
		}
	}
	b.lastCleanup = now
}

// diskStorage wraps memoryStorage with LevelDB persistence for interactions.
type diskStorage struct {
	*memoryStorage
	db     *leveldb.DB
	dbPath string
	closed atomic.Bool
}

// NewDiskStorage creates a disk-backed storage with LevelDB.
func NewDiskStorage(cfg Config, logger *slog.Logger) (*diskStorage, error) {
	// Random subdirectory per startup
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random path: %w", err)
	}
	dbPath := filepath.Join(cfg.DiskPath, hex.EncodeToString(randBytes))

	db, err := leveldb.OpenFile(dbPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %w", err)
	}

	ms := NewMemoryStorage(cfg, logger)

	ds := &diskStorage{
		memoryStorage: ms,
		db:            db,
		dbPath:        dbPath,
	}

	// Lock session.mu before deleting LevelDB keys to serialize with
	// any in-flight AppendInteraction that holds the same session pointer.
	ms.onEvict = func(correlationID string, session *Session) {
		if session != nil {
			session.mu.Lock()
			defer session.mu.Unlock()
		}
		_ = db.Delete([]byte(correlationID), nil)
	}

	// Delete stale LevelDB data before new sessions are added to the map.
	// Runs under m.mu write lock so no concurrent AppendInteraction can
	// be in flight for this correlation ID.
	ms.onRegister = func(correlationID string) {
		_ = db.Delete([]byte(correlationID), nil)
	}

	return ds, nil
}

func (d *diskStorage) AppendInteraction(correlationID string, interaction []byte) error {
	d.mu.RLock()
	session, ok := d.sessions[correlationID]
	d.mu.RUnlock()

	if !ok {
		d.misses.Add(1)
		return nil
	}
	d.hits.Add(1)

	encrypted, err := EncryptInteractionBlock(interaction, session.AESBlock)
	if err != nil {
		d.logger.Error("failed to encrypt interaction for disk", "error", err)
		return nil
	}

	if d.slidingTTL {
		d.touchSession(session)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// LevelDB read-modify-write under per-session lock
	key := []byte(correlationID)
	existing, err := d.db.Get(key, nil)
	if err != nil && !errors.Is(err, leveldberrors.ErrNotFound) {
		return nil // silently discard
	}

	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(encrypted)))
	newValue := append(append(existing, prefix[:]...), encrypted...)

	_ = d.db.Put(key, newValue, nil) // silently discard write errors

	d.logger.Debug("interaction stored (disk)", "correlation-id", correlationID)

	return nil
}

// diskSessionHandle is the SessionHandle for disk-backed storage.
type diskSessionHandle struct {
	session       *Session
	db            *leveldb.DB
	closed        *atomic.Bool
	correlationID string
}

func (h *diskSessionHandle) AESKey() []byte            { return h.session.AESKey }
func (h *diskSessionHandle) PublicKey() *rsa.PublicKey { return h.session.PublicKey }

func (h *diskSessionHandle) GetAndClearInteractions() ([][]byte, error) {
	if h.closed.Load() {
		return nil, errors.New("storage closed")
	}

	h.session.mu.Lock()

	key := []byte(h.correlationID)
	data, err := h.db.Get(key, nil)
	if err != nil {
		h.session.mu.Unlock()
		if errors.Is(err, leveldberrors.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("could not get interactions: %w", err)
	}

	_ = h.db.Delete(key, nil)
	h.session.mu.Unlock()

	// parse length-prefixed records [4-byte big-endian length][payload]...
	var interactions [][]byte
	for off := 0; off+4 <= len(data); {
		n := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+n > len(data) {
			break
		}
		interactions = append(interactions, data[off:off+n:off+n])
		off += n
	}
	return interactions, nil
}

func (d *diskStorage) GetSession(correlationID, secretKey string) (SessionHandle, error) {
	session, err := d.getSession(correlationID, secretKey)
	if err != nil {
		return nil, err
	}
	return &diskSessionHandle{
		session:       session,
		db:            d.db,
		closed:        &d.closed,
		correlationID: correlationID,
	}, nil
}

func (d *diskStorage) Close() error {
	d.closed.Store(true)
	if err := d.db.Close(); err != nil {
		return err
	}
	return os.RemoveAll(d.dbPath)
}
