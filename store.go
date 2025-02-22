// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"encoding/base32"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/admpub/securecookie"
	"github.com/webx-top/echo"
)

const (
	// File name prefix for session files.
	sessionFilePrefix = "session_"
)

// Store is an interface for custom session stores.
//
// See CookieStore and FilesystemStore for examples.
type Store interface {
	// Get should return a cached session.
	Get(ctx echo.Context, name string) (*Session, error)

	// New should create and return a new session.
	//
	// Note that New should never return a nil session, even in the case of
	// an error if using the Registry infrastructure to cache the session.
	New(ctx echo.Context, name string) (*Session, error)
	Reload(ctx echo.Context, s *Session) error

	// Save should persist session to the underlying store implementation.
	Save(ctx echo.Context, s *Session) error
	// Remove server-side data
	Remove(sessionID string) error
}

// IDGenerator session id generator
type IDGenerator interface {
	GenerateID(ctx echo.Context, session *Session) (string, error)
}

// CookieStore ----------------------------------------------------------------

// NewCookieStore returns a new CookieStore.
//
// Keys are defined in pairs to allow key rotation, but the common case is
// to set a single authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for
// encryption. The encryption key can be set to nil or omitted in the last
// pair, but the authentication key is required in all pairs.
//
// It is recommended to use an authentication key with 32 or 64 bytes.
// The encryption key, if set, must be either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256 modes.
func NewCookieStore(keyPairs ...[]byte) *CookieStore {
	cs := &CookieStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
	}
	return cs
}

// CookieStore stores sessions using secure cookies.
type CookieStore struct {
	Codecs []securecookie.Codec
}

// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (s *CookieStore) Get(ctx echo.Context, name string) (*Session, error) {
	return GetRegistry(ctx).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
func (s *CookieStore) New(ctx echo.Context, name string) (*Session, error) {
	session := NewSession(s, name)
	session.IsNew = true
	var err error
	if v := ctx.GetCookie(name); len(v) > 0 {
		err = securecookie.DecodeMultiWithMaxAge(
			name, v, &session.Values,
			ctx.CookieOptions().MaxAge,
			s.Codecs...)
		if err == nil {
			session.IsNew = false
			session.ID = v
		}
	}
	return session, err
}

func (s *CookieStore) Reload(ctx echo.Context, session *Session) error {
	if len(session.ID) == 0 {
		return nil
	}
	err := securecookie.DecodeMultiWithMaxAge(
		session.Name(), session.ID, &session.Values,
		ctx.CookieOptions().MaxAge,
		s.Codecs...)
	if err == nil {
		session.IsNew = false
	}
	return err
}

func (s *CookieStore) GenerateID(ctx echo.Context, session *Session) (string, error) {
	return securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
}

// Save adds a single session to the response.
func (s *CookieStore) Save(ctx echo.Context, session *Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		s.Codecs...)
	if err != nil {
		return err
	}
	SetCookie(ctx, session.Name(), encoded)
	return nil
}

func (s *CookieStore) Remove(sessionID string) error {
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *CookieStore) MaxAge(age int) {
	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// FilesystemStore ------------------------------------------------------------

var fileMutex sync.RWMutex

// NewFilesystemStore returns a new FilesystemStore.
//
// The path argument is the directory where sessions will be saved. If empty
// it will use os.TempDir().
//
// See NewCookieStore() for a description of the other parameters.
func NewFilesystemStore(path string, keyPairs ...[]byte) *FilesystemStore {
	if len(path) == 0 {
		path = os.TempDir()
	}
	fs := &FilesystemStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		path:   path,
	}
	return fs
}

// FilesystemStore stores sessions in the filesystem.
//
// It also serves as a reference for custom stores.
//
// This store is still experimental and not well tested. Feedback is welcome.
type FilesystemStore struct {
	Codecs []securecookie.Codec
	path   string
	debug  bool
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new FilesystemStore is 4096.
func (s *FilesystemStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

func (s *FilesystemStore) SetDebug(on bool) {
	s.debug = on
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *FilesystemStore) Get(ctx echo.Context, name string) (*Session, error) {
	return GetRegistry(ctx).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *FilesystemStore) New(ctx echo.Context, name string) (*Session, error) {
	session := NewSession(s, name)
	session.IsNew = true
	var err error
	if v := ctx.GetCookie(name); len(v) > 0 {
		err = securecookie.DecodeMultiWithMaxAge(
			name, v, &session.ID,
			ctx.CookieOptions().MaxAge,
			s.Codecs...)
		if err == nil {
			err = s.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

func (s *FilesystemStore) Reload(ctx echo.Context, session *Session) error {
	err := s.load(session)
	if err == nil {
		session.IsNew = false
	}
	return err
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func makeFileSessionID() string {
	return base32RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
}

// Save adds a single session to the response.
func (s *FilesystemStore) Save(ctx echo.Context, session *Session) error {
	// Delete if max-age is < 0
	if ctx.CookieOptions().MaxAge < 0 {
		if err := s.erase(session); err != nil {
			return err
		}
		SetCookie(ctx, session.Name(), "", -1)
		return nil
	}
	if len(session.ID) == 0 {
		// Because the ID is used in the filename, encode it to
		// use alphanumeric characters only.
		session.ID = makeFileSessionID()
	}
	if err := s.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		s.Codecs...)
	if err != nil {
		return err
	}
	SetCookie(ctx, session.Name(), encoded)
	return nil
}

func (s *FilesystemStore) Remove(sessionID string) error {
	if len(sessionID) == 0 {
		return nil
	}
	filename := s.sessionFile(sessionID)
	fileMutex.RLock()
	defer fileMutex.RUnlock()

	err := os.Remove(filename)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}

func (s *FilesystemStore) sessionFile(sessionID string) string {
	return filepath.Join(s.path, sessionFilePrefix+filepath.Base(sessionID))
}

func (s *FilesystemStore) size(sessionID string) (int64, error) {
	if len(sessionID) == 0 {
		return 0, nil
	}
	filename := s.sessionFile(sessionID)
	fileMutex.RLock()
	defer fileMutex.RUnlock()

	fi, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return fi.Size(), err
}

// delete session file
func (s *FilesystemStore) erase(session *Session) error {
	return s.Remove(session.ID)
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *FilesystemStore) MaxAge(age int) {
	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

var emptyGob, _ = securecookie.Gob.Serialize(make(map[interface{}]interface{}))

func SizeIsEmptyGob(size int64) bool {
	return size == EmptyGobSize()
}

func EmptyGobSize() int64 {
	size := len(emptyGob)
	return int64(size)
}

// save writes encoded session.Values to a file.
func (s *FilesystemStore) save(session *Session) error {
	b, err := securecookie.Gob.Serialize(session.Values)
	if err != nil {
		return err
	}
	filename := s.sessionFile(session.ID)
	fileMutex.Lock()
	defer fileMutex.Unlock()
	return os.WriteFile(filename, b, 0600)
}

// load reads a file and decodes its content into session.Values.
func (s *FilesystemStore) load(session *Session) error {
	filename := s.sessionFile(session.ID)
	fileMutex.RLock()
	defer fileMutex.RUnlock()
	fdata, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return securecookie.Gob.Deserialize(fdata, &session.Values)
}

func (s *FilesystemStore) DeleteExpired(maxAge float64, emptyDataAge float64) error {
	if maxAge <= 0 && emptyDataAge <= 0 {
		return nil
	}
	emptyLength := EmptyGobSize()
	err := filepath.Walk(s.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return err
		}
		if !strings.HasPrefix(info.Name(), sessionFilePrefix) {
			return err
		}
		age := time.Since(info.ModTime()).Seconds()
		if age > maxAge {
			if s.debug {
				fmt.Printf("delete %s : {age: %v} > {maxAge: %v}\n", info.Name(), age, maxAge)
			}
			err = os.Remove(path)
			return err
		}
		if emptyDataAge > 0 && emptyLength > 0 && info.Size() == emptyLength && age > emptyDataAge {
			if s.debug {
				fmt.Printf("delete %s : {age: %v} > {emptyDataAge: %v}\n", info.Name(), age, emptyDataAge)
			}
			err = os.Remove(path)
			return err
		}
		return err
	})
	return err
}
