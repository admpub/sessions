package sessions

import (
	"os"
	"testing"
	"time"

	"github.com/admpub/securecookie"
	"github.com/stretchr/testify/assert"
)

func TestFileSystemDeleteExpired(t *testing.T) {
	sessionDir := `./testdata`
	err := os.MkdirAll(sessionDir, os.ModePerm)
	assert.NoError(t, err)
	st := NewFilesystemStore(sessionDir)
	st.debug = true
	ss := &Session{ID: makeFileSessionID(), Values: make(map[interface{}]interface{})}
	b, err := securecookie.Gob.Serialize(ss.Values)
	assert.NoError(t, err)
	assert.True(t, SizeIsEmptyGob(int64(len(b))))

	err = st.save(ss)
	assert.NoError(t, err)
	size, err := st.size(ss.ID)
	assert.NoError(t, err)
	assert.True(t, SizeIsEmptyGob(size))
	info, err := os.Stat(st.sessionFile(ss.ID))
	assert.NoError(t, err)
	time.Sleep(2 * time.Second)
	t.Logf(`lifeTime: %.2f`, time.Since(info.ModTime()).Seconds())
	err = st.DeleteExpired(10, 1)
	assert.NoError(t, err)

	ss.Values[`user`] = `user`
	err = st.save(ss)
	assert.NoError(t, err)
	size, err = st.size(ss.ID)
	assert.NoError(t, err)
	assert.False(t, SizeIsEmptyGob(size))
	t.Logf(`emptyLength: %d; currentLength: %d`, EmptyGobSize(), size)

	time.Sleep(2 * time.Second)
	err = st.DeleteExpired(1, 1)
	assert.NoError(t, err)
	time.Sleep(2 * time.Second)
}
