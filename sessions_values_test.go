package sessions

import (
	"testing"

	"github.com/admpub/securecookie"
	"github.com/stretchr/testify/require"
)

func TestEmptyValues(t *testing.T) {
	b, err := securecookie.Gob.Serialize(map[interface{}]interface{}{`A`: 1})
	require.NoError(t, err)
	require.NotEmpty(t, b)
	t.Logf(`%v: %d`, b, len(b))
}
