package certmin

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetrieveRemoteCerts(t *testing.T) {
	certs, warn, err := RetrieveRemoteCerts("faa", 1*time.Second)
	assert.Nil(t, certs)
	assert.NoError(t, warn)
	assert.Error(t, err)

	certs, warn, err = RetrieveRemoteCerts("faa", 0)
	assert.Nil(t, certs)
	assert.NoError(t, warn)
	assert.Error(t, err)

	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, warn, err = RetrieveRemoteCerts("github.com:443", 5*time.Second)
		assert.NoError(t, warn)
		assert.NoError(t, err)
		assert.True(t, len(certs) >= 2)

		certs, warn, err = RetrieveRemoteCerts("8.8.8.8:443", 5*time.Second)
		assert.NoError(t, warn)
		assert.NoError(t, err)
		assert.True(t, len(certs) >= 2)
	}
}
