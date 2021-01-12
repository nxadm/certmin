package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRetrieveCerts(t *testing.T) {
	certs, err := retrieveCerts("foo", "faa", true)
	assert.Nil(t, certs)
	assert.Error(t, err)
	if os.Getenv("AUTHOR_TESTING") != "" {
		certs, err = retrieveCerts("tcp", "github.com:443", true)
		assert.NoError(t, err)
		assert.True(t, len(certs) >= 2)
	}
}
