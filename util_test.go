package certmin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPromptForKeyPassword(t *testing.T) {
	t.SkipNow()
}

func TestParseURL(t *testing.T) {
	remote, err := parseURL("https://foo")
	assert.Equal(t, "foo:443", remote)
	assert.Nil(t, err)

	remote, err = parseURL("ldaps://foo")
	assert.Equal(t, "foo:636", remote)
	assert.Nil(t, err)

	remote, err = parseURL("foo://foo")
	assert.Equal(t, "foo:443", remote)
	assert.Nil(t, err)

	remote, err = parseURL("https://foo:123")
	assert.Equal(t, "foo:123", remote)
	assert.Nil(t, err)

	remote, err = parseURL("foo://foo:123")
	assert.Equal(t, "foo:123", remote)
	assert.Nil(t, err)

	_, err = parseURL("foo://foo:1AA23")
	assert.NotNil(t, err)
	_, err = parseURL("BLAH:123")
	assert.NotNil(t, err)
	_, err = parseURL("BLAH.BOE")
	assert.NotNil(t, err)
}
