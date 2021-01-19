package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLocation(t *testing.T) {
	loc, remote, err := getLocation("util.go")
	assert.NoError(t, err)
	assert.Equal(t, "util.go", loc)
	assert.False(t, remote)

	loc, remote, err = getLocation("https://foo.fa/bar?baz")
	assert.NoError(t, err)
	assert.Equal(t, "foo.fa:443", loc)
	assert.True(t, remote)

	loc, remote, err = getLocation("foo/fa")
	assert.NoError(t, err)
	assert.Equal(t, "foo:443", loc)
	assert.True(t, remote)

	loc, remote, err = getLocation("foo:abc123")
	assert.Error(t, err)
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

func TestPromptForKeyPassword(t *testing.T) {
	t.SkipNow()
}
