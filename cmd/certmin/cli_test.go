package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAction(t *testing.T) {
	t.SkipNow()
}

func TestVerifyAndDispatch(t *testing.T) {
	params := Params{}

	// help
	params.help = true
	action, msg, err := verifyAndDispatch(params, nil)
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)
	params.help = false

	// version
	params.progVersion = true
	action, msg, err = verifyAndDispatch(params, nil)
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)
	params.progVersion = false

	// empty
	action, msg, err = verifyAndDispatch(params, []string{"certmin"})
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)

	// unknown command
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "foo", "t/myserver.crt"})
	assert.Nil(t, action)
	assert.Empty(t, msg)
	assert.NotNil(t, err)

	// no certs
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "skim"})
	assert.Nil(t, action)
	assert.Contains(t, "unknown command", msg)
	assert.NotNil(t, err)

	// Illegal combination
	params.leaf = true
	params.follow = true
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-chain", "foo"})
	assert.Nil(t, action)
	assert.NotNil(t, err)
	params.leaf = false
	params.follow = false

	params.sort = true
	params.rsort = true
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-chain", "foo"})
	assert.Nil(t, action)
	assert.NotNil(t, err)
	params.sort = false
	params.rsort = false

	// illegal verify key
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-key", "foo"})
	assert.Nil(t, action)
	assert.NotNil(t, err)

	// legal actions
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "skim", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Nil(t, err)

	params.roots = []string{"foo"}
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-chain", "foo", "fa"})
	assert.NotNil(t, action)
	assert.Nil(t, err)
	params.roots = nil

	params.leaf = true
	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-chain", "foo", "fa"})
	assert.NotNil(t, action)
	assert.Nil(t, err)
	params.leaf = false

	action, msg, err = verifyAndDispatch(params, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Nil(t, err)
}
