package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAction(t *testing.T) {
	t.SkipNow()
}

//func verifyAndDispatch(help, progVersion, remotes, issuerURIs, noRemoteRoots, keep bool,
//	roots, inters, args []string) (actionFunc, string, error) {
func TestVerifyAndDispatch(t *testing.T) {
	// help
	action, msg, err := verifyAndDispatch(true, false, false,
		false, false, false, nil, nil, nil)
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)

	// version
	action, msg, err = verifyAndDispatch(false, true, false,
		false, false, false, nil, nil, nil)
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)

	// empty
	action, msg, err = verifyAndDispatch(false, false, false,
		false, false, false, nil, nil, []string{"certmin"})
	assert.Nil(t, action)
	assert.NotEmpty(t, msg)
	assert.Nil(t, err)

	// unknown command
	action, msg, err = verifyAndDispatch(false, false, false,
		false, false, false, nil, nil,
		[]string{"certmin", "foo", "t/myserver.crt"})
	assert.Nil(t, action)
	assert.Empty(t, msg)
	assert.NotNil(t, err)

	// no certs
	action, msg, err = verifyAndDispatch(false, false, false, false,
		false, false, nil, nil, []string{"certmin", "skim"})
	assert.Nil(t, action)
	assert.Contains(t, "unkmown command", msg)
	assert.NotNil(t, err)

	// Illegal combination
	action, msg, err = verifyAndDispatch(false, false, true, true,
		false, false, nil, nil, []string{"certmin", "verify-chain", "foo"})
	assert.Nil(t, action)
	assert.NotNil(t, err)

	// illegal verify key
	action, msg, err = verifyAndDispatch(false, false, false, false,
		false, false, nil, nil, []string{"certmin", "verify-key", "foo"})
	assert.Nil(t, action)
	assert.NotNil(t, err)

	// legal actions
	action, msg, err = verifyAndDispatch(false, false, false, false,
		false, false, nil, nil, []string{"certmin", "skim", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Nil(t, err)

	action, msg, err = verifyAndDispatch(
		false, false, false, false, false,
		false, []string{"foo"}, nil, []string{"certmin", "verify-chain", "foo", "fa"})
	assert.NotNil(t, action)
	assert.Nil(t, err)

	action, msg, err = verifyAndDispatch(
		false, false, true, false, false,
		false, nil, nil, []string{"certmin", "verify-chain", "foo", "fa"})
	assert.NotNil(t, action)
	assert.Nil(t, err)

	action, msg, err =
		verifyAndDispatch(
			false, false, false, false, false,
			false, nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Nil(t, err)
}
