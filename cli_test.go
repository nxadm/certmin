package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAction(t *testing.T) {
	t.SkipNow()
}

func TestSkimCmdParse(t *testing.T) {
	action, exitStatus := skimCmdParse(nil, false)
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)
}

func TestVerifyChainCmdParse(t *testing.T) {
	action, exitStatus := verifyChainCmdParse([]string{}, []string{}, "", false)
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)
}

func TestVerifyKeyCmdParse(t *testing.T) {
	action, exitStatus := verifyKeyCmdParse("", "")
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)
}

func TestVerifyAndDispatch(t *testing.T) {
	// help
	action, exitStatus :=
		verifyAndDispatch(true, false, false, nil, nil, nil)
	assert.Nil(t, action)
	assert.Equal(t, exitStatus, 0)

	// empty
	action, exitStatus =
		verifyAndDispatch(false, false, false, nil, nil, []string{"certmin"})
	assert.Nil(t, action)
	assert.Equal(t, 0, exitStatus)

	// illegal no certs
	action, exitStatus =
		verifyAndDispatch(
			false, false, false, nil, nil, []string{"certmin", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// unknown command
	action, exitStatus = verifyAndDispatch(
		false, false, false, nil, nil, []string{"certmin", "foo", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Illegal verify-chain
	action, exitStatus = verifyAndDispatch(false, false, false,
		nil, nil, []string{"certmin", "verify-chain", "foo", "bar"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	action, exitStatus = verifyAndDispatch(false, false,
		false, nil, nil, []string{"certmin", "verify-chain", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Illegal verify key
	action, exitStatus =
		verifyAndDispatch(false, false, true,
			nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false,
			nil, nil, []string{"certmin", "verify-key", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Legal actions
	action, exitStatus =
		verifyAndDispatch(false, false, false,
			nil, nil, []string{"certmin", "skim", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false,
			[]string{"foo"}, nil, []string{"certmin", "verify-chain", "foo"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, true,
			nil, nil, []string{"certmin", "verify-chain", "foo"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false,
			nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false,
			nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)
}
