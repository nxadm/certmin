package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyAndDispatch(t *testing.T) {
	// help
	action, exitStatus :=
		verifyAndDispatch(true, false, false, false, false,
			"", nil, nil, nil)
	assert.Nil(t, action)
	assert.Equal(t,exitStatus, 0)

	// empty
	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin"})
	assert.Nil(t, action)
	assert.Equal(t, 0, exitStatus)

	// illegal no certs
	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// illegal combinations
	action, exitStatus =
		verifyAndDispatch(false, false, true, true, false,
			"", nil, nil, []string{"certmin", "foo", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false, false, true,
			"", nil, nil, []string{"certmin", "foo", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Illegal verify-chain
	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "verify-chain", "foo", "bar"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "verify-chain", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Illegal verify key
	action, exitStatus =
		verifyAndDispatch(false, false, true, false, true,
			"", nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "verify-key", "foo"})
	assert.Nil(t, action)
	assert.Equal(t, 1, exitStatus)

	// Legal actions
	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "skim", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", []string{"foo"}, nil, []string{"certmin", "verify-chain", "foo"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, true, false, true,
			"", nil, nil, []string{"certmin", "verify-chain", "foo"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, false, false, false,
			"", nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)

	action, exitStatus =
		verifyAndDispatch(false, false, true, false, false,
			"", nil, nil, []string{"certmin", "verify-key", "foo", "bar"})
	assert.NotNil(t, action)
	assert.Equal(t, -1, exitStatus)
}

//func TestGetAction(t *testing.T) {
//	mock = true
//	_, exitStatus := getAction()
//	assert.Equal(t, 0, exitStatus)
//
//	//mockArgs = []string{"certmin", "skim", "cert"}
//	//_, exitStatus = getAction()
//	//assert.Equal(t, -1, exitStatus)
//	//
//	//mockArgs = []string{"certmin", "verify-chain", "cert"}
//	//_, exitStatus = getAction()
//	//assert.Equal(t, 1, exitStatus)
//
//	mock = false
//	mockArgs = nil
//}

//
//func TestSkimCmdParse(t *testing.T) {
//	action, exitStatus := skimCmdParse([]string{}, "", false)
//	assert.Nil(t, action)
//	assert.Equal(t, 1, exitStatus)
//
//	action, exitStatus = skimCmdParse(
//		[]string{"t/chain.crt", "t/myserver.crt", "t/myserver-fromca2.crt"}, "", false)
//	assert.NotNil(t, action)
//	assert.Equal(t, -1, exitStatus)
//}
//
//func TestVerifyChainCmdParse(t *testing.T) {
//	action, exitStatus := verifyChainCmdParse([]string{}, []string{}, nil, "", false)
//	assert.Nil(t, action)
//	assert.Equal(t, 1, exitStatus)
//
//	action, exitStatus =
//		verifyChainCmdParse([]string{"foo", "fa"}, []string{"bar", "bas"}, []string{"mycert"}, "", false)
//	assert.NotNil(t, action)
//	assert.Equal(t, -1, exitStatus)
//
//	action, exitStatus = verifyChainCmdParse(nil, []string{"bar", "bas"}, []string{"mycert"}, "", false)
//	assert.Nil(t, action)
//	assert.Equal(t, 1, exitStatus)
//
//	action, exitStatus = verifyChainCmdParse([]string{"foo", "fa"}, []string{"bar", "bas"}, nil, "", false)
//	assert.Nil(t, action)
//	assert.Equal(t, 1, exitStatus)
//
//}
//
//func TestVerifyKeyCmdParse(t *testing.T) {
//	action, exitStatus := verifyKeyCmdParse([]string{}, "")
//	assert.Nil(t, action)
//	assert.Equal(t, 0, exitStatus)
//
//	action, exitStatus = verifyKeyCmdParse([]string{"a", "b"}, "")
//	assert.NotNil(t, action)
//	assert.Equal(t, -1, exitStatus)
//
//	action, exitStatus = verifyKeyCmdParse([]string{"a", "b", "c"}, "")
//	assert.Nil(t, action)
//	assert.Equal(t, 1, exitStatus)
//}
