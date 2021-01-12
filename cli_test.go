package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAction(t *testing.T) {
	mock = true
	_, exitStatus := getAction()
	assert.Equal(t, 0, exitStatus)

	//mockArgs = []string{"certmin", "skim", "cert"}
	//_, exitStatus = getAction()
	//assert.Equal(t, -1, exitStatus)
	//
	//mockArgs = []string{"certmin", "verify-chain", "cert"}
	//_, exitStatus = getAction()
	//assert.Equal(t, 1, exitStatus)

	mock = false
	mockArgs = nil
}

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
