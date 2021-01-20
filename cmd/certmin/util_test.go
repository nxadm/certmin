package main

import (
	"strings"
	"testing"
	"text/tabwriter"

	"github.com/nxadm/certmin"
	"github.com/stretchr/testify/assert"
)

func TestColorKeeper_Colourise(t *testing.T) {
	colourKeeper := make(colourKeeper)
	assert.NotEmpty(t, colourKeeper.colourise("0"))
	assert.NotEmpty(t, colourKeeper.colourise("1"))
	assert.NotEmpty(t, colourKeeper.colourise("2"))
	assert.NotEmpty(t, colourKeeper.colourise("3"))
	assert.NotEmpty(t, colourKeeper.colourise("4"))
	assert.NotEmpty(t, colourKeeper.colourise("5"))
	assert.NotEmpty(t, colourKeeper.colourise("6"))
	assert.NotEmpty(t, colourKeeper.colourise("7"))
	assert.Equal(t, "8", colourKeeper.colourise("8"))
}

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

//func printCert(cert *x509.Certificate, w *tabwriter.Writer, colourKeeper colourKeeper) {
func TestPrintCert(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/myserver.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 0, 1, ' ', tabwriter.StripEscape)
	colourKeeper := make(colourKeeper)
	printCert(certs[0], w, colourKeeper)
	w.Flush()
	assert.Contains(t, sb.String(), "CN=myserver")
}

func TestPromptForKeyPassword(t *testing.T) {
	t.SkipNow()
}

func TestWriteCertFiles(t *testing.T) {
	certs, err := certmin.DecodeCertFile("t/cert-and-chain.crt", "")
	assert.NoError(t, err)
	assert.NotNil(t, certs)
	output, err := writeCertFiles(certs, true)
	assert.NoError(t, err)
	assert.Contains(t, output, ".crt")
}
