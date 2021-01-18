package certmin

//
//import (
//	"os"
//	"testing"
//
//	"github.com/stretchr/testify/assert"
//)
//
//func TestRetrieveCerts(t *testing.T) {
//	certs, err := retrieveCerts("faa")
//	assert.Nil(t, certs)
//	assert.Error(t, err)
//	if os.Getenv("AUTHOR_TESTING") != "" {
//		certs, err = retrieveCerts("github.com:443")
//		assert.NoError(t, err)
//		assert.True(t, len(certs) >= 2)
//	}
//}
//
