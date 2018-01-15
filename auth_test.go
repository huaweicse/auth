package auth

import (
	"net/http"
	"testing"

	hws_cloud "github.com/ServiceComb/auth/third_party/forked/datastream/aws"
	"github.com/stretchr/testify/assert"
)

func Test_noAuth(t *testing.T) {
	r, err := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r.Header))
	err = AddAuthInfo(r)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(r.Header))
}

func Test_UseAKSKAuth(t *testing.T) {
	ak := "NQIZW3SSNRDLT0ZKZANS"
	sk := "Wn3QykqzsyD5osUFc2hFH6qozqOtV5FvetckJ7fr"
	shaaksk := "02a8ceaa95db6653c6f033759774d3bcc01be6b97da1c4ce218ef2451630eeb5"
	project := "project1"

	err := UseAKSKAuth(ak, sk, project)
	assert.NoError(t, err)
	r, err := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	assert.NoError(t, err)
	err = AddAuthInfo(r)
	assert.NoError(t, err)
	assert.Equal(t, r.Header.Get(HeaderServiceAk), ak)
	assert.Equal(t, r.Header.Get(HeaderServiceShaAKSK), shaaksk)
	assert.Equal(t, r.Header.Get(HeaderServiceProject), project)
	assert.NotEmpty(t, r.Header.Get(hws_cloud.HeaderAuthorization))
}

func Test_SetAuthFunc(t *testing.T) {
	k := "name"
	v := "Tom"
	f := func(r *http.Request) error {
		r.Header.Set(k, v)
		return nil
	}
	SetAuthFunc(f)
	r, err := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	assert.NoError(t, err)
	assert.NotEqual(t, v, r.Header.Get(k))

	err = AddAuthInfo(r)
	assert.NoError(t, err)
	assert.Equal(t, v, r.Header.Get(k))
}
