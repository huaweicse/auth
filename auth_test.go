package auth

import (
	"net/http"
	"testing"

	hws_cloud "github.com/huaweicse/auth/third_party/forked/datastream/aws"
	"github.com/stretchr/testify/assert"
)

func Test_Auth(t *testing.T) {
	ak := "NQIZW3SSNRDLT0ZKZANS"
	sk := "Wn3QykqzsyD5osUFc2hFH6qozqOtV5FvetckJ7fr"
	shaaksk := "02a8ceaa95db6653c6f033759774d3bcc01be6b97da1c4ce218ef2451630eeb5"
	project := "project1"

	sign, err := GetSignFunc(ak, sk, project)
	assert.NoError(t, err)
	r, err := http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	r.Header = nil
	assert.NoError(t, err)
	err = sign(r)
	assert.NoError(t, err)
	assert.Equal(t, r.Header.Get(HeaderServiceAk), ak)
	assert.Equal(t, r.Header.Get(HeaderServiceShaAKSK), shaaksk)
	assert.Equal(t, r.Header.Get(HeaderServiceProject), project)
	assert.NotEmpty(t, r.Header.Get(hws_cloud.HeaderAuthorization))

	sign, err = GetShaAKSKSignFunc(ak, sk, project)
	r.Header = nil
	assert.NoError(t, err)
	r, err = http.NewRequest("GET", "http://127.0.0.1:8080", nil)
	assert.NoError(t, err)
	err = sign(r)
	assert.NoError(t, err)
	assert.Equal(t, r.Header.Get(HeaderServiceAk), ak)
	assert.Equal(t, r.Header.Get(HeaderServiceShaAKSK), shaaksk)
	assert.Equal(t, r.Header.Get(HeaderServiceProject), project)
	assert.Empty(t, r.Header.Get(hws_cloud.HeaderAuthorization))
}
