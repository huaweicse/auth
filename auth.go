package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"

	"errors"
	hws_cloud "github.com/huaweicse/auth/third_party/forked/datastream/aws"
)

// Headers for ak/sk auth
const (
	HeaderServiceAk      = "X-Service-AK"
	HeaderServiceShaAKSK = "X-Service-ShaAKSK"
	HeaderServiceProject = "X-Service-Project"
)

//SignRequest inject auth related header and sign this request so that this request can access to huawei cloud
type SignRequest func(*http.Request) error

var ErrAuthConfNotExist = errors.New("auth config is not exist")

// GetSignFunc sets and initializes the ak/sk auth func
func GetSignFunc(ak, sk, project string) (SignRequest, error) {
	s := &hws_cloud.Signer{
		AccessKey: ak,
		SecretKey: sk,
		Service:   "",
		Region:    "",
	}

	shaAKSK, err := genShaAKSK(sk, ak)
	if err != nil {
		return nil, err
	}

	return func(r *http.Request) error {
		r.Header.Set(HeaderServiceAk, ak)
		r.Header.Set(HeaderServiceShaAKSK, shaAKSK)
		r.Header.Set(HeaderServiceProject, project)
		return s.Sign(r)
	}, nil
}

func genShaAKSK(key string, data string) (string, error) {
	h := hmac.New(sha256.New, []byte(key))
	if _, err := h.Write([]byte(data)); err != nil {
		return "", err
	}
	b := h.Sum(nil)
	shaaksk := ""
	for _, j := range b {
		shaaksk = shaaksk + fmt.Sprintf("%02x", j)
	}
	return shaaksk, nil
}
