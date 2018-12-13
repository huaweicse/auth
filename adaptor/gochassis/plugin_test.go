package gochassis_test

import (
	"errors"
	"github.com/huaweicse/auth"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huaweicse/auth/adaptor/gochassis"
	"github.com/stretchr/testify/assert"
)

type AKHandler struct {
	AK *AKAndShaAKSKVefifier
}

func (a *AKHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(gochassis.HeaderAuthorization) != AK2.Authorization {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token error"))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(a.AK.ImagePullSecret))
}

func (a *AKHandler) SetAK(newAK *AKAndShaAKSKVefifier) {
	a.AK = newAK
}

type AKAndShaAKSKVefifier struct {
	Namespace       string
	Authorization   string
	Token           string
	AK              string
	ShaAKSK         string
	Project         string
	ImagePullSecret string
	DefaultSecret   string
}

var AK2 = &AKAndShaAKSKVefifier{
	Namespace:       "default",
	Authorization:   `bearer token2`,
	Token:           `token2`,
	AK:              `A2222222222222222222`,
	ShaAKSK:         `6d0e4c5764b113eca34fd4a32d46661cfff390297dfca6de8a52306951c78038`,
	Project:         `cn-north-1`,
	ImagePullSecret: `{"kind":"Secret","apiVersion":"v1","metadata":{"name":"default-secret","namespace":"default","selfLink":"/api/v1/namespaces/default/secrets/default-secret","uid":"0","resourceVersion":"0","creationTimestamp":"0000-00-00T00:00:00Z"},"data":{".dockerconfigjson":"eyJhdXRocyI6eyIxMDAuMTI1LjAuMTk4OjIwMjAyIjp7ImF1dGgiOiJZMjR0Ym05eWRHZ3RNVUJCTWpJeU1qSXlNakl5TWpJeU1qSXlNakl5TWpvMlpEQmxOR00xTnpZMFlqRXhNMlZqWVRNMFptUTBZVE15WkRRMk5qWXhZMlptWmpNNU1ESTVOMlJtWTJFMlpHVTRZVFV5TXpBMk9UVXhZemM0TURNNCJ9LCJzd3IuY24tbm9ydGgtMS5teWh1YXdlaWNsb3VkLmNvbSI6eyJhdXRoIjoiWTI0dGJtOXlkR2d0TVVCQk1qSXlNakl5TWpJeU1qSXlNakl5TWpJeU1qbzJaREJsTkdNMU56WTBZakV4TTJWallUTTBabVEwWVRNeVpEUTJOall4WTJabVpqTTVNREk1TjJSbVkyRTJaR1U0WVRVeU16QTJPVFV4WXpjNE1ETTQifX19"},"type":"kubernetes.io/dockerconfigjson"}`,
	DefaultSecret:   `{"auths":{"127.0.0.1:80":{"auth":"Y24tbm9ydGgtMUBBMjIyMjIyMjIyMjIyMjIyMjIyMjo2ZDBlNGM1NzY0YjExM2VjYTM0ZmQ0YTMyZDQ2NjYxY2ZmZjM5MDI5N2RmY2E2ZGU4YTUyMzA2OTUxYzc4MDM4"},"swr.cn-north-1.myhuaweicloud.com":{"auth":"Y24tbm9ydGgtMUBBMjIyMjIyMjIyMjIyMjIyMjIyMjo2ZDBlNGM1NzY0YjExM2VjYTM0ZmQ0YTMyZDQ2NjYxY2ZmZjM5MDI5N2RmY2E2ZGU4YTUyMzA2OTUxYzc4MDM4"}}}`,
}

func TestAuthInfoQueryerFromCCE_GetAuthInfos(t *testing.T) {
	t.Log("Not in CCE")
	queryerFromCCE := gochassis.GetAuthInfoQueryerFromCCE()
	for _, v := range queryerFromCCE.EnvIdentifiers {
		os.Unsetenv(v)
	}
	_, _, _, err := queryerFromCCE.GetAuthInfos()
	assert.True(t, gochassis.IsAuthConfNotExist(err))

	t.Log("In CCE")
	os.Setenv("PAAS_CLUSTER_ID", "1")
	queryerFromCCE.ServiceAccountPath = filepath.Join(os.Getenv("GOPATH"), "test", "auth", "ServiceAccount")
	err = os.MkdirAll(queryerFromCCE.ServiceAccountPath, 0700)
	assert.NoError(t, err)
	//write token file
	tokenPath := filepath.Join(queryerFromCCE.ServiceAccountPath, "token")
	tokenFile, err := os.OpenFile(tokenPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0700)
	assert.NoError(t, err)
	defer tokenFile.Close()
	_, err = tokenFile.WriteString(AK2.Token)
	assert.NoError(t, err)

	//write namespace file
	namespacePath := filepath.Join(queryerFromCCE.ServiceAccountPath, "namespace")
	namespaceFile, err := os.OpenFile(namespacePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0700)
	assert.NoError(t, err)
	defer namespaceFile.Close()
	_, err = namespaceFile.WriteString(AK2.Namespace)
	assert.NoError(t, err)

	mux := &http.ServeMux{}
	ak2Handler := &AKHandler{AK: AK2}
	mux.Handle(queryerFromCCE.API4ImagePullSecret(AK2.Namespace), ak2Handler)
	s := httptest.NewTLSServer(mux)
	defer s.Close()
	parts := strings.Split(s.Listener.Addr().String(), ":")
	os.Setenv(gochassis.EnvKubernetesServiceHost, parts[0])
	os.Setenv(gochassis.EnvKubernetesServicePort, parts[1])
	project, ak, shaAkSk, err := queryerFromCCE.GetAuthInfos()
	assert.NoError(t, err)
	assert.Equal(t, AK2.AK, ak)
	assert.Equal(t, AK2.ShaAKSK, shaAkSk)
	assert.Equal(t, AK2.Project, project)
}

func TestAuthInfoQueryerFromServiceStage(t *testing.T) {
	t.Log("ServiceStage mount file not exist")
	q := gochassis.GetAuthInfoQueryerFromServiceStage()
	q.MountPath = filepath.Join(os.Getenv("GOPATH"), "test", "auth", "secret")
	err := os.MkdirAll(q.MountPath, 0700)
	assert.NoError(t, err)
	os.Remove(filepath.Join(q.MountPath, q.File))
	_, _, _, err = q.GetAuthInfos()
	assert.True(t, gochassis.IsAuthConfNotExist(err))

	t.Log("ServiceStage mount file exist")
	err = ioutil.WriteFile(filepath.Join(q.MountPath, q.File), []byte(AK2.DefaultSecret), 0700)
	project, ak, shaAkSk, err := q.GetAuthInfos()
	assert.NoError(t, err)
	assert.Equal(t, AK2.AK, ak)
	assert.Equal(t, AK2.ShaAKSK, shaAkSk)
	assert.Equal(t, AK2.Project, project)
}

type mockAuthInfoGenerator struct {
	ak   string
	err  error
	name string
	n    int
}

func (m *mockAuthInfoGenerator) GetAuthInfos() (string, string, string, error) {
	if m.err != nil {
		return "", "", "", m.err
	}
	m.n++
	return m.ak, m.ak, m.ak, nil
}

func (m *mockAuthInfoGenerator) Source() string {
	return m.name
}

func TestGetAuthHeaderGeneratorFromCustomAuthInfoQueryers(t *testing.T) {
	// test priority
	//all effective
	g1 := &mockAuthInfoGenerator{
		ak:   "1",
		name: "1",
	}
	g2 := &mockAuthInfoGenerator{
		ak:   "2",
		name: "2",
	}
	h, err := gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(g1, g2)
	assert.NoError(t, err)
	_, ak, _, err := h.AuthInfoGener.GetAuthInfos()
	assert.NoError(t, err)
	assert.Equal(t, g1.ak, ak)

	//g2 effective
	testErr1 := errors.New("test1")
	testErr2 := errors.New("test2")
	g1.err = gochassis.ErrAuthConfNotExist
	h, err = gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(g1, g2)
	assert.NoError(t, err)
	_, ak, _, err = h.AuthInfoGener.GetAuthInfos()
	assert.NoError(t, err)
	assert.Equal(t, g2.ak, ak)

	// CustomAuthInfoQueryers: nil, nil
	h, err = gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(nil, nil)
	assert.Nil(t, h)
	assert.True(t, gochassis.IsAuthConfNotExist(err))

	// CustomAuthInfoQueryers: err, err
	g1.err = testErr1
	g2.err = testErr2
	h, err = gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(g1, g2)
	assert.NoError(t, err)
	_, ak, _, err = h.AuthInfoGener.GetAuthInfos()
	assert.Error(t, err)
	assert.Equal(t, g1.err, err)

	// CustomAuthInfoQueryers: not exist, not exist
	g1.err = gochassis.ErrAuthConfNotExist
	g2.err = gochassis.ErrAuthConfNotExist
	h, err = gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(g1, g2)
	assert.Nil(t, h)
	assert.True(t, gochassis.IsAuthConfNotExist(err))
}

//integration test
func TestGetAuthHeaderGenerator(t *testing.T) {
	os.Setenv("PAAS_POD_ID", "a")
	_, err := gochassis.GetAuthHeaderGenerator()
	assert.NoError(t, err)
}

func TestAuthHeaderGenerator_GenAuthHeaders(t *testing.T) {
	t.Log("Refresh aksk")
	akA := "a"
	akB := "b"
	q1 := mockAuthInfoGenerator{
		ak: akA,
	}
	g, err := gochassis.GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(&q1)
	assert.NoError(t, err)
	g.RefreshInterval = 100 * time.Millisecond
	header := g.GenAuthHeaders()
	assert.Equal(t, header.Get(auth.HeaderServiceAk), akA)

	q1.ak = akB
	time.Sleep(200 * time.Millisecond)
	header = g.GenAuthHeaders()
	assert.Equal(t, header.Get(auth.HeaderServiceAk), akB)

	q1.ak = akA
	time.Sleep(200 * time.Millisecond)
	header = g.GenAuthHeaders()
	assert.Equal(t, header.Get(auth.HeaderServiceAk), akA)
	t.Log("test the frequency")
	assert.True(t, q1.n >= 5)
	assert.True(t, q1.n <= 7)
}
