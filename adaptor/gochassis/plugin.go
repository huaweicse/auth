package gochassis

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/huaweicse/auth"

	"github.com/go-mesh/openlogging"
)

//constant value for communication to CCE
const (
	EnvKubernetesServiceHost = "KUBERNETES_SERVICE_HOST"
	EnvKubernetesServicePort = "KUBERNETES_SERVICE_PORT"
	HeaderAuthorization      = "Authorization"
	ExpectedArrLength        = 2
	ServiceAccountPath       = `/var/run/secrets/kubernetes.io/serviceaccount`
)

//default secret path and file mounted to container by ServiceStage
const (
	ServiceStageMountPath = `/opt/CSE/etc/auth`
	DefaultSecretFile     = `.dockerconfigjson`
)

//DefaultRefreshInterval is default refresh interval
const DefaultRefreshInterval = 60 * time.Second

//CCEEnvIdentifications is to judge whether a container runs in CCE cluster
var CCEEnvIdentifications = []string{
	"PAAS_APP_NAME",
	"PAAS_NAMESPACE",
	"PAAS_PROJECT_ID",
	"PAAS_POD_ID",
	"PAAS_CLUSTER_ID",
}

// KubeSecrets is response struct of CCE secret api
type KubeSecrets struct {
	Data KubeSecretsData `json:"data"`
}

//KubeSecretsData is the data of KubeSecrets
type KubeSecretsData struct {
	DockerConfigJSON string `json:".dockerconfigjson"`
}

//DockerConfig is a tenant's default secret
type DockerConfig struct {
	Auths map[string]AuthData `json:"auths"`
}

//AuthData contains AK/SHAAKSK/PROJECT
type AuthData struct {
	Auth string `json:"auth"`
}

//AuthHeaderGenerator gets auth infomation and transfers it to auth headers
//and refresh the auth headers frequently
type AuthHeaderGenerator struct {
	defaultAuthHeaders http.Header
	once               sync.Once
	RefreshInterval    time.Duration
	AuthInfoGener      AuthInfoQueryer
}

// AuthInfoQueryer queries auth infomation: project, AK, SHAAKSK, error
type AuthInfoQueryer interface {
	GetAuthInfos() (string, string, string, error)
	Source() string //source name
}

//AuthInfoQueryerFromServiceStage queries auth infomation from ServiceStage
type AuthInfoQueryerFromServiceStage struct {
	MountPath string
	File      string
}

//GetAuthInfoQueryerFromServiceStage news AuthInfoQueryerFromServiceStage
func GetAuthInfoQueryerFromServiceStage() *AuthInfoQueryerFromServiceStage {
	return &AuthInfoQueryerFromServiceStage{
		MountPath: ServiceStageMountPath,
		File:      DefaultSecretFile,
	}
}

//GetAuthInfos implements AuthInfoQueryer.GetAuthInfos
func (q *AuthInfoQueryerFromServiceStage) GetAuthInfos() (string, string, string, error) {
	secretPath := filepath.Join(q.MountPath, q.File)
	content, err := ioutil.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", "", ErrAuthConfNotExist
		}
		return "", "", "", err
	}
	var dockerConfig DockerConfig
	if err = json.Unmarshal(content, &dockerConfig); err != nil {
		return "", "", "", err
	}
	return getAuthInfosFromCCEDefaultSecret(&dockerConfig)
}

//Source implements AuthInfoQueryer.Source
func (q *AuthInfoQueryerFromServiceStage) Source() string {
	return "ServiceStage"
}

//AuthInfoQueryerFromCCE queries auth infomation from CCE
type AuthInfoQueryerFromCCE struct {
	Client             *http.Client
	ServiceAccountPath string
	EnvIdentifiers     []string
}

//GetAuthInfoQueryerFromCCE news AuthInfoQueryerFromCCE
func GetAuthInfoQueryerFromCCE() *AuthInfoQueryerFromCCE {
	q := AuthInfoQueryerFromCCE{}
	q.ServiceAccountPath = ServiceAccountPath
	trTLS := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// https, verify peer: false
	q.Client = &http.Client{
		Transport: trTLS,
		Timeout:   60 * time.Second,
	}
	q.EnvIdentifiers = make([]string, 0)
	for _, v := range CCEEnvIdentifications {
		q.EnvIdentifiers = append(q.EnvIdentifiers, v)
	}
	return &q
}

//GenAuthHeaders returns the latest auth headers
func (h *AuthHeaderGenerator) GenAuthHeaders() http.Header {
	h.once.Do(h.initialize)
	return h.defaultAuthHeaders
}

//Source implements AuthInfoQueryer.Source
func (q *AuthInfoQueryerFromCCE) Source() string {
	return "CCE"
}

func (q *AuthInfoQueryerFromCCE) isInCCE() bool {
	if len(q.EnvIdentifiers) == 0 {
		return false
	}
	for _, k := range q.EnvIdentifiers {
		if v := os.Getenv(k); v != "" {
			return true
		}
	}
	return false
}

//GetAuthInfos implements AuthInfoQueryer.GetAuthInfos
func (q *AuthInfoQueryerFromCCE) GetAuthInfos() (string, string, string, error) {
	if !q.isInCCE() {
		return "", "", "", ErrAuthConfNotExist
	}
	fd, err := ioutil.ReadFile(filepath.Join(q.ServiceAccountPath, "namespace"))
	if err != nil {
		return "", "", "", err
	}
	namespace := strings.TrimSpace(string(fd))

	url := fmt.Sprintf("https://%s:%s%s",
		os.Getenv(EnvKubernetesServiceHost),
		os.Getenv(EnvKubernetesServicePort),
		q.API4ImagePullSecret(namespace))

	fd, err = ioutil.ReadFile(filepath.Join(q.ServiceAccountPath, "token"))
	if err != nil {
		return "", "", "", err
	}
	token := strings.TrimSpace(string(fd))

	httpHeaders := http.Header{
		HeaderAuthorization: []string{"bearer " + token},
	}

	// kube secrets json
	var kubeSecretsJSONBytes []byte
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header = httpHeaders
	resp, err := q.Client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		d, e := ioutil.ReadAll(resp.Body)
		if e != nil {
			return "", "", "", e
		}
		return "", "", "", fmt.Errorf("request failed, status: %s, resp: %s", resp.Status, string(d))
	}
	kubeSecretsJSONBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", err
	}

	// kube secrets
	var kubeSecrets KubeSecrets
	err = json.Unmarshal(kubeSecretsJSONBytes, &kubeSecrets)
	if err != nil {
		return "", "", "", err
	}
	if kubeSecrets.Data.DockerConfigJSON == "" {
		return "", "", "", errors.New("dockerConfigJson is empty")
	}

	// docker config json
	dockerConfigJSONBase64Bytes, err := base64.StdEncoding.DecodeString(kubeSecrets.Data.DockerConfigJSON)
	if err != nil {
		return "", "", "", err
	}
	// docker config
	var dockerConfig DockerConfig
	err = json.Unmarshal(dockerConfigJSONBase64Bytes, &dockerConfig)
	if err != nil {
		return "", "", "", err
	}
	return getAuthInfosFromCCEDefaultSecret(&dockerConfig)
}

func getAuthInfosFromCCEDefaultSecret(d *DockerConfig) (string, string, string, error) {
	if d == nil {
		return "", "", "", errors.New("input DockerConfig ptr nil")
	}
	if len(d.Auths) == 0 {
		return "", "", "", errors.New("auth data empty")
	}

	// auth string
	var authStr string
	var authStrBase64Bytes []byte
	var authRaw string
	for k, v := range d.Auths {
		if k != "" {
			authRaw = v.Auth
			break
		}
	}
	if len(authRaw) == 0 {
		return "", "", "", errors.New("auth data empty")
	}
	authStrBase64Bytes, err := base64.StdEncoding.DecodeString(authRaw)
	if err != nil {
		return "", "", "", err
	}
	authStr = string(authStrBase64Bytes)

	authSplit := strings.Split(authStr, "@")
	akAndShaAkSk := strings.Split(authSplit[1], ":")
	if len(authSplit) != ExpectedArrLength ||
		len(akAndShaAkSk) != ExpectedArrLength {
		return "", "", "", errors.New("Unexpected Length")
	}
	return authSplit[0], akAndShaAkSk[0], akAndShaAkSk[1], nil
}

func (h *AuthHeaderGenerator) createAuthHeaders() {
	var authHeaders http.Header
	project, ak, shaAkSk, err := h.AuthInfoGener.GetAuthInfos()
	if err != nil {
		openlogging.GetLogger().Errorf("Update auth headers failed, err: %s", err)
		return
	}

	//if AK/ShaAKSK/project not changed, will not update
	if project == h.defaultAuthHeaders.Get(auth.HeaderServiceProject) &&
		ak == h.defaultAuthHeaders.Get(auth.HeaderServiceAk) &&
		shaAkSk == h.defaultAuthHeaders.Get(auth.HeaderServiceShaAKSK) {
		return
	}
	openlogging.GetLogger().Infof("New AK: %s, from %s", ak, h.AuthInfoGener.Source())
	authHeaders = make(http.Header)
	authHeaders.Set(auth.HeaderServiceProject, project)
	authHeaders.Set(auth.HeaderServiceAk, ak)
	authHeaders.Set(auth.HeaderServiceShaAKSK, shaAkSk)

	h.defaultAuthHeaders = authHeaders
}

func (h *AuthHeaderGenerator) initialize() {
	if h.RefreshInterval == 0 {
		h.RefreshInterval = DefaultRefreshInterval
	}
	openlogging.GetLogger().Info("Generate auth headers")
	h.defaultAuthHeaders = make(http.Header)
	h.createAuthHeaders()
	openlogging.GetLogger().Infof("Refresh auth headers, interval: %s", h.RefreshInterval.String())
	go func() {
		for {
			h.createAuthHeaders()
			time.Sleep(h.RefreshInterval)
		}
	}()
}

//API4ImagePullSecret get secret api for a namespace
func (q *AuthInfoQueryerFromCCE) API4ImagePullSecret(namespace string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s-secret",
		namespace,
		"default")
}

//GetAuthHeaderGeneratorFromCustomAuthInfoQueryers news an AuthHeaderGenerator
//from several AuthInfoQueryer
//this is to make pkg more testable
//front param has higher priority
func GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(qs ...AuthInfoQueryer) (*AuthHeaderGenerator, error) {
	var h *AuthHeaderGenerator
	var queryer AuthInfoQueryer
	ok := false
	for _, q := range qs {
		if q == nil {
			continue
		}
		openlogging.GetLogger().Debugf("Try to get auth info from default secret from %s", q.Source())
		_, _, _, err := q.GetAuthInfos()
		//Only if auth config not exist, we try next source
		//otherwise we use this source even if we got error,
		//as we don't know if the error will appear in subsequent attempts.
		//That is, we treat the error as recoverable and make periodic trials.
		if err != nil && IsAuthConfNotExist(err) {
			openlogging.GetLogger().Debugf("Not found auth info from default secret from %s", q.Source())
			continue
		}
		queryer = q
		ok = true
		break
	}
	if ok {
		h = &AuthHeaderGenerator{
			AuthInfoGener:   queryer,
			RefreshInterval: DefaultRefreshInterval,
		}
		openlogging.GetLogger().Infof("Select default secret source: %s", queryer.Source())
		return h, nil
	}
	return nil, ErrAuthConfNotExist
}

//GetAuthHeaderGenerator news an AuthHeaderGenerator
func GetAuthHeaderGenerator() (*AuthHeaderGenerator, error) {
	return GetAuthHeaderGeneratorFromCustomAuthInfoQueryers(
		GetAuthInfoQueryerFromServiceStage(),
		GetAuthInfoQueryerFromCCE())
}
