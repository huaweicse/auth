package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"github.com/go-mesh/openlogging"
)

//ErrAuthConfNotExist means the auth config not exist
var ErrAuthConfNotExist = errors.New("auth config is not exist")

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

//DockerConfig is a tenant's default secret in json format
type DockerConfig struct {
	Auths map[string]Data `json:"auths"`
}

//Data is the base64 format of AK/SHAAKSK/PROJECT
type Data struct {
	Auth string `json:"auth"`
}

//HeaderGenerator gets auth info and transfers it to auth headers
//and refresh the auth headers interval
type HeaderGenerator struct {
	defaultAuthHeaders http.Header
	once               sync.Once
	RefreshInterval    time.Duration
	Retriever          Retriever
}

// Retriever queries auth infomation: project, AK, SHAAKSK, error
type Retriever interface {
	GetAuthInfo() (project string, ak string, shaAKSK string, err error)
	Name() string //source name
}

//GenAuthHeaders returns the latest auth headers
func (h *HeaderGenerator) GenAuthHeaders() http.Header {
	h.once.Do(h.initialize)
	return h.defaultAuthHeaders
}

func parseAuthInfo(dockerConfigJSONBase64Bytes []byte) (string, string, string, error) {
	// docker config
	d := &DockerConfig{}
	err := json.Unmarshal(dockerConfigJSONBase64Bytes, d)
	if err != nil {
		return "", "", "", err
	}
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
			openlogging.Info("get auth info for endpoint: " + k)
			break
		}
	}
	if len(authRaw) == 0 {
		return "", "", "", errors.New("auth data empty")
	}
	authStrBase64Bytes, err = base64.StdEncoding.DecodeString(authRaw)
	if err != nil {
		return "", "", "", err
	}
	authStr = string(authStrBase64Bytes)

	authSplit := strings.Split(authStr, "@")
	akAndShaAkSk := strings.Split(authSplit[1], ":")
	if len(authSplit) != ExpectedArrLength ||
		len(akAndShaAkSk) != ExpectedArrLength {
		return "", "", "", errors.New("unexpected length")
	}
	return authSplit[0], akAndShaAkSk[0], akAndShaAkSk[1], nil
}

func (h *HeaderGenerator) createAuthHeaders() {
	var authHeaders http.Header
	project, ak, shaAkSk, err := h.Retriever.GetAuthInfo()
	if err != nil {
		openlogging.GetLogger().Errorf("Update auth headers failed, err: %s", err)
		return
	}

	//if AK/ShaAKSK/project not changed, will not update
	if project == h.defaultAuthHeaders.Get(HeaderServiceProject) &&
		ak == h.defaultAuthHeaders.Get(HeaderServiceAk) &&
		shaAkSk == h.defaultAuthHeaders.Get(HeaderServiceShaAKSK) {
		return
	}
	openlogging.GetLogger().Infof("New AK: %s, from %s", ak, h.Retriever.Name())
	authHeaders = make(http.Header)
	authHeaders.Set(HeaderServiceProject, project)
	authHeaders.Set(HeaderServiceAk, ak)
	authHeaders.Set(HeaderServiceShaAKSK, shaAkSk)

	h.defaultAuthHeaders = authHeaders
}

func (h *HeaderGenerator) initialize() {
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
func (q *CCERetriever) API4ImagePullSecret(namespace string) string {
	return fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s-secret",
		namespace,
		"default")
}

//GetAuthHeaderGenerator news an HeaderGenerator
//from several Retriever
//front param has higher priority
func GetAuthHeaderGenerator(qs ...Retriever) (*HeaderGenerator, error) {
	var h *HeaderGenerator
	var queryer Retriever
	ok := false
	for _, q := range qs {
		if q == nil {
			continue
		}
		openlogging.GetLogger().Debugf("Try to get auth info from default secret from %s", q.Name())
		_, _, _, err := q.GetAuthInfo()
		//Only if auth config not exist, we try next source
		//otherwise we use this source even if we got error,
		//as we don't know if the error will appear in subsequent attempts.
		//That is, we treat the error as recoverable and make periodic trials.
		if err != nil && err == ErrAuthConfNotExist {
			openlogging.GetLogger().Debugf("Not found auth info from default secret from %s", q.Name())
			continue
		}
		queryer = q
		ok = true
		break
	}
	if ok {
		h = &HeaderGenerator{
			Retriever:       queryer,
			RefreshInterval: DefaultRefreshInterval,
		}
		openlogging.GetLogger().Infof("Select default secret source: %s", queryer.Name())
		return h, nil
	}
	return nil, ErrAuthConfNotExist
}
