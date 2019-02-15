package gochassis

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chassis/foundation/httpclient"
	security2 "github.com/go-chassis/foundation/security"
	"github.com/go-chassis/go-archaius"
	"github.com/go-chassis/go-chassis/bootstrap"
	"github.com/go-chassis/go-chassis/core/common"
	"github.com/go-chassis/go-chassis/core/config"
	"github.com/go-chassis/go-chassis/core/config/model"
	"github.com/go-chassis/go-chassis/security"
	"github.com/go-mesh/openlogging"
	"github.com/huaweicse/auth"
	"gopkg.in/yaml.v2"
)

const (
	paasProjectNameEnv = "PAAS_PROJECT_NAME"
	cipherRootEnv      = "CIPHER_ROOT"
	keytoolAkskFile    = "certificate.yaml"
	keytoolCipher      = "security"

	keyAK      = "cse.credentials.accessKey"
	keySK      = "cse.credentials.secretKey"
	keyProject = "cse.credentials.project"
)

//IsAuthConfNotExist judges whether an error is equal to ErrAuthConfNotExist
func IsAuthConfNotExist(e error) bool {
	return e == ErrAuthConfNotExist
}

//ErrAuthConfNotExist means the auth config not exist
var ErrAuthConfNotExist = errors.New("auth config is not exist")

// loadAkskAuth gets the Authentication Mode ak/sk, token and forms required Auth Headers
func loadPaasAuth() error {
	h, err := GetAuthHeaderGenerator()
	if err != nil {
		return err
	}
	projectFromEnv := os.Getenv(paasProjectNameEnv)
	if projectFromEnv != "" {
		openlogging.GetLogger().Infof("Huawei cloud project: %s", projectFromEnv)
	}
	httpclient.SignRequest = func(r *http.Request) error {
		if r.Header == nil {
			r.Header = make(http.Header)
		}
		for k, vs := range h.GenAuthHeaders() {
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		if projectFromEnv != "" {
			r.Header.Set(auth.HeaderServiceProject, projectFromEnv)
		}
		return nil
	}
	return nil
}

func getAkskCustomCipher(name string) (security2.Cipher, error) {
	f, err := security.GetCipherNewFunc(name)
	if err != nil {
		return nil, err
	}
	cipherPlugin := f()
	if cipherPlugin == nil {
		return nil, fmt.Errorf("cipher plugin [%s] invalid", name)
	}
	return cipherPlugin, nil
}

func getProjectFromURI(rawurl string) (string, error) {
	errGetProjectFailed := errors.New("get project from CSE uri failed")
	// rawurl: https://cse.cn-north-1.myhwclouds.com:443
	if rawurl == "" {
		return "", fmt.Errorf("%v, CSE uri empty", errGetProjectFailed)
	}

	u, err := url.Parse(rawurl)
	if err != nil {
		return "", fmt.Errorf("%v, %v", errGetProjectFailed, err)
	}
	parts := strings.Split(u.Host, ".")
	if len(parts) != 4 {
		openlogging.GetLogger().Info("CSE uri contains no project")
		return "", nil
	}
	return parts[1], nil
}

func getAkskConfig() (*model.CredentialStruct, error) {
	// 1, if env CIPHER_ROOT exists, read ${CIPHER_ROOT}/certificate.yaml
	// 2, if env CIPHER_ROOT not exists, read chassis config
	var akskFile string
	if v, exist := os.LookupEnv(cipherRootEnv); exist {
		p := filepath.Join(v, keytoolAkskFile)
		if _, err := os.Stat(p); err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else {
			akskFile = p
		}
	}

	c := &model.CredentialStruct{}
	if akskFile == "" {
		c.AccessKey = archaius.GetString(keyAK, "")
		c.SecretKey = archaius.GetString(keySK, "")
		c.Project = archaius.GetString(keyProject, "")
		c.AkskCustomCipher = archaius.GetString(common.AKSKCustomCipher, "")
	} else {
		yamlContent, err := ioutil.ReadFile(akskFile)
		if err != nil {
			return nil, err
		}
		globalConf := &model.GlobalCfg{}
		err = yaml.Unmarshal(yamlContent, globalConf)
		if err != nil {
			return nil, err
		}
		c = &(globalConf.Cse.Credentials)
	}
	if c.AccessKey == "" && c.SecretKey == "" {
		return nil, ErrAuthConfNotExist
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("ak or sk is empty")
	}

	// 1, use project of env PAAS_PROJECT_NAME
	// 2, use project in the credential config
	// 3, use project in cse uri contain
	// 4, use project "default"
	if v := os.Getenv(paasProjectNameEnv); v != "" {
		c.Project = v
	}
	if c.Project == "" {
		project, err := getProjectFromURI(config.GetRegistratorAddress())
		if err != nil {
			return nil, err
		}
		if project != "" {
			c.Project = project
		} else {
			c.Project = common.DefaultValue
		}
	}
	return c, nil
}

// loadAkskAuth gets the Authentication Mode ak/sk
func loadAkskAuth() error {
	c, err := getAkskConfig()
	if err != nil {
		return err
	}
	openlogging.GetLogger().Infof("Huawei cloud auth AK: %s, project: %s", c.AccessKey, c.Project)

	plainSk := c.SecretKey
	cipher := c.AkskCustomCipher
	if cipher != "" {
		if cipher == keytoolCipher {
			openlogging.GetLogger().Infof("Use cipher plugin [aes] as plugin [%s]", cipher)
			cipher = "aes"
		}
		cipherPlugin, err := getAkskCustomCipher(cipher)
		if err != nil {
			return err
		}
		res, err := cipherPlugin.Decrypt(c.SecretKey)
		if err != nil {
			return fmt.Errorf("decrypt sk failed %v", err)
		}
		plainSk = res
	}

	httpclient.SignRequest, err = auth.GetShaAKSKSignFunc(c.AccessKey, plainSk, c.Project)
	return err
}

// Init initializes auth module
func Init() error {
	err := loadAkskAuth()
	if err == nil {
		openlogging.GetLogger().Warn("Huawei Cloud auth mode: AKSK, AKSK source: chassis config")
		return nil
	}
	if !IsAuthConfNotExist(err) {
		openlogging.GetLogger().Errorf("Load AKSK failed: %s", err)
		return err
	}

	err = loadPaasAuth()
	if err == nil {
		openlogging.GetLogger().Warn("Huawei Cloud auth mode: AKSK, AKSK source: default secret")
		return nil
	}
	if !IsAuthConfNotExist(err) {
		openlogging.GetLogger().Errorf("Get AKSK auth from default secret failed: %s", err)
		return err
	}
	openlogging.GetLogger().Info("No authentication for Huawei Cloud")
	return nil
}

func init() {
	bootstrap.InstallPlugin("huaweiauth", bootstrap.BootstrapFunc(Init))
}
