/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

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
	"time"
)

//CCERetriever queries auth info from CCE
type CCERetriever struct {
	Client             *http.Client
	ServiceAccountPath string
	EnvIdentifiers     []string
}

//NewCCERetriever news CCERetriever
func NewCCERetriever() *CCERetriever {
	q := CCERetriever{}
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

//Name implements Retriever.Name
func (q *CCERetriever) Name() string {
	return "CCE"
}

func (q *CCERetriever) isInCCE() bool {
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

//GetAuthInfo implements Retriever.GetAuthInfo
func (q *CCERetriever) GetAuthInfo() (string, string, string, error) {
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
	return parseAuthInfo(dockerConfigJSONBase64Bytes)
}
