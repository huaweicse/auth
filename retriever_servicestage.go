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
	"io/ioutil"
	"os"
	"path/filepath"
)

//ServiceStageRetriever queries auth infomation from ServiceStage
type ServiceStageRetriever struct {
	MountPath string
	File      string
}

//NewServiceStageRetriever news ServiceStageRetriever
func NewServiceStageRetriever() *ServiceStageRetriever {
	return &ServiceStageRetriever{
		MountPath: ServiceStageMountPath,
		File:      DefaultSecretFile,
	}
}

//GetAuthInfo implements Retriever.GetAuthInfo
func (q *ServiceStageRetriever) GetAuthInfo() (string, string, string, error) {
	secretPath := filepath.Join(q.MountPath, q.File)
	content, err := ioutil.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", "", ErrAuthConfNotExist
		}
		return "", "", "", err
	}

	return parseAuthInfo(content)
}

//Name implements Retriever.Name
func (q *ServiceStageRetriever) Name() string {
	return "ServiceStage"
}
