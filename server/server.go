/* 
 * Copyright 2019 hea9549
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"dkms/server/usecases"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func RunServer(port string) {
	router := gin.Default()

	router.POST("/key", usecases.KeyRegisterRequest)

	// challenge, response, etc ...
	router.POST("/key/:keyId/:action", usecases.KeyVerificationRequest)

	// get raw key
	router.GET("/key/:keyId", usecases.KeyRetrieveRequest)

	err := router.Run(":" + port)
	if err != nil {
		logrus.Panic("서버 초기화중 오류 : " + err.Error())
	}
}
