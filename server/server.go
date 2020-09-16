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
	"encoding/hex"
	"time"

	"dkms/node"
	"dkms/server/api"
	"dkms/share"
	"dkms/user/mem"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// private Key List (hex)
// a0093a1dea7b0ff7c818278328a278b586e0d7a3836e9474b463b19d9f49160b
// c8bcc391811a42cec1089f1bdf6474fadfcd6193221058d9364cb9f7874d2d03
// 927472421cf861ef38836ff33787049c95cee6d99699d591946d70450acc8d06
// c5fed8a8aaad03d77db926ce81e3fe0f40e98542f4719a2d05b3edb1a2eff30f
// ab592d6dff915cec8e155d7f5e762484ac2ae8beb4cab13644b4a13b596d2501 <- user private key

func New(ip string, port string, prvKeyHex string) *gin.Engine {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	userRepository := mem.NewUserRepository()
	prvKeyBytes, err := hex.DecodeString(prvKeyHex)
	if err != nil {
		panic(err.Error())
	}
	nodeService, err := node.NewService(suite, prvKeyBytes, node.Address{
		Ip:   ip,
		Port: port,
	})
	if err != nil {
		panic("error while initialize node service")
	}

	userApi := api.NewUser(userRepository, nodeService)
	checkerApi := api.NewChecker(userRepository, nodeService)
	nodeApi := api.NewNode(nodeService)

	router := gin.New()
	router.Use(gin.Recovery())

	router.POST("/user", userApi.RegisterUser)

	router.POST("/checker/user", checkerApi.AddCheckUser)

	router.POST("/checker/user/delete", checkerApi.RemoveCheckUser)

	router.POST("/checker/user/startVerify", checkerApi.StartVerify)

	router.POST("/checker/user/challenge", checkerApi.VerifyChallenge)
	router.POST("/checker/start", checkerApi.StartChecking)
	router.POST("/checker/stop", checkerApi.StopChecking)

	router.GET("/info", nodeApi.ServerInfo)
	//// get userInfo
	//router.GET("/user/:userId", api.KeyRetrieveRequest)
	logrus.Info("server is ready for initialize.")
	prvHex, _ := share.ScalarToHex(nodeService.GetMyPrivateKey())
	pubHex, _ := share.PointToHex(nodeService.GetMyPublicKey())
	logrus.Info("this server private key hex : " + prvHex)
	logrus.Info("this server public key hex : " + pubHex)
	return router
}

func getLoggerMiddleware() gin.HandlerFunc {
	logger := logrus.New()
	return func(c *gin.Context) {
		// start time
		startTime := time.Now()
		// Processing request
		c.Next()
		// End time
		endTime := time.Now()
		// execution time
		latencyTime := endTime.Sub(startTime)
		// Request mode
		reqMethod := c.Request.Method
		// Request routing
		reqUri := c.Request.RequestURI
		// Status code
		statusCode := c.Writer.Status()
		// Request IP
		clientIP := c.ClientIP()
		// Log format
		logger.Infof("| %3d | %13v | %15s | %s | %s |",
			statusCode,
			latencyTime,
			clientIP,
			reqMethod,
			reqUri,
		)
	}
}
